"""
WaaaghGate — Webhook notifications.

Send scan results to external services:
- Slack (incoming webhook)
- Microsoft Teams (incoming webhook)
- PagerDuty (Events API v2)
- Generic HTTP webhook (JSON POST)

All notifications are fire-and-forget with optional retry.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity

logger = logging.getLogger("krumpa.waaaghgate.webhook_notifier")


class WebhookPlatform(Enum):
    """Supported notification platforms."""
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    GENERIC = "generic"


@dataclass
class WebhookConfig:
    """Configuration for a single webhook destination."""
    platform: WebhookPlatform
    url: str
    secret: str = ""  # optional signing secret or routing key
    channel: str = ""  # optional override (Slack)
    min_severity: Severity = Severity.LOW
    enabled: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class NotificationResult:
    """Result of sending a notification."""
    platform: WebhookPlatform
    success: bool
    status_code: int = 0
    error: str = ""


class WebhookNotifier:
    """
    Send scan result notifications to configurable webhook endpoints.

    Supports Slack, Teams, PagerDuty, and generic HTTP webhooks.
    Notifications include severity summary, top findings, and gate status.
    """

    def __init__(
        self,
        *,
        webhooks: Optional[List[WebhookConfig]] = None,
        timeout: float = 10.0,
        max_findings_per_message: int = 10,
    ) -> None:
        self._webhooks = webhooks or []
        self._timeout = timeout
        self._max_findings = max_findings_per_message

    def add_webhook(self, config: WebhookConfig) -> None:
        """Register a webhook destination."""
        self._webhooks.append(config)

    async def notify(
        self,
        findings: List[Finding],
        *,
        gate_passed: bool = True,
        scan_url: str = "",
        scan_duration: Optional[float] = None,
    ) -> List[NotificationResult]:
        """
        Send notifications to all configured webhooks.

        Args:
            findings: All findings from the scan.
            gate_passed: Whether the quality gate passed.
            scan_url: Optional URL to the full report.
            scan_duration: Optional scan duration in seconds.

        Returns:
            List of notification results.
        """
        results: List[NotificationResult] = []
        summary = self._build_summary(findings, gate_passed, scan_url, scan_duration)

        for webhook in self._webhooks:
            if not webhook.enabled:
                continue

            # Filter findings by minimum severity
            relevant = [
                f for f in findings
                if f.severity.value >= webhook.min_severity.value
            ]
            if not relevant and gate_passed:
                logger.debug("Skipping %s webhook — no relevant findings", webhook.platform.value)
                continue

            result = await self._send(webhook, relevant, summary)
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Platform-specific payload builders
    # ------------------------------------------------------------------

    def _build_slack_payload(
        self,
        findings: List[Finding],
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build Slack Block Kit message."""
        gate_emoji = ":white_check_mark:" if summary["gate_passed"] else ":x:"
        header = f"{gate_emoji} GateKrumpa Scan {'Passed' if summary['gate_passed'] else 'Failed'}"

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": header}},
            {"type": "section", "text": {"type": "mrkdwn", "text": self._severity_summary_text(summary)}},
        ]

        # Top findings
        top = findings[:self._max_findings]
        if top:
            finding_lines = []
            for f in top:
                icon = self._severity_icon(f.severity)
                finding_lines.append(f"{icon} *{f.title}*")
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(finding_lines)},
            })

        if summary.get("scan_url"):
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Full Report"},
                    "url": summary["scan_url"],
                }],
            })

        return {"blocks": blocks}

    def _build_teams_payload(
        self,
        findings: List[Finding],
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build Microsoft Teams Adaptive Card."""
        gate_status = "PASSED" if summary["gate_passed"] else "FAILED"
        _color = "good" if summary["gate_passed"] else "attention"

        facts = [
            {"name": "Gate Status", "value": gate_status},
            {"name": "Critical", "value": str(summary["counts"].get("critical", 0))},
            {"name": "High", "value": str(summary["counts"].get("high", 0))},
            {"name": "Medium", "value": str(summary["counts"].get("medium", 0))},
            {"name": "Low", "value": str(summary["counts"].get("low", 0))},
            {"name": "Total", "value": str(summary["total"])},
        ]

        sections = [{
            "activityTitle": f"GateKrumpa Scan — {gate_status}",
            "facts": facts,
            "markdown": True,
        }]

        top = findings[:self._max_findings]
        if top:
            text = "\n\n".join(
                f"**[{f.severity.name}]** {f.title}" for f in top
            )
            sections.append({"text": text, "markdown": True})

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if not summary["gate_passed"] else "00FF00",
            "summary": f"GateKrumpa — {gate_status}",
            "sections": sections,
        }

    def _build_pagerduty_payload(
        self,
        findings: List[Finding],
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build PagerDuty Events API v2 payload."""
        critical_count = summary["counts"].get("critical", 0)
        high_count = summary["counts"].get("high", 0)

        # PagerDuty severity mapping
        if critical_count > 0:
            pd_severity = "critical"
        elif high_count > 0:
            pd_severity = "error"
        else:
            pd_severity = "warning"

        return {
            "event_action": "trigger",
            "payload": {
                "summary": (
                    f"GateKrumpa: {summary['total']} findings "
                    f"({critical_count} critical, {high_count} high)"
                ),
                "severity": pd_severity,
                "source": "gatekrumpa",
                "component": "security-scan",
                "custom_details": {
                    "gate_passed": summary["gate_passed"],
                    "findings_by_severity": summary["counts"],
                    "total_findings": summary["total"],
                    "top_findings": [
                        {"title": f.title, "severity": f.severity.name}
                        for f in findings[:5]
                    ],
                },
            },
        }

    def _build_generic_payload(
        self,
        findings: List[Finding],
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build generic JSON webhook payload."""
        return {
            "event": "scan_complete",
            "gate_passed": summary["gate_passed"],
            "summary": {
                "total": summary["total"],
                "by_severity": summary["counts"],
            },
            "scan_url": summary.get("scan_url", ""),
            "scan_duration": summary.get("scan_duration"),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.name,
                    "cwe": f.cwe,
                    "target": f.target.url if f.target else "",
                    "tags": f.tags,
                }
                for f in findings[:self._max_findings]
            ],
        }

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    async def _send(
        self,
        webhook: WebhookConfig,
        findings: List[Finding],
        summary: Dict[str, Any],
    ) -> NotificationResult:
        """Send notification to a single webhook."""
        builders = {
            WebhookPlatform.SLACK: self._build_slack_payload,
            WebhookPlatform.TEAMS: self._build_teams_payload,
            WebhookPlatform.PAGERDUTY: self._build_pagerduty_payload,
            WebhookPlatform.GENERIC: self._build_generic_payload,
        }
        builder = builders.get(webhook.platform, self._build_generic_payload)
        payload = builder(findings, summary)

        headers = {"Content-Type": "application/json"}
        headers.update(webhook.custom_headers)

        # PagerDuty uses routing_key
        if webhook.platform == WebhookPlatform.PAGERDUTY and webhook.secret:
            payload["routing_key"] = webhook.secret

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    webhook.url,
                    content=json.dumps(payload),
                    headers=headers,
                )
                success = resp.status_code < 400
                if not success:
                    logger.warning(
                        "%s webhook returned %d: %s",
                        webhook.platform.value, resp.status_code, resp.text[:200],
                    )
                return NotificationResult(
                    platform=webhook.platform,
                    success=success,
                    status_code=resp.status_code,
                )
        except (httpx.HTTPError, OSError) as exc:
            logger.error("Webhook %s failed: %s", webhook.platform.value, exc)
            return NotificationResult(
                platform=webhook.platform,
                success=False,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        findings: List[Finding],
        gate_passed: bool,
        scan_url: str,
        scan_duration: Optional[float],
    ) -> Dict[str, Any]:
        """Build summary dict from findings."""
        counts: Dict[str, int] = {}
        for f in findings:
            key = f.severity.name.lower()
            counts[key] = counts.get(key, 0) + 1

        return {
            "gate_passed": gate_passed,
            "total": len(findings),
            "counts": counts,
            "scan_url": scan_url,
            "scan_duration": scan_duration,
        }

    @staticmethod
    def _severity_summary_text(summary: Dict[str, Any]) -> str:
        """Build a severity summary line."""
        counts = summary["counts"]
        parts = []
        for level in ("critical", "high", "medium", "low", "info"):
            c = counts.get(level, 0)
            if c:
                parts.append(f"{c} {level}")
        return f"*{summary['total']} findings*: " + ", ".join(parts) if parts else "No findings"

    @staticmethod
    def _severity_icon(severity: Severity) -> str:
        """Emoji icon for severity level."""
        icons = {
            Severity.CRITICAL: ":red_circle:",
            Severity.HIGH: ":large_orange_circle:",
            Severity.MEDIUM: ":large_yellow_circle:",
            Severity.LOW: ":large_blue_circle:",
            Severity.INFO: ":white_circle:",
        }
        return icons.get(severity, ":white_circle:")
