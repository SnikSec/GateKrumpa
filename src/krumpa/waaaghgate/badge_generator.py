"""Badge generation — SVG pass/fail shield for README.

Phase 4 item #63.
"""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from krumpa.core import Finding, Severity

logger = logging.getLogger("krumpa.waaaghgate.badge_generator")


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class BadgeConfig:
    """Configuration for badge generation."""
    label: str = "security"
    passed_text: str = "passing"
    failed_text: str = "failing"
    warning_text: str = "warnings"
    passed_color: str = "#4c1"       # green
    failed_color: str = "#e05d44"    # red
    warning_color: str = "#dfb317"   # yellow
    info_color: str = "#9f9f9f"      # grey
    label_color: str = "#555"
    font_family: str = "DejaVu Sans,Verdana,Geneva,sans-serif"
    font_size: float = 11.0
    height: int = 20
    padding: int = 6


@dataclass
class BadgeResult:
    """Result from badge generation."""
    svg: str
    status: str       # "passing", "failing", "warnings"
    summary: str      # e.g., "2 critical, 1 high"
    file_name: str = "security-badge.svg"


# ------------------------------------------------------------------
# SVG template (shields.io-compatible flat style)
# ------------------------------------------------------------------

_SVG_TEMPLATE = """\
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" \
width="{total_width}" height="{height}" role="img" aria-label="{label}: {message}">
  <title>{label}: {message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="{height}" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="{height}" fill="{label_color}"/>
    <rect x="{label_width}" width="{message_width}" height="{height}" fill="{message_color}"/>
    <rect width="{total_width}" height="{height}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" \
font-family="{font_family}" text-rendering="geometricPrecision" font-size="{font_size}">
    <text aria-hidden="true" x="{label_x}" y="150" fill="#010101" fill-opacity=".3" \
transform="scale(.1)" textLength="{label_text_len}">{label}</text>
    <text x="{label_x}" y="140" transform="scale(.1)" fill="#fff" \
textLength="{label_text_len}">{label}</text>
    <text aria-hidden="true" x="{message_x}" y="150" fill="#010101" fill-opacity=".3" \
transform="scale(.1)" textLength="{message_text_len}">{message}</text>
    <text x="{message_x}" y="140" transform="scale(.1)" fill="#fff" \
textLength="{message_text_len}">{message}</text>
  </g>
</svg>"""


class BadgeGenerator:
    """Generate SVG pass/fail badges from scan findings.

    Produces shields.io-compatible flat-style badges that can be
    embedded in README files, CI dashboards, or PR comments.

    Badge states:
    - **passing** (green): no high/critical findings
    - **warnings** (yellow): medium findings exist, no high/critical
    - **failing** (red): high or critical findings
    """

    def __init__(self, config: Optional[BadgeConfig] = None) -> None:
        self._config = config or BadgeConfig()

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    def generate(self, findings: List[Finding]) -> BadgeResult:
        """Generate an SVG badge from scan findings."""
        counts = self._count_by_severity(findings)
        status, color, message = self._determine_status(counts)

        svg = self._render_svg(
            label=self._config.label,
            message=message,
            message_color=color,
        )

        return BadgeResult(
            svg=svg,
            status=status,
            summary=self._build_summary(counts),
        )

    def generate_detailed(self, findings: List[Finding]) -> List[BadgeResult]:
        """Generate multiple badges — overall + per-severity."""
        badges: List[BadgeResult] = []

        # Overall badge
        badges.append(self.generate(findings))

        # Per-severity badges
        counts = self._count_by_severity(findings)
        for sev, count in counts.items():
            if count > 0:
                color = self._severity_color(sev)
                svg = self._render_svg(
                    label=sev.value.lower(),
                    message=str(count),
                    message_color=color,
                )
                badges.append(BadgeResult(
                    svg=svg,
                    status=sev.value.lower(),
                    summary=f"{count} {sev.value.lower()}",
                    file_name=f"security-{sev.value.lower()}.svg",
                ))

        return badges

    def generate_gate_badge(
        self, passed: bool, detail: str = "",
    ) -> BadgeResult:
        """Generate a gate pass/fail badge."""
        cfg = self._config
        if passed:
            status = cfg.passed_text
            color = cfg.passed_color
        else:
            status = cfg.failed_text
            color = cfg.failed_color

        message = detail or status
        svg = self._render_svg(
            label="gate",
            message=message,
            message_color=color,
        )

        return BadgeResult(
            svg=svg,
            status=status,
            summary=message,
            file_name="gate-badge.svg",
        )

    # ----------------------------------------------------------
    # Status determination
    # ----------------------------------------------------------

    def _count_by_severity(
        self, findings: List[Finding],
    ) -> Dict[Severity, int]:
        """Count findings by severity."""
        counts: Dict[Severity, int] = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def _determine_status(
        self, counts: Dict[Severity, int],
    ) -> tuple[str, str, str]:
        """Determine badge status, color, and message text."""
        cfg = self._config

        critical = counts.get(Severity.CRITICAL, 0)
        high = counts.get(Severity.HIGH, 0)
        medium = counts.get(Severity.MEDIUM, 0)
        low = counts.get(Severity.LOW, 0)

        if critical > 0 or high > 0:
            parts = []
            if critical:
                parts.append(f"{critical} critical")
            if high:
                parts.append(f"{high} high")
            return cfg.failed_text, cfg.failed_color, " | ".join(parts)

        if medium > 0:
            return cfg.warning_text, cfg.warning_color, f"{medium} medium"

        if low > 0:
            return cfg.passed_text, cfg.passed_color, f"{low} low"

        return cfg.passed_text, cfg.passed_color, cfg.passed_text

    def _severity_color(self, sev: Severity) -> str:
        """Map severity to badge color."""
        cfg = self._config
        return {
            Severity.CRITICAL: cfg.failed_color,
            Severity.HIGH: cfg.failed_color,
            Severity.MEDIUM: cfg.warning_color,
            Severity.LOW: cfg.passed_color,
            Severity.INFO: cfg.info_color,
        }.get(sev, cfg.info_color)

    @staticmethod
    def _build_summary(counts: Dict[Severity, int]) -> str:
        """Build a human-readable summary."""
        parts = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                     Severity.LOW, Severity.INFO):
            count = counts.get(sev, 0)
            if count > 0:
                parts.append(f"{count} {sev.value.lower()}")
        return ", ".join(parts) if parts else "no findings"

    # ----------------------------------------------------------
    # SVG rendering
    # ----------------------------------------------------------

    def _render_svg(
        self, label: str, message: str, message_color: str,
    ) -> str:
        """Render an SVG badge."""
        cfg = self._config

        # Estimate text widths (approx 6.5px per char at 11pt)
        char_width = 6.5
        label_text_width = len(label) * char_width
        message_text_width = len(message) * char_width

        label_width = int(label_text_width + cfg.padding * 2)
        message_width = int(message_text_width + cfg.padding * 2)
        total_width = label_width + message_width

        # Scale positions for SVG viewbox (10x for precision)
        label_x = label_width * 10 // 2
        message_x = (label_width + message_width // 2) * 10
        label_text_len = int(label_text_width * 10)
        message_text_len = int(message_text_width * 10)

        return _SVG_TEMPLATE.format(
            total_width=total_width,
            height=cfg.height,
            label_width=label_width,
            message_width=message_width,
            label_color=cfg.label_color,
            message_color=message_color,
            font_family=html.escape(cfg.font_family),
            font_size=int(cfg.font_size * 10),
            label_x=label_x,
            message_x=message_x,
            label_text_len=label_text_len,
            message_text_len=message_text_len,
            label=html.escape(label),
            message=html.escape(message),
        )
