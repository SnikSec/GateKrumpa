"""
WaaaghGate — CI/CD Integration module.

Responsibilities:
    - Quality-gate policy evaluation (fail/warn thresholds by severity)
    - SARIF, JSON, and Markdown report generation
    - Exit-code determination for pipeline integration
"""

from krumpa.waaaghgate.gate import GatePolicy, GateResult, PolicyViolation
from krumpa.waaaghgate.reporter import PipelineReporter, ReportFormat
from krumpa.waaaghgate.baseline import Baseline, BaselineDiff
from krumpa.waaaghgate.policy_loader import PolicyLoader, validate_policy, list_environments
from krumpa.waaaghgate.suppression import SuppressionManager, SuppressionRule, SuppressionResult
from krumpa.waaaghgate.pr_annotator import PrAnnotator, PrAnnotation, PrReport
from krumpa.waaaghgate.html_report import HtmlReportGenerator
from krumpa.waaaghgate.diff_report import DiffReporter, DiffReport
from krumpa.waaaghgate.compliance import ComplianceMapper
from krumpa.waaaghgate.module import WaaaghGateModule

__all__ = [
    "WaaaghGateModule",
    "GatePolicy",
    "GateResult",
    "PolicyViolation",
    "PipelineReporter",
    "ReportFormat",
    "Baseline",
    "BaselineDiff",
    "PolicyLoader",
    "validate_policy",
    "list_environments",
    "SuppressionManager",
    "SuppressionRule",
    "SuppressionResult",
    "PrAnnotator",
    "PrAnnotation",
    "PrReport",
    "HtmlReportGenerator",
    "DiffReporter",
    "DiffReport",
    "ComplianceMapper",
]
