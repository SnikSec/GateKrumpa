"""
WaaaghLogic — Business Logic Testing module.

Responsibilities:
    - Multi-step workflow analysis (step skipping, out-of-order access)
    - Parameter tampering detection (price, quantity, role manipulation)
    - Idempotency & replay attack testing
    - Race condition probing on state-changing endpoints
"""

from krumpa.waaaghlogic.flow_analyzer import FlowAnalyzer, WorkflowStep
from krumpa.waaaghlogic.idempotency_checker import IdempotencyChecker
from krumpa.waaaghlogic.mass_assignment import MassAssignmentTester
from krumpa.waaaghlogic.file_upload import FileUploadTester
from krumpa.waaaghlogic.privilege_escalation import PrivilegeEscalationTester
from krumpa.waaaghlogic.pagination import PaginationTester
from krumpa.waaaghlogic.module import WaaaghLogicModule

__all__ = [
    "WaaaghLogicModule",
    "FlowAnalyzer",
    "WorkflowStep",
    "IdempotencyChecker",
    "MassAssignmentTester",
    "FileUploadTester",
    "PrivilegeEscalationTester",
    "PaginationTester",
]
