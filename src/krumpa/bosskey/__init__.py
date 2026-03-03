"""
BossKey — Auth Modeling module.

Responsibilities:
    - Session / token security analysis (cookie flags, entropy, JWT inspection)
    - Authentication endpoint probing (default creds, lockout, rate-limit)
    - Authorisation boundary testing (privilege escalation, IDOR indicators)
"""

from krumpa.bosskey.session_analyzer import SessionAnalyzer
from krumpa.bosskey.auth_probe import AuthProbe
from krumpa.bosskey.csrf_checker import CsrfChecker
from krumpa.bosskey.oauth2_analyzer import OAuth2Analyzer
from krumpa.bosskey.session_fixation import SessionFixationChecker
from krumpa.bosskey.password_policy import PasswordPolicyTester
from krumpa.bosskey.session_timeout import SessionTimeoutTester
from krumpa.bosskey.lockout_tester import AccountLockoutTester
from krumpa.bosskey.jwt_attacks import JwtAdvancedTester
from krumpa.bosskey.rbac_matrix import RbacMatrixBuilder
from krumpa.bosskey.module import BossKeyModule

__all__ = [
    "BossKeyModule",
    "SessionAnalyzer",
    "AuthProbe",
    "CsrfChecker",
    "OAuth2Analyzer",
    "SessionFixationChecker",
    "PasswordPolicyTester",
    "SessionTimeoutTester",
    "AccountLockoutTester",
    "JwtAdvancedTester",
    "RbacMatrixBuilder",
]
