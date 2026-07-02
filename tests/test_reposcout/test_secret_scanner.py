"""Tests for SecretScanner — repository secret detection."""

from __future__ import annotations


from krumpa.core import Severity, Target
from krumpa.reposcout.repo_crawler import RepoData
from krumpa.reposcout.secret_scanner import SecretScanner


def _make_repo(files: dict) -> RepoData:
    data = RepoData(provider="github", org="test-org", repo="test-repo")
    data.files.update(files)
    return data


class TestSecretScanner:

    def _target(self) -> Target:
        return Target(url="github://test-org/test-repo")

    def test_detects_aws_access_key(self):
        repo = _make_repo({"config.py": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        assert any("AWS Access Key" in f.title for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_github_token(self):
        repo = _make_repo({"deploy.sh": "TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN"})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        assert any("GitHub Token" in f.title for f in findings)

    def test_detects_openai_key(self):
        repo = _make_repo({"app.py": "OPENAI_API_KEY = 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcde'"})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        assert any("OpenAI" in f.title for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_database_url(self):
        repo = _make_repo({"settings.py": "DB = 'postgres://admin:password123@db.example.com:5432/mydb'"})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        assert any("Database URL" in f.title for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_detects_private_key_header(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        repo = _make_repo({"id_rsa": pem})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        assert any("Private" in f.title for f in findings)

    def test_lowers_severity_in_example_files(self):
        repo = _make_repo({"example_config.py": "API_KEY = 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcde'"})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        # Severity should be reduced for example/test files — not CRITICAL
        if findings:
            non_critical = [f for f in findings if f.severity != Severity.CRITICAL]
            assert len(non_critical) >= 1

    def test_evidence_does_not_contain_full_secret(self):
        repo = _make_repo({"config.py": "KEY = 'AKIAIOSFODNN7EXAMPLE'"})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        for f in findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence

    def test_deduplicates_same_pattern_per_file(self):
        # Same AWS key appears on two lines in same file — should produce one finding per file
        content = "KEY1 = 'AKIAIOSFODNN7EXAMPLE'\nKEY2 = 'AKIAIOSFODNN7EXAMPLA'"
        repo = _make_repo({"config.py": content})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        aws_findings = [f for f in findings if "AWS Access Key" in f.title and "config.py" in f.evidence]
        assert len(aws_findings) == 1

    def test_no_findings_for_clean_code(self):
        clean = "import os\n\ndef main():\n    print('hello world')\n"
        repo = _make_repo({"main.py": clean})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert critical_high == []

    def test_empty_repo_returns_no_findings(self):
        repo = RepoData(provider="github", org="org", repo="repo")
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())
        assert findings == []

    def test_skips_binary_extensions(self):
        # .png extension should be skipped
        repo = _make_repo({"logo.png": "AKIAIOSFODNN7EXAMPLE"})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())
        assert findings == []

    def test_finding_includes_line_number(self):
        repo = _make_repo({"config.py": "x = 1\ny = 2\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nz = 3"})
        scanner = SecretScanner()
        findings = scanner.scan(repo, self._target())

        assert any("Line: 3" in f.evidence for f in findings)
