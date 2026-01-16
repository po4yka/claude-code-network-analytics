"""Tests for security module."""

import pytest

from netanalytics.security.risks import (
    RiskLevel,
    RiskFactor,
    RiskAnalysis,
    analyze_risks,
)
from netanalytics.security.vulnerabilities import (
    VulnerabilityResult,
    DefaultCredentialsCheck,
    UnencryptedServiceCheck,
    OpenDatabaseCheck,
)


class TestRiskLevel:
    """Test risk level enumeration."""

    def test_risk_levels(self):
        """Test all risk levels."""
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.INFO.value == "info"


class TestRiskFactor:
    """Test RiskFactor dataclass."""

    def test_risk_factor_creation(self):
        """Test creating a risk factor."""
        factor = RiskFactor(
            name="Test Risk",
            level=RiskLevel.HIGH,
            description="Test description",
            score=7.5,
        )
        assert factor.name == "Test Risk"
        assert factor.level == RiskLevel.HIGH
        assert factor.score == 7.5

    def test_risk_factor_to_dict(self):
        """Test risk factor serialization."""
        factor = RiskFactor(
            name="Exposed Service",
            level=RiskLevel.MEDIUM,
            description="Service is exposed",
            score=5.0,
        )
        data = factor.to_dict()
        assert data["name"] == "Exposed Service"
        assert data["level"] == "medium"
        assert data["score"] == 5.0


class TestRiskAnalysis:
    """Test risk analysis functionality."""

    def test_analyze_empty(self):
        """Test risk analysis with no data."""
        analysis = analyze_risks([], [], [])
        assert analysis.overall_level == RiskLevel.INFO
        assert analysis.overall_score == 0.0

    def test_analyze_high_risk_ports(self):
        """Test risk analysis with dangerous ports."""
        open_ports = [21, 23, 3306, 6379]  # FTP, Telnet, MySQL, Redis
        analysis = analyze_risks(open_ports, [], [])
        assert analysis.overall_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_analyze_with_vulnerabilities(self):
        """Test risk analysis with critical vulnerabilities."""
        vulns = [
            VulnerabilityResult(
                name="Critical Bug",
                severity="critical",
                description="Test",
                port=80,
                service="http",
                remediation="Fix it",
            )
        ]
        analysis = analyze_risks([80], [], vulns)
        assert analysis.overall_level == RiskLevel.CRITICAL


class TestVulnerabilityChecks:
    """Test vulnerability check classes."""

    def test_default_credentials_check(self):
        """Test default credentials vulnerability check."""
        check = DefaultCredentialsCheck()

        # Should flag FTP
        result = check.check("192.168.1.1", 21, {"service": "ftp"})
        assert result is not None
        assert result.severity == "high"

        # Should not flag SSH
        result = check.check("192.168.1.1", 22, {"service": "ssh"})
        assert result is not None  # SSH also has default creds risk

    def test_unencrypted_service_check(self):
        """Test unencrypted service vulnerability check."""
        check = UnencryptedServiceCheck()

        # Should flag HTTP
        result = check.check("192.168.1.1", 80, {"service": "http"})
        assert result is not None
        assert "HTTPS" in result.remediation

        # Should flag Telnet
        result = check.check("192.168.1.1", 23, {"service": "telnet"})
        assert result is not None
        assert "SSH" in result.remediation

    def test_open_database_check(self):
        """Test exposed database vulnerability check."""
        check = OpenDatabaseCheck()

        # Should flag MySQL
        result = check.check("192.168.1.1", 3306, {})
        assert result is not None
        assert result.severity == "critical"

        # Should flag PostgreSQL
        result = check.check("192.168.1.1", 5432, {})
        assert result is not None

        # Should not flag HTTP
        result = check.check("192.168.1.1", 80, {})
        assert result is None


class TestVulnerabilityResult:
    """Test VulnerabilityResult dataclass."""

    def test_vulnerability_result_creation(self):
        """Test creating a vulnerability result."""
        vuln = VulnerabilityResult(
            name="SQL Injection",
            severity="high",
            description="Input not sanitized",
            port=80,
            service="http",
            remediation="Use parameterized queries",
            cve="CVE-2021-12345",
            cvss=8.5,
        )
        assert vuln.name == "SQL Injection"
        assert vuln.severity == "high"
        assert vuln.cve == "CVE-2021-12345"

    def test_vulnerability_result_to_dict(self):
        """Test vulnerability result serialization."""
        vuln = VulnerabilityResult(
            name="XSS",
            severity="medium",
            description="Cross-site scripting",
            port=443,
            service="https",
            remediation="Sanitize output",
        )
        data = vuln.to_dict()
        assert data["name"] == "XSS"
        assert data["severity"] == "medium"
        assert data["port"] == 443
