"""Risk analysis functionality."""

from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    """Risk level enumeration."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskFactor:
    """Individual risk factor."""

    name: str
    level: RiskLevel
    description: str
    score: float  # 0.0 to 10.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "level": self.level.value,
            "description": self.description,
            "score": self.score,
        }


@dataclass
class RiskAnalysis:
    """Complete risk analysis results."""

    overall_level: RiskLevel
    overall_score: float  # 0.0 to 10.0
    factors: list[RiskFactor]

    def to_dict(self) -> dict:
        return {
            "overall_level": self.overall_level.value,
            "overall_score": round(self.overall_score, 1),
            "factors": [f.to_dict() for f in self.factors],
        }

    def __str__(self) -> str:
        lines = [
            f"Overall Risk: {self.overall_level.value.upper()} ({self.overall_score:.1f}/10)",
            "",
            "Risk Factors:",
        ]

        for factor in self.factors:
            lines.append(f"  - {factor.name}: {factor.level.value} ({factor.score:.1f})")
            lines.append(f"    {factor.description}")

        return "\n".join(lines)


def _calculate_port_risk(open_ports: list[int]) -> RiskFactor:
    """Calculate risk based on open ports."""
    HIGH_RISK_PORTS = {21, 23, 445, 3389, 1433, 1521, 3306, 5432, 27017}
    MEDIUM_RISK_PORTS = {22, 25, 53, 110, 143, 161, 389, 636}

    high_risk_count = sum(1 for p in open_ports if p in HIGH_RISK_PORTS)
    medium_risk_count = sum(1 for p in open_ports if p in MEDIUM_RISK_PORTS)

    if high_risk_count >= 3:
        return RiskFactor(
            name="Exposed High-Risk Ports",
            level=RiskLevel.CRITICAL,
            description=f"{high_risk_count} high-risk ports exposed (databases, remote access)",
            score=9.0,
        )
    elif high_risk_count >= 1:
        return RiskFactor(
            name="Exposed High-Risk Ports",
            level=RiskLevel.HIGH,
            description=f"{high_risk_count} high-risk port(s) exposed",
            score=7.0,
        )
    elif medium_risk_count >= 3:
        return RiskFactor(
            name="Multiple Services Exposed",
            level=RiskLevel.MEDIUM,
            description=f"{medium_risk_count} services exposed",
            score=5.0,
        )
    elif len(open_ports) > 10:
        return RiskFactor(
            name="Many Open Ports",
            level=RiskLevel.MEDIUM,
            description=f"{len(open_ports)} open ports detected",
            score=4.0,
        )
    else:
        return RiskFactor(
            name="Port Exposure",
            level=RiskLevel.LOW,
            description=f"{len(open_ports)} open ports detected",
            score=2.0,
        )


def _calculate_service_risk(services: list[dict]) -> RiskFactor:
    """Calculate risk based on detected services."""
    unencrypted = ["ftp", "telnet", "http", "smtp", "pop3", "imap"]
    databases = ["mysql", "postgresql", "mongodb", "redis", "mssql"]

    unencrypted_count = sum(1 for s in services if s.get("service", "").lower() in unencrypted)
    database_count = sum(1 for s in services if s.get("service", "").lower() in databases)

    if database_count >= 2:
        return RiskFactor(
            name="Multiple Databases Exposed",
            level=RiskLevel.CRITICAL,
            description=f"{database_count} database services exposed to network",
            score=9.5,
        )
    elif database_count == 1:
        return RiskFactor(
            name="Database Exposed",
            level=RiskLevel.HIGH,
            description="Database service exposed to network",
            score=7.5,
        )
    elif unencrypted_count >= 3:
        return RiskFactor(
            name="Multiple Unencrypted Services",
            level=RiskLevel.HIGH,
            description=f"{unencrypted_count} unencrypted services in use",
            score=6.5,
        )
    elif unencrypted_count >= 1:
        return RiskFactor(
            name="Unencrypted Services",
            level=RiskLevel.MEDIUM,
            description=f"{unencrypted_count} unencrypted service(s) in use",
            score=4.5,
        )
    else:
        return RiskFactor(
            name="Service Security",
            level=RiskLevel.LOW,
            description="Services appear reasonably configured",
            score=2.0,
        )


def _calculate_vuln_risk(vulnerabilities: list) -> RiskFactor:
    """Calculate risk based on vulnerabilities."""
    critical = sum(1 for v in vulnerabilities if v.severity == "critical")
    high = sum(1 for v in vulnerabilities if v.severity == "high")
    medium = sum(1 for v in vulnerabilities if v.severity == "medium")

    if critical >= 1:
        return RiskFactor(
            name="Critical Vulnerabilities",
            level=RiskLevel.CRITICAL,
            description=f"{critical} critical vulnerability(ies) found",
            score=10.0,
        )
    elif high >= 3:
        return RiskFactor(
            name="Multiple High Vulnerabilities",
            level=RiskLevel.HIGH,
            description=f"{high} high-severity vulnerabilities found",
            score=8.0,
        )
    elif high >= 1:
        return RiskFactor(
            name="High Vulnerability",
            level=RiskLevel.HIGH,
            description=f"{high} high-severity vulnerability found",
            score=7.0,
        )
    elif medium >= 3:
        return RiskFactor(
            name="Multiple Medium Vulnerabilities",
            level=RiskLevel.MEDIUM,
            description=f"{medium} medium-severity vulnerabilities found",
            score=5.0,
        )
    elif medium >= 1:
        return RiskFactor(
            name="Medium Vulnerability",
            level=RiskLevel.MEDIUM,
            description=f"{medium} medium-severity vulnerability found",
            score=4.0,
        )
    else:
        return RiskFactor(
            name="No Major Vulnerabilities",
            level=RiskLevel.LOW,
            description="No significant vulnerabilities detected",
            score=1.0,
        )


def analyze_risks(
    open_ports: list[int],
    services: list[dict],
    vulnerabilities: list,
) -> RiskAnalysis:
    """
    Analyze overall risk based on findings.

    Args:
        open_ports: List of open ports
        services: List of detected services
        vulnerabilities: List of vulnerability findings

    Returns:
        RiskAnalysis with overall assessment
    """
    factors = []

    # Calculate individual risk factors
    if open_ports:
        factors.append(_calculate_port_risk(open_ports))

    if services:
        factors.append(_calculate_service_risk(services))

    factors.append(_calculate_vuln_risk(vulnerabilities))

    # Calculate overall score (weighted average)
    if factors:
        total_score = sum(f.score for f in factors)
        overall_score = total_score / len(factors)
    else:
        overall_score = 0.0

    # Determine overall level
    if overall_score >= 8.0:
        overall_level = RiskLevel.CRITICAL
    elif overall_score >= 6.0:
        overall_level = RiskLevel.HIGH
    elif overall_score >= 4.0:
        overall_level = RiskLevel.MEDIUM
    elif overall_score >= 2.0:
        overall_level = RiskLevel.LOW
    else:
        overall_level = RiskLevel.INFO

    return RiskAnalysis(
        overall_level=overall_level,
        overall_score=overall_score,
        factors=factors,
    )
