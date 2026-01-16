"""Security assessment functionality."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from .risks import RiskAnalysis, RiskLevel, analyze_risks
from .vulnerabilities import VulnerabilityResult, check_vulnerabilities


class AssessmentLevel(Enum):
    """Assessment thoroughness level."""

    BASIC = "basic"
    FULL = "full"


@dataclass
class SecurityAssessment:
    """Complete security assessment results."""

    target: str
    level: AssessmentLevel
    start_time: datetime
    end_time: datetime
    open_ports: list[int]
    services: list[dict]
    vulnerabilities: list[VulnerabilityResult]
    risk_analysis: RiskAnalysis
    recommendations: list[str]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "level": self.level.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
            "open_ports": self.open_ports,
            "services": self.services,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "risk_analysis": self.risk_analysis.to_dict(),
            "recommendations": self.recommendations,
            "summary": {
                "total_vulns": len(self.vulnerabilities),
                "critical_vulns": sum(1 for v in self.vulnerabilities if v.severity == "critical"),
                "high_vulns": sum(1 for v in self.vulnerabilities if v.severity == "high"),
                "overall_risk": self.risk_analysis.overall_level.value,
            },
        }

    def __str__(self) -> str:
        lines = [
            f"Security Assessment: {self.target}",
            f"Level: {self.level.value}",
            f"Duration: {(self.end_time - self.start_time).total_seconds():.2f}s",
            "",
            f"Open Ports: {len(self.open_ports)}",
            f"Services Detected: {len(self.services)}",
            "",
            "Vulnerabilities:",
            f"  Critical: {sum(1 for v in self.vulnerabilities if v.severity == 'critical')}",
            f"  High: {sum(1 for v in self.vulnerabilities if v.severity == 'high')}",
            f"  Medium: {sum(1 for v in self.vulnerabilities if v.severity == 'medium')}",
            f"  Low: {sum(1 for v in self.vulnerabilities if v.severity == 'low')}",
            "",
            f"Overall Risk Level: {self.risk_analysis.overall_level.value.upper()}",
            "",
            "Recommendations:",
        ]

        for i, rec in enumerate(self.recommendations[:5], 1):
            lines.append(f"  {i}. {rec}")

        return "\n".join(lines)


def security_assessment(
    target: str,
    level: str = "basic",
    ports: str | None = None,
) -> SecurityAssessment:
    """
    Perform security assessment on a target.

    Args:
        target: Target IP or hostname
        level: Assessment level ("basic" or "full")
        ports: Specific ports to check (default: common ports)

    Returns:
        SecurityAssessment with findings
    """
    from ..discovery import detect_services, port_scan

    assessment_level = AssessmentLevel(level)
    start_time = datetime.now()

    # Default ports based on level
    if ports is None:
        if assessment_level == AssessmentLevel.BASIC:
            ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080"
        else:
            ports = "1-1024"

    # Port scan
    scan_result = port_scan(target, ports=ports, scan_type="connect", grab_banner=True)

    open_ports = [p.port for p in scan_result.get_open_ports()]

    # Service detection on open ports
    services = []
    if open_ports:
        service_results = detect_services(target, open_ports)
        services = [s.to_dict() for s in service_results if s.service]

    # Vulnerability checks
    vulnerabilities = check_vulnerabilities(target, open_ports, services, level=level)

    # Risk analysis
    risk_analysis = analyze_risks(open_ports, services, vulnerabilities)

    # Generate recommendations
    recommendations = _generate_recommendations(
        open_ports, services, vulnerabilities, risk_analysis
    )

    end_time = datetime.now()

    return SecurityAssessment(
        target=target,
        level=assessment_level,
        start_time=start_time,
        end_time=end_time,
        open_ports=open_ports,
        services=services,
        vulnerabilities=vulnerabilities,
        risk_analysis=risk_analysis,
        recommendations=recommendations,
    )


def _generate_recommendations(
    open_ports: list[int],
    services: list[dict],
    vulnerabilities: list[VulnerabilityResult],
    risk_analysis: RiskAnalysis,
) -> list[str]:
    """Generate security recommendations based on findings."""
    recommendations = []

    # Port-based recommendations
    dangerous_ports = {
        21: "FTP is insecure. Consider SFTP instead.",
        23: "Telnet is insecure. Use SSH instead.",
        445: "SMB exposed. Ensure proper firewall rules.",
        3389: "RDP exposed. Use VPN or limit access.",
    }

    for port in open_ports:
        if port in dangerous_ports:
            recommendations.append(dangerous_ports[port])

    # Service-based recommendations
    for service in services:
        if service.get("service") == "ssh":
            recommendations.append("Ensure SSH uses key-based authentication.")
        elif service.get("service") in ("http", "https"):
            recommendations.append("Ensure web services use HTTPS with valid certificates.")

    # Vulnerability-based recommendations
    critical_vulns = [v for v in vulnerabilities if v.severity == "critical"]
    if critical_vulns:
        recommendations.insert(
            0, f"URGENT: Address {len(critical_vulns)} critical vulnerabilities immediately."
        )

    # General recommendations based on risk level
    if risk_analysis.overall_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        recommendations.append("Consider a penetration test to identify additional issues.")
        recommendations.append("Review firewall rules and network segmentation.")

    # Deduplicate and limit
    seen = set()
    unique_recs = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recs.append(rec)

    return unique_recs[:10]
