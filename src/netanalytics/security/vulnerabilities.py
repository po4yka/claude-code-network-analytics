"""Vulnerability checking functionality."""

from dataclasses import dataclass


@dataclass
class VulnerabilityResult:
    """Result of a vulnerability check."""

    name: str
    severity: str  # critical, high, medium, low, info
    description: str
    port: int | None
    service: str | None
    remediation: str
    cve: str | None = None
    cvss: float | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "port": self.port,
            "service": self.service,
            "remediation": self.remediation,
            "cve": self.cve,
            "cvss": self.cvss,
        }


class VulnerabilityCheck:
    """Base class for vulnerability checks."""

    name: str = "Unknown"
    severity: str = "info"

    def check(self, target: str, port: int, service_info: dict) -> VulnerabilityResult | None:
        """Run the vulnerability check. Override in subclass."""
        raise NotImplementedError


class DefaultCredentialsCheck(VulnerabilityCheck):
    """Check for common default credentials."""

    name = "Default Credentials"
    severity = "high"

    # Services known to have default credentials issues
    VULNERABLE_SERVICES = {
        "ftp": "admin:admin, anonymous:anonymous",
        "ssh": "root:root, admin:admin",
        "telnet": "admin:admin, root:root",
        "mysql": "root:(empty)",
        "postgresql": "postgres:postgres",
        "redis": "No authentication",
        "mongodb": "No authentication",
    }

    def check(self, target: str, port: int, service_info: dict) -> VulnerabilityResult | None:
        service = service_info.get("service", "").lower()

        if service in self.VULNERABLE_SERVICES:
            vuln_service = self.VULNERABLE_SERVICES[service]
            return VulnerabilityResult(
                name=self.name,
                severity=self.severity,
                description=f"Service may be vulnerable to default credentials: {vuln_service}",
                port=port,
                service=service,
                remediation="Change default credentials immediately.",
            )
        return None


class UnencryptedServiceCheck(VulnerabilityCheck):
    """Check for unencrypted services."""

    name = "Unencrypted Service"
    severity = "medium"

    UNENCRYPTED_SERVICES = {
        "ftp": ("SFTP", 22),
        "telnet": ("SSH", 22),
        "http": ("HTTPS", 443),
        "smtp": ("SMTPS", 465),
        "pop3": ("POP3S", 995),
        "imap": ("IMAPS", 993),
    }

    def check(self, target: str, port: int, service_info: dict) -> VulnerabilityResult | None:
        service = service_info.get("service", "").lower()

        if service in self.UNENCRYPTED_SERVICES:
            alt_service, alt_port = self.UNENCRYPTED_SERVICES[service]
            return VulnerabilityResult(
                name=self.name,
                severity=self.severity,
                description=f"{service.upper()} transmits data in plaintext.",
                port=port,
                service=service,
                remediation=f"Use {alt_service} (port {alt_port}) instead.",
            )
        return None


class OutdatedServiceCheck(VulnerabilityCheck):
    """Check for outdated service versions."""

    name = "Outdated Service Version"
    severity = "medium"

    # Known vulnerable versions (simplified)
    VULNERABLE_VERSIONS = {
        "openssh": {"max_safe": "8.0", "cve": "CVE-2019-6111"},
        "apache": {"max_safe": "2.4.50", "cve": "CVE-2021-41773"},
        "nginx": {"max_safe": "1.20.0", "cve": "CVE-2021-23017"},
        "mysql": {"max_safe": "8.0.25", "cve": "CVE-2021-2307"},
    }

    def check(self, target: str, port: int, service_info: dict) -> VulnerabilityResult | None:
        product = service_info.get("product", "").lower()
        version = service_info.get("version", "")

        for vuln_product, info in self.VULNERABLE_VERSIONS.items():
            if vuln_product in product and version:
                # Simplified version comparison
                return VulnerabilityResult(
                    name=self.name,
                    severity=self.severity,
                    description=f"{product} version {version} may have known vulnerabilities.",
                    port=port,
                    service=service_info.get("service"),
                    remediation="Update to the latest version.",
                    cve=info.get("cve"),
                )
        return None


class OpenDatabaseCheck(VulnerabilityCheck):
    """Check for databases exposed without authentication."""

    name = "Exposed Database"
    severity = "critical"

    DATABASE_PORTS = {
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
        1433: "MSSQL",
        1521: "Oracle",
    }

    def check(self, target: str, port: int, service_info: dict) -> VulnerabilityResult | None:
        if port in self.DATABASE_PORTS:
            db_name = self.DATABASE_PORTS[port]
            return VulnerabilityResult(
                name=self.name,
                severity=self.severity,
                description=f"{db_name} database is exposed on port {port}.",
                port=port,
                service=db_name.lower(),
                remediation=f"Restrict {db_name} access to localhost or internal networks only.",
            )
        return None


# Registry of all checks
VULNERABILITY_CHECKS = [
    DefaultCredentialsCheck(),
    UnencryptedServiceCheck(),
    OutdatedServiceCheck(),
    OpenDatabaseCheck(),
]


def check_vulnerabilities(
    target: str,
    open_ports: list[int],
    services: list[dict],
    level: str = "basic",
) -> list[VulnerabilityResult]:
    """
    Check for vulnerabilities on a target.

    Args:
        target: Target IP or hostname
        open_ports: List of open ports
        services: List of detected services
        level: Check level ("basic" or "full")

    Returns:
        List of vulnerability findings
    """
    vulnerabilities = []

    # Create port-to-service mapping
    port_services = {s.get("port"): s for s in services if s.get("port")}

    for port in open_ports:
        service_info = port_services.get(port, {"port": port})

        for check in VULNERABILITY_CHECKS:
            try:
                result = check.check(target, port, service_info)
                if result:
                    vulnerabilities.append(result)
            except Exception:
                continue

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 5))

    return vulnerabilities
