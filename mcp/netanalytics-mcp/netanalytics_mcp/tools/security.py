"""Security tools for MCP server - vulnerability assessment and risk analysis."""

from typing import Annotated

from fastmcp import FastMCP

from netanalytics.security import analyze_risks, check_vulnerabilities, security_assessment


def register_security_tools(mcp: FastMCP) -> None:
    """Register security tools with the MCP server."""

    @mcp.tool()
    def run_security_assessment(
        target: Annotated[str, "Target IP address or hostname"],
        level: Annotated[str, "Assessment level: 'basic' or 'full' (default: basic)"] = "basic",
    ) -> dict:
        """Run a security assessment on a target.

        Basic level: port scan + service detection + common vulnerability checks.
        Full level: comprehensive scan + OS detection + all vulnerability checks + risk analysis.

        Warning: Only scan systems you own or have explicit authorization to test.
        """
        # Warn about external targets
        import ipaddress

        try:
            ip = ipaddress.ip_address(target)
            is_private = ip.is_private
        except ValueError:
            # Hostname - assume could be external
            is_private = target in ("localhost", "127.0.0.1", "::1")

        warning = None
        if not is_private:
            warning = (
                "WARNING: Target appears to be external/public. "
                "Ensure you have authorization to scan this system."
            )

        try:
            result = security_assessment(target, level=level)

            response = {
                "target": target,
                "level": level,
                "assessment": result.to_dict(),
            }

            if warning:
                response["warning"] = warning

            return response

        except Exception as e:
            return {"error": str(e), "assessment": {}}

    @mcp.tool()
    def check_target_vulnerabilities(
        target: Annotated[str, "Target IP address or hostname"],
        ports: Annotated[list[int], "List of open ports to check"],
    ) -> dict:
        """Check for common vulnerabilities on open ports.

        Checks for:
        - Default credentials on common services
        - Known vulnerable service versions
        - Misconfigurations (open relay, anonymous access, etc.)
        - SSL/TLS issues on secure ports

        Returns list of findings with severity and recommendations.
        """
        if not ports:
            return {"error": "Must provide at least one port to check", "vulnerabilities": []}

        try:
            results = check_vulnerabilities(target, ports)

            vulnerabilities = []
            for vuln in results:
                vulnerabilities.append({
                    "port": vuln.port,
                    "service": vuln.service,
                    "vulnerability": vuln.name,
                    "severity": vuln.severity.value,
                    "description": vuln.description,
                    "recommendation": vuln.recommendation,
                    "cve": vuln.cve,
                })

            return {
                "target": target,
                "ports_checked": ports,
                "vulnerability_count": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
            }

        except Exception as e:
            return {"error": str(e), "vulnerabilities": []}

    @mcp.tool()
    def analyze_security_risks(
        findings: Annotated[dict, "Security findings from assessment or vulnerability check"],
    ) -> dict:
        """Analyze risk from security findings.

        Calculates overall risk score based on:
        - Vulnerability severity distribution
        - Exploitability of findings
        - Potential business impact
        - Exposure level

        Returns risk score (0-100), risk level, and prioritized remediation steps.
        """
        if not findings:
            return {"error": "Must provide security findings to analyze", "risk_analysis": {}}

        try:
            analysis = analyze_risks(findings)

            return {
                "risk_score": analysis.score,
                "risk_level": analysis.level.value,
                "summary": analysis.summary,
                "critical_findings": analysis.critical_count,
                "high_findings": analysis.high_count,
                "medium_findings": analysis.medium_count,
                "low_findings": analysis.low_count,
                "remediation_priorities": analysis.remediation_priorities,
            }

        except Exception as e:
            return {"error": str(e), "risk_analysis": {}}
