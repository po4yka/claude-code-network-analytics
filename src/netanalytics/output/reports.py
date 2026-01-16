"""Report generation functionality."""

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from ..core.utils import ensure_results_dir

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Analysis Report - {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6; color: #333; max-width: 1200px;
            margin: 0 auto; padding: 20px; background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px;
        }
        .header h1 { font-size: 2em; margin-bottom: 10px; }
        .header .meta { opacity: 0.9; font-size: 0.9em; }
        .card {
            background: white; border-radius: 10px; padding: 20px;
            margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h2 {
            color: #667eea; border-bottom: 2px solid #eee;
            padding-bottom: 10px; margin-bottom: 15px;
        }
        .summary-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .summary-item {
            background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center;
        }
        .summary-item .value { font-size: 2em; font-weight: bold; color: #667eea; }
        .summary-item .label { color: #666; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .risk-badge {
            display: inline-block; padding: 5px 15px; border-radius: 20px;
            font-weight: bold; color: white;
        }
        .risk-critical { background: #dc3545; }
        .risk-high { background: #fd7e14; }
        .risk-medium { background: #ffc107; color: #333; }
        .risk-low { background: #28a745; }
        .recommendation {
            background: #e7f3ff; border-left: 4px solid #667eea;
            padding: 10px 15px; margin: 10px 0; border-radius: 0 5px 5px 0;
        }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Analysis Report</h1>
        <div class="meta">
            <strong>Target:</strong> {{ target }}<br>
            <strong>Generated:</strong> {{ timestamp }}<br>
            <strong>Assessment Level:</strong> {{ level }}
        </div>
    </div>

    <div class="card">
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="value">{{ open_ports|length }}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="summary-item">
                <div class="value">{{ services|length }}</div>
                <div class="label">Services</div>
            </div>
            <div class="summary-item">
                <div class="value">{{ vulnerabilities|length }}</div>
                <div class="label">Vulnerabilities</div>
            </div>
            <div class="summary-item">
                <div class="value">
                    <span class="risk-badge risk-{{ risk_level }}">{{ risk_level|upper }}</span>
                </div>
                <div class="label">Risk Level</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Open Ports</h2>
        {% if open_ports %}
        <table>
            <tr><th>Port</th><th>Service</th><th>Version</th><th>Banner</th></tr>
            {% for port in open_ports %}
            <tr>
                <td>{{ port.port }}</td>
                <td>{{ port.service or '-' }}</td>
                <td>{{ port.version or '-' }}</td>
                <td>{% if port.banner %}{{ port.banner[:50] }}{% if port.banner|length > 50 %}...{% endif %}{% else %}-{% endif %}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No open ports detected.</p>
        {% endif %}
    </div>

    <div class="card">
        <h2>Vulnerabilities</h2>
        {% if vulnerabilities %}
        <table>
            <tr><th>Severity</th><th>Name</th><th>Port</th><th>Description</th></tr>
            {% for vuln in vulnerabilities %}
            <tr>
                <td class="severity-{{ vuln.severity }}">{{ vuln.severity|upper }}</td>
                <td>{{ vuln.name }}</td>
                <td>{{ vuln.port or '-' }}</td>
                <td>{{ vuln.description }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No vulnerabilities detected.</p>
        {% endif %}
    </div>

    <div class="card">
        <h2>Recommendations</h2>
        {% if recommendations %}
        {% for rec in recommendations %}
        <div class="recommendation">{{ rec }}</div>
        {% endfor %}
        {% else %}
        <p>No specific recommendations at this time.</p>
        {% endif %}
    </div>

    <div class="footer">
        Generated by Network Analytics Toolkit
    </div>
</body>
</html>
"""

MARKDOWN_TEMPLATE = """# Network Analysis Report

**Target:** {{ target }}
**Generated:** {{ timestamp }}
**Assessment Level:** {{ level }}

---

## Summary

| Metric | Value |
|--------|-------|
| Open Ports | {{ open_ports|length }} |
| Services | {{ services|length }} |
| Vulnerabilities | {{ vulnerabilities|length }} |
| Risk Level | **{{ risk_level|upper }}** |

---

## Open Ports

{% if open_ports %}
| Port | Service | Version | Banner |
|------|---------|---------|--------|
{% for port in open_ports %}
| {{ port.port }} | {{ port.service or '-' }} | {{ port.version or '-' }} | {{ port.banner[:30] if port.banner else '-' }}{{ '...' if port.banner and port.banner|length > 30 else '' }} |
{% endfor %}
{% else %}
No open ports detected.
{% endif %}

---

## Vulnerabilities

{% if vulnerabilities %}
{% for vuln in vulnerabilities %}
### {{ vuln.severity|upper }}: {{ vuln.name }}

- **Port:** {{ vuln.port or 'N/A' }}
- **Description:** {{ vuln.description }}
- **Remediation:** {{ vuln.remediation }}

{% endfor %}
{% else %}
No vulnerabilities detected.
{% endif %}

---

## Recommendations

{% if recommendations %}
{% for rec in recommendations %}
1. {{ rec }}
{% endfor %}
{% else %}
No specific recommendations at this time.
{% endif %}

---

*Generated by Network Analytics Toolkit*
"""


class ReportGenerator:
    """Generate network analysis reports."""

    def __init__(self, target: str):
        self.target = target
        self.data: dict = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "level": "basic",
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "recommendations": [],
            "risk_level": "low",
        }

    def set_assessment(self, assessment) -> None:
        """Set data from SecurityAssessment."""
        self.data.update(
            {
                "level": assessment.level.value,
                "open_ports": [
                    {"port": p, "service": None, "version": None, "banner": None}
                    for p in assessment.open_ports
                ],
                "services": assessment.services,
                "vulnerabilities": [v.to_dict() for v in assessment.vulnerabilities],
                "recommendations": assessment.recommendations,
                "risk_level": assessment.risk_analysis.overall_level.value,
            }
        )

        # Merge service info into ports
        service_map = {s.get("port"): s for s in assessment.services}
        for port_data in self.data["open_ports"]:
            port = port_data["port"]
            if port in service_map:
                port_data.update(service_map[port])

    def set_scan_results(self, scan_result) -> None:
        """Set data from port scan result."""
        self.data["open_ports"] = [
            {
                "port": p.port,
                "service": p.service,
                "version": None,
                "banner": p.banner,
            }
            for p in scan_result.get_open_ports()
        ]

    def generate_html(self, output_file: str | None = None) -> str:
        """Generate HTML report."""
        template = Template(HTML_TEMPLATE)
        html = template.render(**self.data)

        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html)

        return html

    def generate_markdown(self, output_file: str | None = None) -> str:
        """Generate Markdown report."""
        template = Template(MARKDOWN_TEMPLATE)
        md = template.render(**self.data)

        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(md)

        return md

    def generate_json(self, output_file: str | None = None) -> str:
        """Generate JSON report."""
        json_str = json.dumps(self.data, indent=2)

        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_str)

        return json_str


def generate_report(
    target: str,
    output_format: str = "html",
    output_file: str | None = None,
) -> str:
    """
    Generate a comprehensive network report.

    Args:
        target: Target IP or hostname
        output_format: Report format (html, md, json)
        output_file: Output file path (auto-generated if None)

    Returns:
        Path to generated report
    """
    from ..security import security_assessment

    # Run assessment
    assessment = security_assessment(target, level="basic")

    # Generate report
    generator = ReportGenerator(target)
    generator.set_assessment(assessment)

    # Determine output file
    if not output_file:
        results_dir = ensure_results_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = {"html": "html", "md": "md", "json": "json"}[output_format]
        output_file = str(results_dir / f"report_{target}_{timestamp}.{ext}")

    # Generate report
    if output_format == "html":
        generator.generate_html(output_file)
    elif output_format == "md":
        generator.generate_markdown(output_file)
    elif output_format == "json":
        generator.generate_json(output_file)

    return output_file
