# Network Report Command

Generate comprehensive network analysis report.

## Usage

```
/net-report <target> [options]
```

## Arguments

- `target` (required): IP address, hostname, or network to analyze

## Options

- `--format, -f`: Report format - `html`, `md`, or `json` (default: `html`)
- `--output, -o`: Output file path (auto-generated if omitted)
- `--level`: Assessment depth - `basic` or `full`
- `--include`: Sections to include (ports, services, vulns, topology, traffic)

## Examples

```bash
# Generate HTML report
/net-report 192.168.1.1

# Markdown report for documentation
/net-report 192.168.1.1 --format md --output report.md

# JSON for integration
/net-report 192.168.1.1 --format json

# Full assessment report
/net-report 192.168.1.1 --level full --format html --output full_report.html
```

## Report Sections

### Summary
- Target information
- Assessment timestamp
- Overall statistics
- Risk level badge

### Open Ports
- Port numbers
- Service names
- Versions detected
- Banner information

### Services
- Detailed service information
- Product and version
- Configuration notes

### Vulnerabilities
- Severity-sorted findings
- CVE references (if available)
- Affected ports/services
- Remediation steps

### Risk Analysis
- Overall risk score
- Risk factors breakdown
- Contributing issues

### Recommendations
- Prioritized action items
- Security improvements
- Best practices

## Output Formats

### HTML
- Styled, professional report
- Color-coded severity
- Interactive elements
- Print-friendly

### Markdown
- Documentation-ready
- Git-friendly
- Easy to edit
- Converts to other formats

### JSON
- Machine-readable
- API integration
- Automated processing
- Full data export

## Execution

When you invoke this command, I will:

1. Run security assessment on the target
2. Collect all findings and metrics
3. Generate report in requested format
4. Save to specified or auto-generated path
5. Return the report location

## File Naming

Auto-generated filenames follow pattern:
```
results/report_{target}_{timestamp}.{ext}
```

Example: `results/report_192.168.1.1_20240115_143022.html`

## Requirements

- `jinja2` for HTML/Markdown templating
- Assessment requires appropriate permissions
- Results directory is auto-created
