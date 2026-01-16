# Security Check Command

Run security assessment on a target.

## Usage

```
/security-check <target> [options]
```

## Arguments

- `target` (required): IP address or hostname to assess

## Options

- `--level`: Assessment level - `basic` or `full` (default: `basic`)
- `--ports, -p`: Specific ports to check
- `--output, -o`: Save results to file (JSON)
- `--verbose`: Show detailed findings

## Examples

```bash
# Basic security check
/security-check 192.168.1.1

# Full assessment
/security-check 192.168.1.1 --level full

# Check specific ports
/security-check 192.168.1.1 --ports 22,80,443,3306

# Save detailed report
/security-check 192.168.1.1 --level full --output security_report.json
```

## Assessment Levels

### Basic
- Scans common ports (FTP, SSH, HTTP, HTTPS, databases)
- Checks for default credentials exposure
- Identifies unencrypted services
- Basic vulnerability detection

### Full
- Scans ports 1-1024
- Service version detection
- Comprehensive vulnerability checks
- Detailed risk analysis
- Extended recommendations

## What This Command Does

1. **Port Scanning**: Identifies open ports and services
2. **Service Detection**: Determines running services and versions
3. **Vulnerability Checks**:
   - Default credentials exposure
   - Unencrypted service usage
   - Outdated software versions
   - Exposed databases
4. **Risk Analysis**: Calculates overall risk score
5. **Recommendations**: Provides actionable security advice

## Risk Levels

- **CRITICAL**: Immediate action required (score 8-10)
- **HIGH**: Urgent attention needed (score 6-8)
- **MEDIUM**: Should be addressed soon (score 4-6)
- **LOW**: Minor issues (score 2-4)
- **INFO**: Informational only (score 0-2)

## Execution

When you invoke this command, I will:

1. Run port scan on the target
2. Detect services on open ports
3. Execute vulnerability checks
4. Analyze overall risk
5. Generate recommendations
6. Display formatted results
7. Save report if requested

## Output Includes

- Summary of findings
- Open ports table
- Vulnerability details with severity
- Risk factor breakdown
- Prioritized recommendations

## Security Note

This tool is for authorized security testing only. Always obtain proper authorization before running security assessments.
