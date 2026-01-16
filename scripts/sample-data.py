#!/usr/bin/env python3
"""Generate sample JSON outputs for demos/tests."""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from netanalytics.core.utils import ensure_results_dir


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def _sample_scan(target: str) -> dict:
    ports = [22, 80, 443, 8080]
    open_ports = random.sample(ports, k=2)
    now = datetime.now()
    return {
        "target": target,
        "scan_type": "connect",
        "start_time": now.isoformat(),
        "end_time": (now + timedelta(seconds=1)).isoformat(),
        "duration_seconds": 1.0,
        "summary": {"open": len(open_ports), "closed": 0, "filtered": 0, "total": len(ports)},
        "ports": [
            {
                "port": p,
                "state": "open",
                "service": "http" if p in (80, 8080) else "ssh",
                "banner": "Example Banner",
                "response_time_ms": round(random.uniform(1, 20), 2),
            }
            for p in open_ports
        ],
    }


def _sample_security(target: str) -> dict:
    return {
        "target": target,
        "level": "basic",
        "start_time": datetime.now().isoformat(),
        "end_time": datetime.now().isoformat(),
        "duration_seconds": 0.5,
        "open_ports": [22, 80],
        "services": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}],
        "vulnerabilities": [
            {
                "name": "Unencrypted Service",
                "severity": "medium",
                "description": "HTTP transmits data in plaintext.",
                "port": 80,
                "service": "http",
                "remediation": "Use HTTPS (port 443) instead.",
            }
        ],
        "risk_analysis": {"overall_level": "medium", "overall_score": 5.0, "factors": []},
        "recommendations": ["Enable HTTPS and redirect HTTP."],
    }


def _sample_traffic() -> dict:
    return {
        "total_packets": 1200,
        "total_bytes": 857600,
        "duration_seconds": 60.0,
        "protocols": {"TCP": 900, "UDP": 250, "DNS": 50},
        "top_sources": [{"ip": "192.168.1.10", "count": 400}],
        "top_destinations": [{"ip": "192.168.1.1", "count": 450}],
        "top_ports": [{"port": 443, "count": 350}],
        "packets_per_second": 20.0,
        "bytes_per_second": 14293.33,
        "tcp_flags": {"SYN": 120, "ACK": 860},
        "conversations": [
            {"endpoints": ["192.168.1.10", "192.168.1.1"], "packets": 300, "bytes": 210000}
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate sample JSON outputs.")
    parser.add_argument("--target", default="192.168.1.1")
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    random.seed(42)

    results_dir = Path(args.output_dir) if args.output_dir else ensure_results_dir()
    _write_json(results_dir / "sample_scan.json", _sample_scan(args.target))
    _write_json(results_dir / "sample_security.json", _sample_security(args.target))
    _write_json(results_dir / "sample_traffic.json", _sample_traffic())

    print(f"Sample data written to {results_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
