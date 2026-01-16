#!/usr/bin/env python3
"""Benchmark scan throughput and latency."""

from __future__ import annotations

import argparse
import time

from netanalytics.discovery.port_scan import port_scan


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark port scanning performance.")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--ports", default="1-1024")
    parser.add_argument("--scan-type", choices=["connect", "syn"], default="connect")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--rate-limit", type=int, default=200)
    args = parser.parse_args()

    start = time.perf_counter()
    result = port_scan(
        args.target,
        ports=args.ports,
        scan_type=args.scan_type,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        grab_banner=False,
    )
    duration = time.perf_counter() - start

    total = len(result.ports)
    rate = total / duration if duration > 0 else 0

    print(f"Target: {args.target}")
    print(f"Ports: {args.ports} ({total})")
    print(f"Scan type: {args.scan_type}")
    print(f"Duration: {duration:.2f}s")
    print(f"Throughput: {rate:.2f} ports/sec")
    print(f"Open: {result.open_count}, Closed: {result.closed_count}, Filtered: {result.filtered_count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
