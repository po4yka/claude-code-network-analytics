#!/usr/bin/env python3
"""Quick pcap summary for CLI use."""

from __future__ import annotations

import argparse
import json

from netanalytics.traffic.analyzer import analyze_pcap


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize a pcap file.")
    parser.add_argument("pcap", help="Path to pcap file")
    parser.add_argument("--protocol", choices=["all", "tcp", "udp", "http", "dns"], default="all")
    parser.add_argument("--output", help="Write JSON output to file")
    args = parser.parse_args()

    stats = analyze_pcap(args.pcap, protocol_filter=args.protocol)
    print(stats)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(stats.to_dict(), f, indent=2)
        print(f"Wrote {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
