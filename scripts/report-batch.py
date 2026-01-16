#!/usr/bin/env python3
"""Batch report generation for multiple targets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from netanalytics.output.reports import generate_report
from netanalytics.core.utils import ensure_results_dir


def _parse_targets(args: argparse.Namespace) -> list[str]:
    targets = []
    if args.targets:
        targets.extend([t.strip() for t in args.targets.split(",") if t.strip()])
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate reports for multiple targets.")
    parser.add_argument("--targets", help="Comma-separated targets")
    parser.add_argument("--file", help="File with one target per line")
    parser.add_argument("--format", choices=["html", "md", "json"], default="html")
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    targets = _parse_targets(args)
    if not targets:
        print("No targets provided.")
        return 2

    output_dir = Path(args.output_dir) if args.output_dir else ensure_results_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    for target in targets:
        output_file = output_dir / f"report_{target}.{args.format}"
        path = generate_report(target, output_format=args.format, output_file=str(output_file))
        summary.append({"target": target, "report": path})
        print(f"Generated {path}")

    summary_path = output_dir / "report_batch_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"Summary written to {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
