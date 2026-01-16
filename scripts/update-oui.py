#!/usr/bin/env python3
"""Download and cache OUI vendor data."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from urllib.request import urlopen

from netanalytics.core.utils import ensure_results_dir


DEFAULT_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def _download_csv(url: str) -> list[dict[str, str]]:
    with urlopen(url, timeout=30) as resp:
        content = resp.read().decode("utf-8", errors="ignore")
    reader = csv.DictReader(content.splitlines())
    return list(reader)


def _normalize(rows: list[dict[str, str]]) -> dict[str, str]:
    mapping = {}
    for row in rows:
        assignment = row.get("Assignment", "").strip().lower()
        org = row.get("Organization Name", "").strip()
        if assignment and org:
            mapping[assignment.replace("-", ":")] = org
    return mapping


def main() -> int:
    parser = argparse.ArgumentParser(description="Download OUI vendor list.")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    output_dir = ensure_results_dir()
    output_path = Path(args.output) if args.output else output_dir / "oui_vendors.json"

    rows = _download_csv(args.url)
    mapping = _normalize(rows)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(mapping, indent=2))

    print(f"Saved {len(mapping)} OUI entries to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
