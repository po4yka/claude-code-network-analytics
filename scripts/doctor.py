#!/usr/bin/env python3
"""Environment checks for Network Analytics Toolkit."""

from __future__ import annotations

import argparse
import platform
import shutil
import sys
from dataclasses import dataclass


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def _check_python_version() -> CheckResult:
    major, minor = sys.version_info[:2]
    ok = (major, minor) >= (3, 11)
    detail = f"{platform.python_version()} (requires >= 3.11)"
    return CheckResult("python_version", ok, detail)


def _check_imports() -> list[CheckResult]:
    results = []
    for module in [
        "scapy",
        "psutil",
        "networkx",
        "click",
        "rich",
        "jinja2",
        "matplotlib",
    ]:
        try:
            __import__(module)
            results.append(CheckResult(f"import:{module}", True, "ok"))
        except Exception as exc:  # pragma: no cover - diagnostic
            results.append(CheckResult(f"import:{module}", False, str(exc)))
    return results


def _check_commands() -> list[CheckResult]:
    results = []
    for cmd in ["nmap", "tshark", "tcpdump"]:
        path = shutil.which(cmd)
        results.append(CheckResult(f"cmd:{cmd}", path is not None, path or "not found"))
    return results


def _check_root() -> CheckResult:
    is_root = False
    if hasattr(os := __import__("os"), "geteuid"):
        is_root = os.geteuid() == 0
    detail = "root" if is_root else "not root (required for ARP/ICMP/SYN/capture)"
    return CheckResult("root", is_root, detail)


def _print_results(results: list[CheckResult]) -> int:
    failures = [r for r in results if not r.ok]
    for r in results:
        status = "OK" if r.ok else "FAIL"
        print(f"{status:4} {r.name:20} {r.detail}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Environment checks for netanalytics.")
    parser.add_argument("--no-root", action="store_true", help="Skip root check")
    args = parser.parse_args()

    results = [_check_python_version()]
    results.extend(_check_imports())
    results.extend(_check_commands())
    if not args.no_root:
        results.append(_check_root())

    return _print_results(results)


if __name__ == "__main__":
    raise SystemExit(main())
