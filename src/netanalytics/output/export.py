"""Data export functionality."""

import csv
import json
from pathlib import Path
from datetime import datetime
from typing import Any


def export_json(
    data: dict | list,
    output_file: str,
    pretty: bool = True,
) -> str:
    """
    Export data to JSON file.

    Args:
        data: Data to export
        output_file: Output file path
        pretty: Pretty print JSON

    Returns:
        Path to output file
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        if pretty:
            json.dump(data, f, indent=2, default=_json_serializer)
        else:
            json.dump(data, f, default=_json_serializer)

    return str(output_path)


def export_csv(
    data: list[dict],
    output_file: str,
    fieldnames: list[str] | None = None,
) -> str:
    """
    Export list of dicts to CSV file.

    Args:
        data: List of dictionaries to export
        output_file: Output file path
        fieldnames: CSV column names (auto-detected if None)

    Returns:
        Path to output file
    """
    if not data:
        return output_file

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Auto-detect fieldnames from first item
    if fieldnames is None:
        fieldnames = list(data[0].keys())

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)

    return str(output_path)


def _json_serializer(obj: Any) -> Any:
    """Custom JSON serializer for special types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
