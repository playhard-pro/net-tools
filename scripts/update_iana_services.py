#!/usr/bin/env python3
"""Generate the embedded IANA port/protocol reference table.

The script downloads the official IANA service-name and port-number registry,
keeps only the four fields used by the application, and writes a compact TSV.
It uses only the Python standard library so maintainers do not need extra
packages.

Usage:
    python3 scripts/update_iana_services.py
    python3 scripts/update_iana_services.py --input /tmp/service-names-port-numbers.csv
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import sys
import urllib.request
from pathlib import Path

SOURCE_URL = (
    "https://www.iana.org/assignments/service-names-port-numbers/"
    "service-names-port-numbers.csv"
)
ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "crates" / "core" / "src" / "utils" / "iana_services.tsv"
FIELDS = ("Service Name", "Port Number", "Transport Protocol", "Description")


def normalize(value: str | None) -> str:
    """Collapse whitespace so one registry entry always fits on one TSV line."""
    return " ".join((value or "").split())


def port_bounds(value: str) -> tuple[int, int] | None:
    """Return the inclusive port range, or None when the field is unusable."""
    value = value.strip()
    if not value:
        return None
    if "-" in value:
        start_text, end_text = value.split("-", 1)
        if start_text.strip().isdigit() and end_text.strip().isdigit():
            start = int(start_text)
            end = int(end_text)
            if 0 <= start <= end <= 65535:
                return start, end
        return None
    if value.isdigit():
        port = int(value)
        if 0 <= port <= 65535:
            return port, port
    return None


def load_rows(path: Path | None) -> list[dict[str, str]]:
    if path is None:
        print(f"downloading {SOURCE_URL}", file=sys.stderr)
        with urllib.request.urlopen(SOURCE_URL, timeout=60) as response:
            data = response.read()
    else:
        data = path.read_bytes()
    text = data.decode("utf-8-sig")
    return list(csv.DictReader(io.StringIO(text)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        help="use a local CSV instead of downloading the registry",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT,
        help=f"output TSV path (default: {OUTPUT})",
    )
    args = parser.parse_args()

    rows = load_rows(args.input)
    selected: list[tuple[int, int, str, str, str, str]] = []
    skipped = 0
    for row in rows:
        port_text = normalize(row.get("Port Number"))
        bounds = port_bounds(port_text)
        if bounds is None:
            # Range rows without a parseable port are not useful as a lookup
            # key. Everything else, including reserved ranges, is kept.
            if port_text:
                skipped += 1
            continue
        selected.append(
            (
                bounds[0],
                bounds[1],
                port_text,
                normalize(row.get("Service Name")),
                normalize(row.get("Transport Protocol")),
                normalize(row.get("Description")),
            )
        )

    selected.sort(key=lambda row: (row[0], row[1], row[3], row[4]))
    today = dt.date.today().isoformat()
    lines = [
        "# IANA Service Name and Transport Protocol Port Number Registry",
        f"# Source: {SOURCE_URL}",
        f"# Retrieved: {today}",
        "# License: CC0 1.0 (IANA/IETF Protocol Registries joint statement)",
        "service\tport\ttransport\tdescription",
    ]
    lines.extend(
        "\t".join((service, port, transport, description))
        for _, _, port, service, transport, description in selected
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"wrote {len(selected)} rows to {args.output}"
        + (f" ({skipped} unparseable range rows skipped)" if skipped else ""),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
