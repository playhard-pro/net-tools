#!/usr/bin/env python3
"""Generate the embedded common-vendor OUI table.

The public IEEE registration listings are downloaded and filtered to a curated
set of common device, infrastructure, virtualization and embedded vendors. Only
the assignment prefix and organization name are kept. This keeps the binary
small while still covering the vendors most users encounter.

Usage:
    python3 scripts/update_mac_oui.py
    python3 scripts/update_mac_oui.py --input-dir /tmp
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "crates" / "core" / "src" / "net" / "mac_oui.tsv"
SOURCES = {
    "oui.csv": "https://standards-oui.ieee.org/oui/oui.csv",
    "mam.csv": "https://standards-oui.ieee.org/oui28/mam.csv",
    "oui36.csv": "https://standards-oui.ieee.org/oui36/oui36.csv",
}

# Case-insensitive substrings matched against the IEEE organization name.
VENDOR_KEYWORDS = (
    "apple",
    "samsung",
    "intel",
    "amd",
    "nvidia",
    "qualcomm",
    "broadcom",
    "realtek",
    "mediatek",
    "marvell",
    "texas instruments",
    "stmicroelectronics",
    "nordic semiconductor",
    "u-blox",
    "sierra wireless",
    "quectel",
    "telit",
    "thales",
    "gemalto",
    "cisco",
    "juniper",
    "arista",
    "aruba",
    "extreme networks",
    "brocade",
    "fortinet",
    "palo alto",
    "check point",
    "f5 networks",
    "riverbed",
    "huawei",
    "h3c",
    "ruijie",
    "zte",
    "fiberhome",
    "xiaomi",
    "google",
    "amazon",
    "microsoft",
    "dell",
    "hewlett packard",
    "hp inc",
    "lenovo",
    "sony",
    "lg electronics",
    "nokia",
    "motorola",
    "vivo",
    "oppo",
    "honor",
    "tcl",
    "hisense",
    "sharp",
    "acer",
    "panasonic",
    "toshiba",
    "fujitsu",
    "canon",
    "brother",
    "seiko epson",
    "nintendo",
    "roku",
    "sonos",
    "philips",
    "siemens",
    "bosch",
    "schneider",
    "rockwell",
    "tp-link",
    "netgear",
    "d-link",
    "asustek",
    "ubiquiti",
    "mikrotik",
    "raspberry pi",
    "espressif",
    "vmware",
    "virtualbox",
    "qemu",
    "xen",
    "parallels",
    "proxmox",
    "garmin",
    "gopro",
    "fitbit",
    "nest",
    "ring",
    "wyze",
)


def load_source(name: str, directory: Path | None) -> str:
    if directory is not None:
        return (directory / name).read_text(encoding="utf-8-sig")
    url = SOURCES[name]
    print(f"downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read().decode("utf-8-sig")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir",
        type=Path,
        help="directory containing oui.csv, mam.csv and oui36.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT,
        help=f"output TSV path (default: {OUTPUT})",
    )
    args = parser.parse_args()

    entries: dict[str, str] = {}
    for name in SOURCES:
        text = load_source(name, args.input_dir)
        for row in csv.DictReader(io.StringIO(text)):
            assignment = (row.get("Assignment") or "").strip().upper()
            organization = " ".join((row.get("Organization Name") or "").split())
            if not assignment or not organization:
                continue
            lowered = organization.lower()
            if not any(keyword in lowered for keyword in VENDOR_KEYWORDS):
                continue
            # Keep the longest name if the same prefix appears more than once.
            entries.setdefault(assignment, organization)

    ordered = sorted(entries.items(), key=lambda item: (len(item[0]), item[0]))
    today = dt.date.today().isoformat()
    lines = [
        "# Common OUI / MA-M / MA-S prefixes",
        "# Source: IEEE Registration Authority public listings",
        f"# Retrieved: {today}",
        "prefix\tvendor",
    ]
    lines.extend(f"{prefix}\t{vendor}" for prefix, vendor in ordered)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(ordered)} prefixes to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
