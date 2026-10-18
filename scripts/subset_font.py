#!/usr/bin/env python3
"""Regenerate the bundled CJK font subset.

The full WenQuanYi Micro Hei collection is several megabytes, while the UI only
needs a small character set plus enough common Chinese characters for names,
banners and other data returned by network services. This script keeps:

- every character used by the locale files (the actual UI text),
- printable ASCII and Latin-1,
- all GB2312 characters, which cover common simplified Chinese,
- a small set of punctuation and direction symbols used by the UI.

The generated file is a TrueType font, not a TTC, and uses the regular face.

Requires fonttools:

    python3 -m pip install fonttools
    python3 scripts/subset_font.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "fonts" / "wqy-microhei.ttc"
OUTPUT = ROOT / "assets" / "fonts" / "wqy-microhei-subset.ttf"
LOCALES = ROOT / "locales"

# Punctuation and symbols that appear in the UI but are not guaranteed to be
# part of the GB2312 repertoire.
EXTRA_SYMBOLS = "·—…“”‘’（）【】《》、，。！？：；→←↑↓×÷≈≤≥±°"


def locale_chars() -> set[str]:
    chars: set[str] = set()
    for path in sorted(LOCALES.glob("*.yml")):
        chars.update(path.read_text(encoding="utf-8"))
    return {char for char in chars if char.isprintable()}


def gb2312_chars() -> set[str]:
    chars: set[str] = set()
    for high in range(0xA1, 0xF8):
        for low in range(0xA1, 0xFF):
            try:
                chars.add(bytes([high, low]).decode("gb2312"))
            except UnicodeDecodeError:
                pass
    return chars


def required_chars() -> set[str]:
    chars = locale_chars() | gb2312_chars()
    chars.update(chr(code) for code in range(0x20, 0x100))
    chars.update(EXTRA_SYMBOLS)
    return {char for char in chars if char.isprintable()}


def verify(path: Path, required: set[str]) -> None:
    from fontTools.ttLib import TTFont

    cmap = TTFont(path).getBestCmap()
    missing = sorted(char for char in required if ord(char) not in cmap)
    if missing:
        sample = "".join(missing[:40])
        raise SystemExit(f"subset is missing UI characters: {sample}")


def main() -> None:
    if not SOURCE.exists():
        raise SystemExit(f"source font not found: {SOURCE}")
    if not OUTPUT.parent.exists():
        raise SystemExit(f"output directory not found: {OUTPUT.parent}")

    ui_chars = locale_chars()
    chars = required_chars()
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", suffix=".txt", delete=False
    ) as text_file:
        text_file.write("".join(sorted(chars)))
        text_path = Path(text_file.name)

    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "fontTools.subset",
                str(SOURCE),
                "--font-number=0",
                f"--text-file={text_path}",
                f"--output-file={OUTPUT}",
                "--layout-features=*",
                "--name-IDs=*",
                "--name-legacy",
                "--name-languages=*",
            ],
            check=True,
        )
    finally:
        text_path.unlink(missing_ok=True)

    verify(OUTPUT, ui_chars)
    print(f"wrote {OUTPUT} ({len(chars)} characters)")


if __name__ == "__main__":
    main()
