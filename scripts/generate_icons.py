#!/usr/bin/env python3
"""Generate the Windows .ico from the master icon.

The project keeps a single master image at ``assets/icon.png``. Windows
installers and the executable resource need a real multi-size ``.ico``, which
is produced here. Linux and macOS packages use the master PNG directly.

Run from the repository root after replacing ``assets/icon.png``::

    python3 scripts/generate_icons.py

Only the Python standard library is required.
"""

from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

# Sizes embedded in the .ico. All are standard Windows shell sizes.
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)

ROOT = Path(__file__).resolve().parent.parent
MASTER = ROOT / "assets" / "icon.png"
OUTPUT = ROOT / "assets" / "icon.ico"


def decode_png(path: Path) -> tuple[int, int, bytes]:
    """Decode a non-interlaced 8-bit RGBA PNG into raw RGBA bytes."""
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path} is not a PNG file")

    pos = 8
    idat = bytearray()
    width = height = bit_depth = color_type = interlace = 0
    while pos < len(data):
        length = int.from_bytes(data[pos : pos + 4], "big")
        kind = data[pos + 4 : pos + 8]
        chunk = data[pos + 8 : pos + 8 + length]
        if kind == b"IHDR":
            (
                width,
                height,
                bit_depth,
                color_type,
                _compression,
                _filter,
                interlace,
            ) = struct.unpack(">IIBBBBB", chunk)
        elif kind == b"IDAT":
            idat += chunk
        elif kind == b"IEND":
            break
        pos += 12 + length

    if bit_depth != 8 or color_type != 6 or interlace != 0:
        raise ValueError(
            f"{path} must be an 8-bit, non-interlaced RGBA PNG "
            f"(got depth={bit_depth}, color_type={color_type}, interlace={interlace})"
        )

    raw = zlib.decompress(bytes(idat))
    stride = width * 4
    pixels = bytearray()
    previous = bytearray(stride)
    cursor = 0
    for _ in range(height):
        filter_type = raw[cursor]
        cursor += 1
        line = bytearray(raw[cursor : cursor + stride])
        cursor += stride
        unfilter_line(line, previous, filter_type)
        pixels += line
        previous = line

    return width, height, bytes(pixels)


def unfilter_line(line: bytearray, previous: bytearray, filter_type: int) -> None:
    """Reverse one PNG scanline filter in place."""
    stride = len(line)
    bpp = 4
    if filter_type == 0:
        return
    if filter_type == 1:  # Sub
        for i in range(bpp, stride):
            line[i] = (line[i] + line[i - bpp]) & 0xFF
    elif filter_type == 2:  # Up
        for i in range(stride):
            line[i] = (line[i] + previous[i]) & 0xFF
    elif filter_type == 3:  # Average
        for i in range(stride):
            left = line[i - bpp] if i >= bpp else 0
            line[i] = (line[i] + ((left + previous[i]) >> 1)) & 0xFF
    elif filter_type == 4:  # Paeth
        for i in range(stride):
            left = line[i - bpp] if i >= bpp else 0
            up = previous[i]
            up_left = previous[i - bpp] if i >= bpp else 0
            line[i] = (line[i] + paeth(left, up, up_left)) & 0xFF
    else:
        raise ValueError(f"unknown PNG filter type {filter_type}")


def paeth(a: int, b: int, c: int) -> int:
    """PNG Paeth predictor."""
    estimate = a + b - c
    pa = abs(estimate - a)
    pb = abs(estimate - b)
    pc = abs(estimate - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def resize(rgba: bytes, width: int, height: int, size: int) -> bytes:
    """Box-filter downscale to a square, averaging in premultiplied alpha.

    Averaging premultiplied values keeps transparent pixels from darkening the
    edges of the resized image.
    """
    out = bytearray(size * size * 4)
    for oy in range(size):
        y0 = oy * height // size
        y1 = max(y0 + 1, (oy + 1) * height // size)
        for ox in range(size):
            x0 = ox * width // size
            x1 = max(x0 + 1, (ox + 1) * width // size)
            red = green = blue = alpha = count = 0
            for y in range(y0, y1):
                row = y * width * 4
                for x in range(x0, x1):
                    i = row + x * 4
                    a = rgba[i + 3]
                    red += rgba[i] * a
                    green += rgba[i + 1] * a
                    blue += rgba[i + 2] * a
                    alpha += a
                    count += 1
            o = (oy * size + ox) * 4
            if alpha == 0:
                out[o : o + 4] = b"\x00\x00\x00\x00"
            else:
                out[o] = red // alpha
                out[o + 1] = green // alpha
                out[o + 2] = blue // alpha
                out[o + 3] = alpha // count
    return bytes(out)


def to_ico_image(rgba: bytes, size: int) -> bytes:
    """Encode one size as a 32-bit bottom-up BMP DIB with an empty AND mask."""
    xor = bytearray()
    for y in range(size - 1, -1, -1):
        row = y * size * 4
        for x in range(size):
            i = row + x * 4
            xor += bytes((rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]))

    # The 1-bit AND mask is unused for 32-bit images but must still be present.
    mask_row = ((size + 31) // 32) * 4
    mask = bytes(mask_row * size)

    header = struct.pack(
        "<IiiHHIIiiII",
        40,
        size,
        size * 2,
        1,
        32,
        0,
        len(xor) + len(mask),
        0,
        0,
        0,
        0,
    )
    return header + bytes(xor) + mask


def build_ico(entries: list[tuple[int, bytes]]) -> bytes:
    """Assemble ICO directory plus image data."""
    header = struct.pack("<HHH", 0, 1, len(entries))
    offset = 6 + 16 * len(entries)
    directory = bytearray()
    images = bytearray()
    for size, image in entries:
        dimension = 0 if size >= 256 else size
        directory += struct.pack(
            "<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(image), offset
        )
        images += image
        offset += len(image)
    return header + bytes(directory) + bytes(images)


def main() -> int:
    if not MASTER.exists():
        print(f"master icon not found: {MASTER}", file=sys.stderr)
        return 1

    width, height, rgba = decode_png(MASTER)
    entries = [(size, to_ico_image(resize(rgba, width, height, size), size)) for size in ICON_SIZES]
    OUTPUT.write_bytes(build_ico(entries))
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({', '.join(str(s) for s in ICON_SIZES)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
