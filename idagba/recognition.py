"""Cartridge and multiboot recognition for IDA's accept_file.

Cartridges load at 0x08000000 (up to 32 MiB, no padding) with static wait-state
views. Multiboot images (up to 256 KiB) load at 0x02000000 and enter at 0x020000C0;
they are recognized from a stock devkitARM __text_start, a .mb name, or mGBA's
literal-pool vote. A header without the 0x96 fixed byte is accepted only when its
logo is all zero (an unfixed build), as in mGBA.
"""

from __future__ import annotations

import struct
from typing import Protocol

from idagba.crt0 import Crt0, find_crt0
from idagba.rom import BASE, HEADER_SIZE, MAX_SIZE, MB_BASE, MB_MAX, entry_target, logo_matches

FORMAT = 'Nintendo Game Boy Advance ROM (ARM7TDMI)'
RELAXED_FORMAT = 'Nintendo Game Boy Advance ROM (homebrew or damaged header)'
MB_FORMAT = 'Nintendo Game Boy Advance multiboot image (EWRAM)'
FORMAT_MARKER = 'Game Boy Advance'


class LoaderInput(Protocol):
    """The part of IDA's loader_input_t that recognition reads."""

    def read(self, size: int = -1, /) -> bytes: ...
    def seek(self, offset: int, whence: int = 0, /) -> int: ...
    def tell(self) -> int: ...
    def size(self) -> int: ...


def accept_file(li: LoaderInput, filename: str) -> dict[str, str | int] | int:
    position = li.tell()
    try:
        li.seek(0)
        size = li.size()
        fmt = recognize(li.read(min(size, MB_MAX)), size, filename)
        # 1 accepts the file; 0x8000 is IDA's ACCEPT_FIRST, which lists the format first.
        return (
            {'format': fmt, 'processor': 'ARM:ARM7TDMI', 'options': 1 if fmt == RELAXED_FORMAT else 0x8001}
            if fmt
            else 0
        )
    finally:
        li.seek(position)


def recognize(data: bytes | bytearray, size: int, filename: str) -> str | None:
    """Classify a header; multiboot detection needs the whole image in data."""
    if not HEADER_SIZE <= size <= MAX_SIZE or len(data) < HEADER_SIZE:
        return None

    # mGBA's rule: a missing fixed byte is tolerated only on an unfixed (all-zero logo) header.
    if data[0xB2] != 0x96 and any(data[4:0xA0]):
        return None

    name = str(filename).lower()
    logo = logo_matches(data)
    if 0xC4 <= size <= MB_MAX and len(data) >= size and (name.endswith('.mb') or looks_multiboot(bytes(data[:size]))):
        named = name.endswith(('.mb', '.gba', '.agb'))
        valid = logo or (named and entry_target(data, size, MB_BASE, HEADER_SIZE) is not None)
        return MB_FORMAT if valid else None

    if logo:
        return FORMAT

    if name.endswith(('.gba', '.agb')) and entry_target(data, size) is not None:
        return RELAXED_FORMAT

    return None


def looks_multiboot(image: bytes) -> bool:
    crt0 = find_crt0(image)
    if isinstance(crt0, Crt0):
        pool = crt0.pool()
        return pool is not None and pool.text_start == MB_BASE

    return _literal_vote(image)


def _literal_vote(image: bytes) -> bool:
    # mGBA's GBAIsMB literal vote, without its toolchain-specific branch rules.
    # A tiny cartridge with EWRAM-heavy startup code can be misdetected.
    ewram = cartridge = 0
    for ea in range(HEADER_SIZE, min(len(image) - 3, HEADER_SIZE + 128 * 4), 4):
        word = struct.unpack_from('<I', image, ea)[0]
        values = [word]
        if word & 0x0F7F0000 == 0x051F0000:  # LDR Rd, [PC, #+/-imm12]
            literal = ea + 8 + (word & 0xFFF if word & 0x00800000 else -(word & 0xFFF))
            if 0 <= literal <= len(image) - 4:
                values.append(struct.unpack_from('<I', image, literal)[0])

        for value in values:
            ewram += value & ~0x1FFFF == MB_BASE
            cartridge += value & ~0x1FFFF == BASE

    return cartridge < 2 and ewram > 0
