"""Decides whether a file is a GBA cartridge, a multiboot image, or neither."""

from __future__ import annotations

import struct
from typing import Protocol

from idagba.crt0 import Crt0, find_crt0
from idagba.hardware import BASE_EWRAM, BASE_ROM0, SIZE_EWRAM, SIZE_ROM0
from idagba.rom import HEADER_SIZE, entry_target, logo_matches

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

        # multiboot checks need the whole image (max 256 KiB)
        fmt = recognize(li.read(min(size, SIZE_EWRAM)), size, filename)

        # 1 accepts the file and 0x8000 (ACCEPT_FIRST) lists the format first
        return (
            {'format': fmt, 'processor': 'ARM:ARM7TDMI', 'options': 1 if fmt == RELAXED_FORMAT else 0x8001}
            if fmt
            else 0
        )
    finally:
        # other loaders read this stream too
        li.seek(position)


def recognize(data: bytes | bytearray, size: int, filename: str) -> str | None:
    """Return the format name of an image, or None. A multiboot check needs the whole image in data."""
    if not HEADER_SIZE <= size <= SIZE_ROM0 or len(data) < HEADER_SIZE:
        return None

    # like mGBA, allow a missing 0x96 byte only when the logo is all zero (an unfixed header)
    # https://github.com/mgba-emu/mgba/blob/cfef853/src/gba/gba.c#L728-L745
    if data[0xB2] != 0x96 and any(data[4:0xA0]):
        return None

    name = str(filename).lower()
    logo = logo_matches(data)

    # check multiboot first since it has a cartridge header too
    fits_ewram = 0xC4 <= size <= SIZE_EWRAM and len(data) >= size
    if fits_ewram and (name.endswith('.mb') or looks_multiboot(bytes(data[:size]))):
        # without the logo, a known extension and a valid entry branch are enough
        named = name.endswith(('.mb', '.gba', '.agb'))
        valid = logo or (named and entry_target(data, size, BASE_EWRAM, HEADER_SIZE) is not None)
        return MB_FORMAT if valid else None

    if logo:
        return FORMAT

    # no logo, but a valid entry branch
    if name.endswith(('.gba', '.agb')) and entry_target(data, size) is not None:
        return RELAXED_FORMAT

    return None


def looks_multiboot(image: bytes) -> bool:
    # the startup code says where the image was linked to run
    crt0 = find_crt0(image)
    if isinstance(crt0, Crt0):
        pool = crt0.pool()
        return pool is not None and pool.text_start == BASE_EWRAM

    # otherwise guess from the addresses the code uses
    return _literal_vote(image)


def _literal_vote(image: bytes) -> bool:
    """Whether the code after the header uses EWRAM addresses and not cartridge ones."""
    # same counting rule as mGBA's GBAIsMB, without its entry branch checks
    # https://github.com/mgba-emu/mgba/blob/cfef853/src/gba/gba.c#L791-L844
    # a tiny cartridge that uses EWRAM addresses early can be taken for multiboot
    ewram = cartridge = 0
    scanned_words = 128
    for offset in range(HEADER_SIZE, min(len(image) - 3, HEADER_SIZE + scanned_words * 4), 4):
        word = struct.unpack_from('<I', image, offset)[0]
        candidates = [word]

        # the literal an `ldr rX, [pc, #imm]` loads is a candidate too
        if word & 0x0F7F0000 == 0x051F0000:
            imm = word & 0xFFF
            literal = offset + 8 + (imm if word & 0x00800000 else -imm)
            if 0 <= literal <= len(image) - 4:
                candidates.append(struct.unpack_from('<I', image, literal)[0])

        # count the addresses in the first 128 KiB of each region
        for value in candidates:
            ewram += value & ~0x1FFFF == BASE_EWRAM
            cartridge += value & ~0x1FFFF == BASE_ROM0

    return ewram > 0 and cartridge < 2
