"""Cartridge header facts and the GBA image address constants."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class HeaderFacts:
    """Raw parsed header facts; byte fields are escaped only when displayed."""

    size: int
    title: bytes
    game_code: bytes
    maker: bytes
    unit: int
    device: int
    version: int
    entry_word: int
    logo_valid: bool
    fixed: int
    reserved1: bytes
    reserved2: bytes
    checksum_stored: int
    checksum_computed: int
    save_markers: tuple[str, ...]
    warnings: tuple[str, ...]


BASE = 0x08000000
MAX_SIZE = 0x02000000
MB_BASE = 0x02000000
MB_MAX = 0x40000
HEADER_SIZE = 0xC0
EWRAM = (0x02000000, 0x02040000)
IWRAM = (0x03000000, 0x03008000)


def arm_branch_target(word: int, ea: int) -> int | None:
    if word & 0xFF000000 != 0xEA000000:
        return None

    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000

    return ea + 8 + (imm << 2)


def logo_matches(header: bytes | bytearray) -> bool:
    if len(header) < 0xC0:
        return False

    expected = bytearray.fromhex("""
        24 ff ae 51 69 9a a2 21 3d 84 82 0a 84 e4 09 ad
        11 24 8b 98 c0 81 7f 21 a3 52 be 19 93 09 ce 20
        10 46 4a 4a f8 27 31 ec 58 c7 e8 33 82 e3 ce bf
        85 f4 df 94 ce 4b 09 c1 94 56 8a c0 13 72 a7 fc
        9f 84 4d 73 a3 ca 9a 61 58 97 a3 27 fc 03 98 76
        23 1d c7 61 03 04 ae 56 bf 38 84 00 40 a7 0e fd
        ff 52 fe 03 6f 95 30 f1 97 fb c0 85 60 d6 80 25
        a9 63 be 03 01 4e 38 e2 f9 a2 34 ff bb 3e 03 44
        78 00 90 cb 88 11 3a 94 65 c0 7c 63 87 f0 3c af
        d6 25 e4 8b 38 0a ac 72 21 d4 f8 07
    """)
    logo = bytearray(header[4:0xA0])

    for offset, mask in ((0x9C, 0x84), (0x9E, 0x03)):
        logo[offset - 4] &= ~mask & 0xFF
        expected[offset - 4] &= ~mask & 0xFF

    return logo == expected


def entry_target(image: bytes | bytearray, size: int, base: int = BASE, at: int = 0) -> int | None:
    target = arm_branch_target(struct.unpack_from('<I', image, at)[0], base + at)
    return target if target is not None and base + 0xC0 <= target <= base + size - 4 else None


@dataclass(frozen=True, slots=True)
class Image:
    """A complete image and its load address; the base alone tells a cartridge from a multiboot image."""

    rom: bytes = field(repr=False)
    base: int = BASE

    @property
    def multiboot(self) -> bool:
        return self.base == MB_BASE

    @property
    def end(self) -> int:
        return self.base + len(self.rom)

    @property
    def entry(self) -> int:
        """The header's branch for a cartridge; the BIOS enters a multiboot image right after its header."""
        return self.base + (0xC0 if self.multiboot else 0)

    @property
    def entry_target(self) -> int | None:
        return entry_target(self.rom, len(self.rom), self.base, self.entry - self.base)

    @property
    def views(self) -> tuple[tuple[int, str], ...]:
        """Address and name suffix of every static view of the image."""
        if self.multiboot:
            return ((self.base, ''),)

        # GBATEK: the cartridge answers at three addresses that differ only in bus wait state.
        return ((BASE, ''), (0x0A000000, '_WS1'), (0x0C000000, '_WS2'))


def header_facts(image: Image) -> HeaderFacts:
    rom, base = image.rom, image.base
    entry = image.entry - base
    checksum = (-sum(rom[0xA0:0xBD]) - 0x19) & 0xFF
    warnings = []
    if rom[0xB2] != 0x96:
        warnings.append(f'fixed header byte is {rom[0xB2]:#04x}, not 0x96 (unfixed header)')

    if checksum != rom[0xBD]:
        warnings.append(f'header checksum mismatch: stored {rom[0xBD]:#04x}, computed {checksum:#04x}')

    if not logo_matches(rom):
        warnings.append('Nintendo logo is damaged or nonstandard')

    if rom[0xB3]:
        warnings.append(f'unexpected unit code {rom[0xB3]:#x}')

    if any(rom[0xB5:0xBC]) or any(rom[0xBE:0xC0]):
        warnings.append('nonzero reserved header bytes')

    if image.entry_target is None:
        warnings.append(f'unusual or out-of-payload ARM entry instruction; entry remains at {base + entry:#010x}')

    return HeaderFacts(
        size=len(rom),
        title=bytes(rom[0xA0:0xAC]),
        game_code=bytes(rom[0xAC:0xB0]),
        maker=bytes(rom[0xB0:0xB2]),
        unit=rom[0xB3],
        device=rom[0xB4],
        version=rom[0xBC],
        entry_word=struct.unpack_from('<I', rom, entry)[0],
        logo_valid=logo_matches(rom),
        fixed=rom[0xB2],
        reserved1=bytes(rom[0xB5:0xBC]),
        reserved2=bytes(rom[0xBE:0xC0]),
        checksum_stored=rom[0xBD],
        checksum_computed=checksum,
        save_markers=tuple(
            sorted({m.decode('ascii') for m in re.findall(rb'(?:EEPROM|SRAM(?:_F)?|FLASH(?:512|1M)?)_V[0-9]{3}', rom)})
        ),
        warnings=tuple(warnings),
    )
