"""Stock devkitARM startup (crt0) recognition and recovery.

Known stock devkitARM startup copies are validated atomically before populating
mutable RAM. Unknown startups still receive the base map, header and hardware
types; their RAM contents and main entry are not guessed.

Startup reference: https://github.com/devkitPro/devkitarm-crtls/blob/master/gba_crt0.s
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from idagba.errors import LoadError, require
from idagba.rom import BASE, arm_branch_target

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class StartupCopy:
    name: str
    source: int
    destination: int
    size: int


@dataclass(frozen=True, slots=True)
class AddressComment:
    address: int
    text: str


@dataclass(frozen=True, slots=True)
class StartupRecovery:
    base: int
    start: int
    clear_mem: int
    copies: tuple[StartupCopy, ...]
    constructors: int
    main: int
    stacks: tuple[str, ...]
    bss: tuple[str, ...]
    protected: tuple[tuple[int, int], ...]
    hints: tuple[AddressComment, ...]


@dataclass(frozen=True, slots=True)
class StartupRecoveryFailure:
    reason: str


_CRT_ARM = (
    0xE3A00301, 0xE5800208, 0xE3A00012, 0xE129F000, 0xE59FD0B8,
    0xE3A0001F, 0xE129F000, 0xE59FD0B0, 0xE28F0001, 0xE12FFF10,
)  # fmt: skip
# Big-endian halfwords, as written in the crt0 listing.
_CRT_THUMB: tuple[int, ...] = struct.unpack(
    '>84H',
    bytes.fromhex("""
482B 0140 D20B 4678 0140 D30D 2202 0612
4B28 1A9B 1C16 0091 F000 F83D 4730 2140
0309 01C8 F000 F82C 4823 4924 1A09 F000
F827 4823 4923 1A09 F000 F822 4922 4A23
4C23 F000 F827 4923 4A23 4C24 F000 F822
4A23 4924 1A53 D002 4A23 F000 F81C 4923
4A23 4C24 F000 F816 4923 4824 6008 4B24
F000 F80F 2000 2100 4B22 F000 F80A DF00
2203 1889 4391 D003 2200 C004 3904 D1FC
4770 4718 1AA3 2003 181B 4383 D003 C901
C201 3B04 D1FB 4770
"""),
)
_SOFT_RESET = _CRT_THUMB.index(0xDF00)
# devkitarm-crtls before 333d62c (2020-12-10) has no SoftReset SWI after the call to main:
# every helper sits one halfword closer to its callers and a nop aligns the literal pool.
_CRT_THUMB_NO_RESET = (
    *(halfword - 1 if halfword & 0xF800 == 0xF800 else halfword for halfword in _CRT_THUMB[:_SOFT_RESET]),
    *_CRT_THUMB[_SOFT_RESET + 1 :],
    0x46C0,
)
# Offset from the crt0 start of the instruction that loads each linker symbol (gba_crt0.s).
_SP_IRQ, _SP_USR = 0x10, 0x1C
TEXT_START = 0x28
_BSS = (0x50, 0x52)  # __bss_start__, __bss_end__
_SBSS = (0x5A, 0x5C)  # __sbss_start__, __sbss_end__
# IDB name, then __*_lma, __*_start, __*_end.
_COPIES = (
    ('GBA_DATA_LMA', 0x64, 0x66, 0x68),
    ('GBA_IWRAM_LMA', 0x6E, 0x70, 0x72),
    ('GBA_EWRAM_LMA', 0x86, 0x88, 0x8A),
)
_IWRAM0 = (0x78, 0x7A, 0x80)  # __load_stop_iwram0, __load_start_iwram0, __iwram_overlay_start
_INIT_ARRAY, _MAIN = 0x96, 0xA0


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _ram_span(start: int, size: int) -> bool:
    return any(lo <= start and start + size <= hi for lo, hi in ((0x02000000, 0x02040000), (0x03000000, 0x03008000)))


def code_pointer(
    pointer: int,
    image: tuple[int, int],
    copies: Sequence[StartupCopy],
    protected: Sequence[tuple[int, int]],
) -> bool:
    """Whether pointer (Thumb state in bit 0) leads to code past the image header or inside a RAM copy."""
    address = pointer & ~1
    width = 2 if pointer & 1 else 4
    if address % width:
        return False

    span = address, address + width
    if image[0] + 0xC0 <= address and address + width <= image[1]:
        return not any(_overlaps(span, extent) for extent in protected)

    return any(copy.destination <= address and address + width <= copy.destination + copy.size for copy in copies)


def _match_thumb(rom: bytes, offset: int, template: tuple[int, ...]) -> bool:
    for i, reference in enumerate(template):
        mask = 0xFF00 if reference & 0xF800 == 0x4800 else 0xFFFF
        if struct.unpack_from('<H', rom, offset + i * 2)[0] & mask != reference & mask:
            return False

    return True


def _match_crt(rom: bytes, offset: int) -> bool:
    if offset < 0xC0 or offset % 4 or offset + 0xD0 > len(rom):
        return False

    for i, reference in enumerate(_CRT_ARM):
        mask = 0xFFFFF000 if i * 4 in (_SP_IRQ, _SP_USR) else 0xFFFFFFFF
        if struct.unpack_from('<I', rom, offset + i * 4)[0] & mask != reference & mask:
            return False

    return any(_match_thumb(rom, offset + 0x28, template) for template in (_CRT_THUMB, _CRT_THUMB_NO_RESET))


_CRT_LITERALS = (
    _SP_IRQ,
    _SP_USR,
    *(0x28 + 2 * i for i, reference in enumerate(_CRT_THUMB) if reference & 0xF800 == 0x4800),
)


@dataclass(frozen=True, slots=True)
class CrtMatch:
    """Where the stock crt0 template sits in an image; every offset is a file offset."""

    rom: bytes = field(repr=False)
    offset: int
    branches: tuple[int, ...]

    def literal_offset(self, delta: int) -> int:
        """File offset of the literal loaded by the instruction at offset + delta."""
        at = self.offset + delta
        if delta in (_SP_IRQ, _SP_USR):
            return at + 8 + (struct.unpack_from('<I', self.rom, at)[0] & 0xFFF)

        return ((at + 4) & ~3) + 4 * (struct.unpack_from('<H', self.rom, at)[0] & 0xFF)


def find_crt(rom: bytes) -> CrtMatch | StartupRecoveryFailure:
    """Follow up to four ARM entry branches (file offsets) to the stock crt0 template."""
    offset = 0
    visited = set()
    branches = []
    for hop in range(5):
        if offset in visited or offset % 4 or not 0 <= offset <= len(rom) - 4:
            return StartupRecoveryFailure('entry branch chain loops, is unaligned, or leaves the input')

        visited.add(offset)
        if _match_crt(rom, offset):
            return CrtMatch(rom, offset, tuple(branches))

        if hop == 4:
            break

        target = arm_branch_target(struct.unpack_from('<I', rom, offset)[0], offset)
        if target is None or target < 0xC0:
            return StartupRecoveryFailure('entry chain does not reach the stock crt0 template')

        branches.append(offset)
        offset = target

    return StartupRecoveryFailure('no stock crt0 within four entry branches')


class _Recovery:
    """Validates one matched crt0 against an image base; any failed check raises LoadError."""

    def __init__(self, match: CrtMatch, base: int) -> None:
        self.rom, self.offset, self.base = match.rom, match.offset, base
        self.start = base + match.offset
        self.image = (base, base + len(match.rom))
        # Ranges no copy source or code pointer may touch; grows with the literals and the copy sources.
        self.protected = [
            *((base + branch, base + branch + 4) for branch in match.branches),
            (base, base + 0xC0),
            (self.start, self.start + 0xD0),
        ]
        self.values = self._literals(match)

    def build(self) -> StartupRecovery:
        values = self.values
        copies = self._copies()
        for name, delta in (('constructors', _INIT_ARRAY), ('main', _MAIN)):
            pointer = values[delta]
            require(
                code_pointer(pointer, self.image, copies, self.protected), f'invalid {name} code pointer {pointer:#x}'
            )

        # ClearMem and the helpers behind it follow the SoftReset SWI in the revisions that have one.
        swi = 0x28 + 2 * _SOFT_RESET
        has_reset = struct.unpack_from('<H', self.rom, self.offset + swi)[0] == 0xDF00
        stacks, bss, hints = self._hints()
        return StartupRecovery(
            base=self.base,
            start=self.start,
            clear_mem=self.start + swi + (2 if has_reset else 0),
            copies=tuple(copies),
            constructors=values[_INIT_ARRAY],
            main=values[_MAIN],
            stacks=tuple(stacks),
            bss=tuple(bss),
            protected=tuple(self.protected),
            hints=tuple(hints),
        )

    def _literals(self, match: CrtMatch) -> dict[int, int]:
        """Value of every literal the template loads, keyed by the offset of its instruction."""
        base, template = self.base, (self.start, self.start + 0xD0)
        literals = {delta: base + match.literal_offset(delta) for delta in _CRT_LITERALS}
        for address in literals.values():
            require(
                address % 4 == 0 and base <= address <= self.image[1] - 4,
                'startup literal pool leaves input or is unaligned',
            )
            require(not _overlaps((address, address + 4), template), 'startup literal overlaps instructions')
            self.protected.append((address, address + 4))

        values = {delta: struct.unpack_from('<I', self.rom, address - base)[0] for delta, address in literals.items()}
        require(values[TEXT_START] == base, 'startup is not linked for this image base')
        return values

    def _copies(self) -> list[StartupCopy]:
        """The sections crt0 copies into RAM, validated against the image, the startup and each other."""
        values = self.values
        copies = []
        for name, lma, begin, end in _COPIES:
            require(values[end] >= values[begin], name + ': backwards destination bounds')
            copies.append(StartupCopy(name, values[lma], values[begin], (values[end] - values[begin] + 3) & ~3))

        stop, load, overlay = (values[delta] for delta in _IWRAM0)
        require(stop >= load, 'overlay0: backwards source bounds')
        copies.append(StartupCopy('GBA_IWRAM0_LMA', load, overlay, (stop - load + 3) & ~3))
        # A section linked where it is loaded copies onto itself: nothing to populate.
        copies = [copy for copy in copies if copy.size and copy.source != copy.destination]
        sources, destinations = [], []
        for copy in copies:
            source, destination = self._spans(copy, sources, destinations)
            sources.append(source)
            destinations.append(destination)

        self.protected += sources
        return copies

    def _spans(
        self, copy: StartupCopy, sources: Sequence[tuple[int, int]], destinations: Sequence[tuple[int, int]]
    ) -> tuple[tuple[int, int], tuple[int, int]]:
        """Source and destination range of a copy that is clear of everything protected and the earlier copies."""
        src, dst, size = copy.source, copy.destination, copy.size
        require(src % 4 == dst % 4 == 0, copy.name + ': unaligned copy')
        require(self.base <= src and src + size <= self.image[1], copy.name + ': source leaves input')
        require(_ram_span(dst, size), copy.name + ': destination leaves canonical RAM')
        source, destination = (src, src + size), (dst, dst + size)
        require(not _overlaps(destination, self.image), copy.name + ': destination overlaps the loaded image')
        require(
            not any(_overlaps(source, span) for span in (*self.protected, *sources)),
            copy.name + ': source overlaps startup, literal, or another source',
        )
        require(
            not any(_overlaps(destination, span) for span in destinations),
            copy.name + ': overlapping destinations',
        )
        return source, destination

    def _hints(self) -> tuple[list[str], list[str], list[AddressComment]]:
        """Stack and BSS lines for the report, plus the comments that pin them to addresses."""
        values = self.values
        stacks, bss, hints = [], [], []
        for delta, mode in ((_SP_IRQ, 'IRQ'), (_SP_USR, 'system')):
            value = values[delta]
            if value % 4 == 0 and 0x03000000 <= value <= 0x03008000:
                text = f'Stock crt0 {mode} stack hint: SP={value:#010x}'
                stacks.append(text)
                hints.append(AddressComment(self.start + delta, text))

        for bounds, region, name in (
            (_BSS, (0x03000000, 0x03008000), 'BSS'),
            (_SBSS, (0x02000000, 0x02040000), 'SBSS'),
        ):
            lo, hi = values[bounds[0]], values[bounds[1]]
            if lo % 4 == hi % 4 == 0 and region[0] <= lo <= hi <= region[1]:
                text = f'{name} cleared at runtime: [{lo:#010x}, {hi:#010x}); bytes remain unknown in static IDB'
                bss.append(text)
                if lo < hi:
                    hints.append(AddressComment(lo, text))

        return stacks, bss, hints


def recover_startup(rom: bytes, base: int = BASE) -> StartupRecovery | StartupRecoveryFailure:
    # ponytail: validated stock crt0 layout only; extend with another validated pattern when needed.
    found = find_crt(rom)
    if isinstance(found, StartupRecoveryFailure):
        return found

    try:
        return _Recovery(found, base).build()
    except LoadError as exc:
        return StartupRecoveryFailure(str(exc))
