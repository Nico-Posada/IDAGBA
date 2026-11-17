"""Stock devkitARM startup (crt0) recognition and recovery.

Known stock devkitARM startup copies are validated atomically before populating
mutable RAM. Unknown startups still receive the base map, header and hardware
types; their RAM contents and main entry are not guessed.

Startup reference: https://github.com/devkitPro/devkitarm-crtls/blob/master/gba_crt0.s
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
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


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _ram_span(start: int, size: int) -> bool:
    return any(lo <= start and start + size <= hi for lo, hi in ((0x02000000, 0x02040000), (0x03000000, 0x03008000)))


def code_pointer(
    pointer: int,
    rom: bytes,
    copies: Sequence[StartupCopy],
    protected: Sequence[tuple[int, int]],
    base: int = BASE,
) -> bool:
    address = pointer & ~1
    width = 2 if pointer & 1 else 4
    if address % width:
        return False

    span = address, address + width
    if base + 0xC0 <= address and address + width <= base + len(rom):
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
        mask = 0xFFFFF000 if i * 4 in (0x10, 0x1C) else 0xFFFFFFFF
        if struct.unpack_from('<I', rom, offset + i * 4)[0] & mask != reference & mask:
            return False

    return any(_match_thumb(rom, offset + 0x28, template) for template in (_CRT_THUMB, _CRT_THUMB_NO_RESET))


_CRT_LITERALS = (
    0x10,
    0x1C,
    *(0x28 + 2 * i for i, reference in enumerate(_CRT_THUMB) if reference & 0xF800 == 0x4800),
)


def crt_literal(rom: bytes, offset: int, delta: int) -> int:
    """File offset of the literal loaded by the stock crt0 instruction at offset + delta."""
    if delta in (0x10, 0x1C):
        return offset + delta + 8 + (struct.unpack_from('<I', rom, offset + delta)[0] & 0xFFF)

    return ((offset + delta + 4) & ~3) + 4 * (struct.unpack_from('<H', rom, offset + delta)[0] & 0xFF)


def find_crt(rom: bytes) -> tuple[int, tuple[int, ...]] | StartupRecoveryFailure:
    """Follow up to four ARM entry branches (file offsets) to the stock crt0 template."""
    offset = 0
    visited = set()
    branches = []
    for hop in range(5):
        if offset in visited or offset % 4 or not 0 <= offset <= len(rom) - 4:
            return StartupRecoveryFailure('entry branch chain loops, is unaligned, or leaves the input')

        visited.add(offset)
        if _match_crt(rom, offset):
            return offset, tuple(branches)

        if hop == 4:
            break

        target = arm_branch_target(struct.unpack_from('<I', rom, offset)[0], offset)
        if target is None or target < 0xC0:
            return StartupRecoveryFailure('entry chain does not reach the stock crt0 template')

        branches.append(offset)
        offset = target

    return StartupRecoveryFailure('no stock crt0 within four entry branches')


def recover_startup(rom: bytes, base: int = BASE) -> StartupRecovery | StartupRecoveryFailure:
    # ponytail: validated stock crt0 layout only; extend with another validated pattern when needed.
    found = find_crt(rom)
    if isinstance(found, StartupRecoveryFailure):
        return found

    offset, branches = found
    start = base + offset
    # ClearMem and the helpers behind it follow the SoftReset SWI in the revisions that have one.
    swi = 0x28 + 2 * _SOFT_RESET
    clear_mem = start + swi + (2 if struct.unpack_from('<H', rom, offset + swi)[0] == 0xDF00 else 0)
    image = (base, base + len(rom))
    protected = [(base + b, base + b + 4) for b in branches] + [(base, base + 0xC0), (start, start + 0xD0)]
    try:
        literals = {delta: base + crt_literal(rom, offset, delta) for delta in _CRT_LITERALS}
        for address in literals.values():
            require(
                address % 4 == 0 and base <= address <= base + len(rom) - 4,
                'startup literal pool leaves input or is unaligned',
            )
            require(
                not _overlaps((address, address + 4), (start, start + 0xD0)), 'startup literal overlaps instructions'
            )
            protected.append((address, address + 4))

        values = {delta: struct.unpack_from('<I', rom, address - base)[0] for delta, address in literals.items()}
        require(values[0x28] == base, 'startup is not linked for this image base')
        copies = []
        for name, src, begin, end in (
            ('GBA_DATA_LMA', values[0x64], values[0x66], values[0x68]),
            ('GBA_IWRAM_LMA', values[0x6E], values[0x70], values[0x72]),
            ('GBA_EWRAM_LMA', values[0x86], values[0x88], values[0x8A]),
        ):
            require(end >= begin, name + ': backwards destination bounds')
            copies.append(StartupCopy(name=name, source=src, destination=begin, size=(end - begin + 3) & ~3))

        require(values[0x78] >= values[0x7A], 'overlay0: backwards source bounds')
        copies.append(
            StartupCopy(
                name='GBA_IWRAM0_LMA',
                source=values[0x7A],
                destination=values[0x80],
                size=(values[0x78] - values[0x7A] + 3) & ~3,
            )
        )
        # A section linked where it is loaded copies onto itself: nothing to populate.
        copies = [copy for copy in copies if copy.size and copy.source != copy.destination]
        sources, destinations = [], []
        for copy in copies:
            src, dst, size = copy.source, copy.destination, copy.size
            require(src % 4 == dst % 4 == 0, copy.name + ': unaligned copy')
            require(base <= src and src + size <= base + len(rom), copy.name + ': source leaves input')
            require(_ram_span(dst, size), copy.name + ': destination leaves canonical RAM')
            source, destination = (src, src + size), (dst, dst + size)
            require(not _overlaps(destination, image), copy.name + ': destination overlaps the loaded image')
            require(
                not any(_overlaps(source, span) for span in protected + sources),
                copy.name + ': source overlaps startup, literal, or another source',
            )
            require(
                not any(_overlaps(destination, span) for span in destinations),
                copy.name + ': overlapping destinations',
            )
            sources.append(source)
            destinations.append(destination)

        protected += sources
        for name, pointer in (('constructors', values[0x96]), ('main', values[0xA0])):
            require(code_pointer(pointer, rom, copies, protected, base), f'invalid {name} code pointer {pointer:#x}')
    except LoadError as exc:
        return StartupRecoveryFailure(str(exc))

    stacks, bss, hints = [], [], []
    for delta, mode in ((0x10, 'IRQ'), (0x1C, 'system')):
        value = values[delta]
        if value % 4 == 0 and 0x03000000 <= value <= 0x03008000:
            text = f'Stock crt0 {mode} stack hint: SP={value:#010x}'
            stacks.append(text)
            hints.append(AddressComment(start + delta, text))

    for lo, hi, region, name in (
        (values[0x50], values[0x52], (0x03000000, 0x03008000), 'BSS'),
        (values[0x5A], values[0x5C], (0x02000000, 0x02040000), 'SBSS'),
    ):
        if lo % 4 == hi % 4 == 0 and region[0] <= lo <= hi <= region[1]:
            text = f'{name} cleared at runtime: [{lo:#010x}, {hi:#010x}); bytes remain unknown in static IDB'
            bss.append(text)
            if lo < hi:
                hints.append(AddressComment(lo, text))

    return StartupRecovery(
        base=base,
        start=start,
        clear_mem=clear_mem,
        copies=tuple(copies),
        constructors=values[0x96],
        main=values[0xA0],
        stacks=tuple(stacks),
        bss=tuple(bss),
        protected=tuple(protected),
        hints=tuple(hints),
    )
