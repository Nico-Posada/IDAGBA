"""Stock devkitARM startup code (crt0): find it, read its literal pool, check what the pool describes.

devkitARM links gba_crt0.s in front of every program it builds. The code is the same in every
image; only the literal pool behind it differs. That pool holds the linker symbols the loader wants:
where main is, and which sections the startup copies from the image into RAM before calling it.

1. find_crt0 follows the entry branches to a byte-exact copy of the startup code.
2. Crt0.pool reads the literal pool behind that code into a LiteralPool.
3. recover_startup checks that the copies and code pointers in the pool fit the image, and returns
   them as a StartupRecovery.

Recovery is all or nothing. When the startup is not the stock one, or any check fails, the result
is a StartupRecoveryFailure and the loader leaves RAM empty and main unnamed rather than guess.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from idagba.errors import LoadError, require
from idagba.rom import BASE, EWRAM, HEADER_SIZE, IWRAM, arm_branch_target

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class StartupCopy:
    """One section the startup copies out of the image into RAM; name labels its source in the IDB."""

    name: str
    source: int
    destination: int
    size: int


@dataclass(frozen=True, slots=True)
class Note:
    """A recovered fact for the load report, also a comment at address when it has one."""

    text: str
    address: int | None = None


@dataclass(frozen=True, slots=True)
class StartupRecovery:
    """What a validated stock startup tells about its image.

    start and clear_mem are the addresses of start_vector and ClearMem. constructors and main keep
    their Thumb state in bit 0. reserved lists the image ranges that are already explained.
    """

    base: int
    start: int
    clear_mem: int
    copies: tuple[StartupCopy, ...]
    constructors: int
    main: int
    notes: tuple[Note, ...]
    reserved: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class StartupRecoveryFailure:
    reason: str


def recover_startup(rom: bytes, base: int = BASE) -> StartupRecovery | StartupRecoveryFailure:
    """Recover the startup of an image loaded at base, or say why that is not possible."""
    crt0 = find_crt0(rom)
    if isinstance(crt0, StartupRecoveryFailure):
        return crt0

    try:
        return _recover(crt0, base)
    except LoadError as exc:
        return StartupRecoveryFailure(str(exc))


def _recover(crt0: Crt0, base: int) -> StartupRecovery:
    pool = crt0.pool()
    if pool is None:
        msg = 'startup literal pool leaves the input'
        raise LoadError(msg)

    require(pool.text_start == base, 'startup is not linked for this image base')
    image = (base, base + len(crt0.rom))
    start = base + crt0.offset
    # Ranges that are already explained: the header, the startup with its pool, and the branches
    # that lead to it. No section may be copied out of them and no code pointer may land in them.
    reserved = [
        (base, base + HEADER_SIZE),
        (start, base + crt0.pool_offset + LiteralPool.FORMAT.size),
        *((base + branch, base + branch + 4) for branch in crt0.entry_branches),
    ]
    copies = _copies(pool)
    # The source of a copy is data, so it is explained as well.
    reserved += _check_copies(copies, image, reserved)
    for name, pointer in (('__libc_init_array', pool.libc_init_array), ('main', pool.main)):
        require(code_pointer(pointer, image, copies, reserved), f'invalid {name} code pointer {pointer:#x}')

    return StartupRecovery(
        base=base,
        start=start,
        clear_mem=base + crt0.clear_mem,
        copies=tuple(copies),
        constructors=pool.libc_init_array,
        main=pool.main,
        notes=tuple(_notes(pool, start)),
        reserved=tuple(reserved),
    )


@dataclass(frozen=True, slots=True)
class LiteralPool:
    """The literal pool behind the startup code: the value of every linker symbol it loads."""

    # Layout order taken from the `ldr rX, =symbol` loads in
    # https://github.com/devkitPro/devkitarm-crtls/blob/333d62c/gba_crt0.s#L65-L183
    sp_irq: int
    sp_usr: int
    text_start: int
    end: int
    bss_start: int
    bss_end: int
    sbss_start: int
    sbss_end: int
    data_lma: int
    data_start: int
    data_end: int
    iwram_lma: int
    iwram_start: int
    iwram_end: int
    load_stop_iwram0: int
    load_start_iwram0: int
    iwram_overlay_start: int
    ewram_lma: int
    ewram_start: int
    ewram_end: int
    fake_heap_end: int
    eheap_end: int
    libc_init_array: int
    main: int

    FORMAT: ClassVar[struct.Struct] = struct.Struct('<24I')


@dataclass(frozen=True, slots=True)
class Crt0:
    """A stock startup found in an image.

    Every offset is a file offset, so no load address is needed yet: offset is start_vector,
    clear_mem is ClearMem, pool_offset is the literal pool, and entry_branches are the branches
    followed from the file start to get here.
    """

    rom: bytes = field(repr=False)
    offset: int
    clear_mem: int
    pool_offset: int
    entry_branches: tuple[int, ...]

    # The assembled startup code and the offset of ClearMem in it, taken from
    # https://github.com/devkitPro/devkitarm-crtls/blob/333d62c/gba_crt0.s#L58-L253
    # and from the revision before it, which has no SoftReset after main:
    # https://github.com/devkitPro/devkitarm-crtls/blob/eac1e8c/gba_crt0.s#L58-L250
    REVISIONS: ClassVar[tuple[tuple[bytes, int], ...]] = (
        (
            bytes.fromhex("""
                01 03 A0 E3 08 02 80 E5 12 00 A0 E3 00 F0 29 E1
                B8 D0 9F E5 1F 00 A0 E3 00 F0 29 E1 B0 D0 9F E5
                01 00 8F E2 10 FF 2F E1 2B 48 40 01 0B D2 78 46
                40 01 0D D3 02 22 12 06 28 4B 9B 1A 16 1C 91 00
                00 F0 3D F8 30 47 40 21 09 03 C8 01 00 F0 2C F8
                23 48 24 49 09 1A 00 F0 27 F8 23 48 23 49 09 1A
                00 F0 22 F8 22 49 23 4A 23 4C 00 F0 27 F8 23 49
                23 4A 24 4C 00 F0 22 F8 23 4A 24 49 53 1A 02 D0
                23 4A 00 F0 1C F8 23 49 23 4A 24 4C 00 F0 16 F8
                23 49 24 48 08 60 24 4B 00 F0 0F F8 00 20 00 21
                22 4B 00 F0 0A F8 00 DF 03 22 89 18 91 43 03 D0
                00 22 04 C0 04 39 FC D1 70 47 18 47 A3 1A 03 20
                1B 18 83 43 03 D0 01 C9 01 C2 04 3B FB D1 70 47
            """),
            0xA8,
        ),
        (
            bytes.fromhex("""
                01 03 A0 E3 08 02 80 E5 12 00 A0 E3 00 F0 29 E1
                B8 D0 9F E5 1F 00 A0 E3 00 F0 29 E1 B0 D0 9F E5
                01 00 8F E2 10 FF 2F E1 2B 48 40 01 0B D2 78 46
                40 01 0D D3 02 22 12 06 28 4B 9B 1A 16 1C 91 00
                00 F0 3C F8 30 47 40 21 09 03 C8 01 00 F0 2B F8
                23 48 24 49 09 1A 00 F0 26 F8 23 48 23 49 09 1A
                00 F0 21 F8 22 49 23 4A 23 4C 00 F0 26 F8 23 49
                23 4A 24 4C 00 F0 21 F8 23 4A 24 49 53 1A 02 D0
                23 4A 00 F0 1B F8 23 49 23 4A 24 4C 00 F0 15 F8
                23 49 24 48 08 60 24 4B 00 F0 0E F8 00 20 00 21
                22 4B 00 F0 09 F8 03 22 89 18 91 43 03 D0 00 22
                04 C0 04 39 FC D1 70 47 18 47 A3 1A 03 20 1B 18
                83 43 03 D0 01 C9 01 C2 04 3B FB D1 70 47 C0 46
            """),
            0xA6,
        ),
    )

    @classmethod
    def at(cls, rom: bytes, offset: int, entry_branches: tuple[int, ...]) -> Crt0 | None:
        """The stock startup at a file offset, if one is there."""
        for code, clear_mem in cls.REVISIONS:
            if rom.startswith(code, offset):
                return cls(rom, offset, offset + clear_mem, offset + len(code), entry_branches)

        return None

    def pool(self) -> LiteralPool | None:
        """The literal pool behind the code, or None when the file ends inside it."""
        if self.pool_offset + LiteralPool.FORMAT.size > len(self.rom):
            return None

        return LiteralPool(*LiteralPool.FORMAT.unpack_from(self.rom, self.pool_offset))


def find_crt0(rom: bytes) -> Crt0 | StartupRecoveryFailure:
    """Follow the chain of ARM branches from the file start to a stock startup."""
    max_branches = 4
    offset = 0
    branches = []
    while True:
        if offset in branches or offset % 4 or not 0 <= offset <= len(rom) - 4:
            return StartupRecoveryFailure('entry branch chain loops, is unaligned, or leaves the input')

        crt0 = Crt0.at(rom, offset, tuple(branches)) if offset >= HEADER_SIZE else None
        if crt0:
            return crt0

        if len(branches) == max_branches:
            return StartupRecoveryFailure(f'no stock crt0 within {max_branches} entry branches')

        target = arm_branch_target(struct.unpack_from('<I', rom, offset)[0], offset)
        if target is None or target < HEADER_SIZE:
            return StartupRecoveryFailure('entry chain does not reach the stock crt0 template')

        branches.append(offset)
        offset = target


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _within(inner: tuple[int, int], outer: tuple[int, int]) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def _copies(pool: LiteralPool) -> list[StartupCopy]:
    """The sections the startup copies into RAM, without those that leave nothing to populate."""
    # Source, destination and length taken from the CopyMemChk and CopyMem calls in
    # https://github.com/devkitPro/devkitarm-crtls/blob/333d62c/gba_crt0.s#L130-L163
    copies = [
        _copy('GBA_DATA_LMA', pool.data_lma, pool.data_start, pool.data_end - pool.data_start),
        _copy('GBA_IWRAM_LMA', pool.iwram_lma, pool.iwram_start, pool.iwram_end - pool.iwram_start),
        _copy('GBA_EWRAM_LMA', pool.ewram_lma, pool.ewram_start, pool.ewram_end - pool.ewram_start),
        _copy(
            'GBA_IWRAM0_LMA',
            pool.load_start_iwram0,
            pool.iwram_overlay_start,
            pool.load_stop_iwram0 - pool.load_start_iwram0,
        ),
    ]
    # A section linked where it is loaded is copied onto itself, as .ewram is in a multiboot image.
    return [copy for copy in copies if copy.size and copy.source != copy.destination]


def _copy(name: str, source: int, destination: int, size: int) -> StartupCopy:
    require(size >= 0, f'{name}: section ends before it starts')
    # CopyMem rounds the length up to a whole word.
    return StartupCopy(name, source, destination, (size + 3) & ~3)


def _check_copies(
    copies: Sequence[StartupCopy], image: tuple[int, int], reserved: Sequence[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Source range of every copy, once each reads unexplained image bytes and writes RAM of its own."""
    sources, destinations = [], []
    for copy in copies:
        source = (copy.source, copy.source + copy.size)
        destination = (copy.destination, copy.destination + copy.size)
        require(copy.source % 4 == copy.destination % 4 == 0, f'{copy.name}: unaligned copy')
        require(_within(source, image), f'{copy.name}: source leaves input')
        require(
            _within(destination, EWRAM) or _within(destination, IWRAM),
            f'{copy.name}: destination leaves canonical RAM',
        )
        # A multiboot image is itself loaded into EWRAM.
        require(not _overlaps(destination, image), f'{copy.name}: destination overlaps the loaded image')
        require(
            not any(_overlaps(source, span) for span in (*reserved, *sources)),
            f'{copy.name}: source overlaps startup, literal, or another source',
        )
        require(
            not any(_overlaps(destination, span) for span in destinations),
            f'{copy.name}: overlapping destinations',
        )
        sources.append(source)
        destinations.append(destination)

    return sources


def _notes(pool: LiteralPool, start: int) -> list[Note]:
    """Stack tops and zero-filled ranges, when the pool holds plausible ones."""
    # Offsets of the two `ldr sp` instructions in
    # https://github.com/devkitPro/devkitarm-crtls/blob/333d62c/gba_crt0.s#L65-L68
    ldr_sp_irq, ldr_sp_usr = 0x10, 0x1C
    notes = []
    for mode, top, load in (('IRQ', pool.sp_irq, ldr_sp_irq), ('system', pool.sp_usr, ldr_sp_usr)):
        if top % 4 == 0 and IWRAM[0] <= top <= IWRAM[1]:
            notes.append(Note(f'Stock crt0 {mode} stack hint: SP={top:#010x}', start + load))

    # The startup zero-fills both ranges at run time, so the image holds no bytes for them.
    for name, lo, hi, region in (
        ('BSS', pool.bss_start, pool.bss_end, IWRAM),
        ('SBSS', pool.sbss_start, pool.sbss_end, EWRAM),
    ):
        if lo % 4 == hi % 4 == 0 and region[0] <= lo <= hi <= region[1]:
            text = f'{name} cleared at runtime: [{lo:#010x}, {hi:#010x}); bytes remain unknown in static IDB'
            notes.append(Note(text, lo if lo < hi else None))

    return notes


def code_pointer(
    pointer: int, image: tuple[int, int], copies: Sequence[StartupCopy], reserved: Sequence[tuple[int, int]]
) -> bool:
    """Whether pointer (Thumb state in bit 0) can lead to code: unexplained image bytes or a RAM copy.

    Post-analysis asks this too, for pointers it finds in literal pools and IRQ vector stores.
    """
    address = pointer & ~1
    width = 2 if pointer & 1 else 4
    if address % width:
        return False

    instruction = (address, address + width)
    if _within(instruction, (image[0] + HEADER_SIZE, image[1])):
        return not any(_overlaps(instruction, span) for span in reserved)

    return any(_within(instruction, (copy.destination, copy.destination + copy.size)) for copy in copies)
