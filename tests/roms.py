"""Synthetic GBA images; the templates are kept independent of the production tables on purpose."""

from __future__ import annotations

import io
import struct

BASE = 0x08000000
FORMAT = 'Nintendo Game Boy Advance ROM (ARM7TDMI)'
MB_BASE = 0x02000000
MB_FORMAT = 'Nintendo Game Boy Advance multiboot image (EWRAM)'
LOGO = bytes.fromhex(
    '24 ff ae 51 69 9a a2 21 3d 84 82 0a 84 e4 09 ad '
    '11 24 8b 98 c0 81 7f 21 a3 52 be 19 93 09 ce 20 '
    '10 46 4a 4a f8 27 31 ec 58 c7 e8 33 82 e3 ce bf '
    '85 f4 df 94 ce 4b 09 c1 94 56 8a c0 13 72 a7 fc '
    '9f 84 4d 73 a3 ca 9a 61 58 97 a3 27 fc 03 98 76 '
    '23 1d c7 61 03 04 ae 56 bf 38 84 00 40 a7 0e fd '
    'ff 52 fe 03 6f 95 30 f1 97 fb c0 85 60 d6 80 25 '
    'a9 63 be 03 01 4e 38 e2 f9 a2 34 ff bb 3e 03 44 '
    '78 00 90 cb 88 11 3a 94 65 c0 7c 63 87 f0 3c af '
    'd6 25 e4 8b 38 0a ac 72 21 d4 f8 07'
)
ARM_TEMPLATE = (
    0xE3A00301, 0xE5800208, 0xE3A00012, 0xE129F000, 0xE59FD0B8,
    0xE3A0001F, 0xE129F000, 0xE59FD0B0, 0xE28F0001, 0xE12FFF10,
)  # fmt: skip
# Big-endian halfwords, as written in the crt0 listing.
THUMB_TEMPLATE: tuple[int, ...] = struct.unpack(
    '>84H',
    bytes.fromhex("""
482B 0140 D20B 4678 0140 D30D 2202 0612 4B28 1A9B 1C16 0091 F000 F83D 4730 2140
0309 01C8 F000 F82C 4823 4924 1A09 F000 F827 4823 4923 1A09 F000 F822 4922 4A23
4C23 F000 F827 4923 4A23 4C24 F000 F822 4A23 4924 1A53 D002 4A23 F000 F81C 4923
4A23 4C24 F000 F816 4923 4824 6008 4B24 F000 F80F 2000 2100 4B22 F000 F80A DF00
2203 1889 4391 D003 2200 C004 3904 D1FC 4770 4718 1AA3 2003 181B 4383 D003 C901
C201 3B04 D1FB 4770
"""),
)
# The same listing before devkitarm-crtls 333d62c added the SoftReset SWI, as shipped in pre-2021 ROMs.
THUMB_TEMPLATE_NO_RESET: tuple[int, ...] = struct.unpack(
    '>84H',
    bytes.fromhex("""
482B 0140 D20B 4678 0140 D30D 2202 0612 4B28 1A9B 1C16 0091 F000 F83C 4730 2140
0309 01C8 F000 F82B 4823 4924 1A09 F000 F826 4823 4923 1A09 F000 F821 4922 4A23
4C23 F000 F826 4923 4A23 4C24 F000 F821 4A23 4924 1A53 D002 4A23 F000 F81B 4923
4A23 4C24 F000 F815 4923 4824 6008 4B24 F000 F80E 2000 2100 4B22 F000 F809 2203
1889 4391 D003 2200 C004 3904 D1FC 4770 4718 1AA3 2003 181B 4383 D003 C901 C201
3B04 D1FB 4770 46C0
"""),
)
LOAD_VALUES = {
    0x10: 0x03007F00, 0x1C: 0x03007E00, 0x28: 0x08000000,
    0x38: 0x02000400, 0x90: 0x03002008, 0x92: 0x02040000,
    0x50: 0x03003000, 0x52: 0x03003020,
    0x5A: 0x02000200, 0x5C: 0x02000210,
    0x64: 0x08000800, 0x66: 0x03000100, 0x68: 0x03000108,
    0x6E: 0x08000840, 0x70: 0x03002000, 0x72: 0x0300200C,
    0x78: 0x08000878, 0x7A: 0x08000870, 0x80: 0x03002100,
    0x86: 0x08000860, 0x88: 0x02000100, 0x8A: 0x02000108,
    0x96: 0x08000781, 0xA0: 0x08000701,
}  # fmt: skip
REAL_SHA256 = '320dcb2a7e4704bb5dab99ad3dbf27943459ca37a263c633d6ddc3f059550e7c'


def _branch(source: int, target: int) -> int:
    delta = target - source - 8
    assert delta % 4 == 0
    assert -(1 << 25) <= delta < (1 << 25)
    return 0xEA000000 | ((delta >> 2) & 0xFFFFFF)


def _finish_header(rom: bytearray, entry: int = 0x080000C0) -> None:
    struct.pack_into('<I', rom, 0, _branch(BASE, entry))
    rom[4:0xA0] = LOGO
    rom[0xA0:0xAC] = b'SYNTHETIC\0\0\0'
    rom[0xAC:0xB0] = b'TEST'
    rom[0xB0:0xB2] = b'01'
    rom[0xB2] = 0x96
    rom[0xB3:0xBC] = b'\0' * 9
    rom[0xBC] = 0
    rom[0xBD] = (-sum(rom[0xA0:0xBD]) - 0x19) & 0xFF
    rom[0xBE:0xC0] = b'\0\0'


def make_synthetic(thumb: tuple[int, ...] = THUMB_TEMPLATE) -> tuple[bytes, dict[int, int]]:
    """Build the shifted crt0 fixture without importing production tables."""
    rom = bytearray(0x1000)
    start = BASE + 0x240
    _finish_header(rom, BASE + 0x220)
    struct.pack_into('<I', rom, 0x220, _branch(BASE + 0x220, start))
    for index, word in enumerate(ARM_TEMPLATE):
        struct.pack_into('<I', rom, 0x240 + index * 4, word)

    for index, halfword in enumerate(thumb):
        struct.pack_into('<H', rom, 0x268 + index * 2, halfword)

    # The assembler emits the pool right behind the code: one word per load, in order of first use.
    literal_offsets = {}
    for index, instruction_offset in enumerate(sorted(LOAD_VALUES)):
        instruction = 0x240 + instruction_offset
        literal = 0x240 + 0xD0 + index * 4
        literal_offsets[instruction_offset] = literal
        struct.pack_into('<I', rom, literal, LOAD_VALUES[instruction_offset])
        if instruction_offset in (0x10, 0x1C):
            immediate = struct.unpack_from('<I', rom, instruction)[0] & 0xFFF
            assert instruction + 8 + immediate == literal
        else:
            immediate = struct.unpack_from('<H', rom, instruction)[0] & 0xFF
            assert ((instruction + 4) & ~3) + immediate * 4 == literal

    # Thumb main: poll VCOUNT, mutate initialized RAM, call copied ARM, read WS1 ROM.
    main_halfwords = (
        0xB500, 0x4B09, 0x8818, 0x289F, 0xD9FC, 0x4B08, 0x6818, 0x3001,
        0x6018, 0xF000, 0xF805, 0x4906, 0x6809, 0x1840, 0xBD00, 0x46C0,
        0x4B04, 0x4718,
    )  # fmt: skip
    for index, halfword in enumerate(main_halfwords):
        struct.pack_into('<H', rom, 0x700 + index * 2, halfword)

    struct.pack_into('<IIII', rom, 0x728, 0x04000006, 0x03002000, 0x0A000880, 0x03000100)
    struct.pack_into('<H', rom, 0x780, 0x4770)  # constructor dispatcher fixture
    struct.pack_into('<II', rom, 0x800, 0xE2800001, 0xE12FFF1E)
    rom[0x840:0x84C] = struct.pack('<III', 5, 0xB5F0B082, 0x47702000)
    rom[0x860:0x868] = b'EWRAM!!\0'
    rom[0x870:0x878] = b'OVERLAY0'
    struct.pack_into('<I', rom, 0x880, 0x12345678)
    return bytes(rom), literal_offsets


def make_long_jump() -> bytes:
    """Thumb BL used as an intra-function jump beyond the short-B range."""
    rom = bytearray(make_synthetic()[0])
    rom[0x700:0x738] = bytes(0x38)
    # PUSH {r4,lr}; SUB sp,#16; MOV r4,#7; STR r4,[sp]; BL 0x08000F20.
    struct.pack_into('<6H', rom, 0x700, 0xB510, 0xB084, 0x2407, 0x9400, 0xF000, 0xFC0A)
    # The remote block uses the same stack frame and returns through its epilogue.
    struct.pack_into('<4H', rom, 0xF20, 0x9800, 0x3001, 0xB004, 0xBD10)
    return bytes(rom)


def make_palette() -> bytes:
    """Write both ends of OBJ palette RAM and the user's two BG colors."""
    rom = bytearray(make_synthetic()[0])
    # LDR address/value; STRH, followed by BX LR and an aligned literal pool.
    struct.pack_into(
        '<16H', rom, 0x700,
        0x4807, 0x4908, 0x8001, 0x4808, 0x4908, 0x8001, 0x4808, 0x8001,
        0x4808, 0x8001, 0x4808, 0x2101, 0x0209, 0x8001, 0x4770, 0x46C0,
    )  # fmt: skip
    struct.pack_into('<7I', rom, 0x720, 0x05000000, 20903, 0x050001E2, 0x7FFF, 0x05000200, 0x050003FE, 0x04000000)
    return bytes(rom)


def make_large() -> bytes:
    rom = bytearray(0x01000004)
    _finish_header(rom)
    struct.pack_into('<I', rom, 0xC0, 0xE12FFF1E)
    struct.pack_into('<I', rom, len(rom) - 4, 0xA55A3CC3)
    return bytes(rom)


def make_multiboot() -> bytes:
    """The shifted crt0 fixture relinked for EWRAM, entered by the BIOS at 0xC0."""
    rom, literals = make_synthetic()
    rom = bytearray(rom)
    struct.pack_into('<I', rom, 0xC0, _branch(BASE + 0xC0, BASE + 0x220))
    for literal in literals.values():
        value = struct.unpack_from('<I', rom, literal)[0]
        if value & 0xFF000000 == BASE:
            struct.pack_into('<I', rom, literal, value - BASE + MB_BASE)

    # The EWRAM section is linked where it is loaded, so crt0 copies it onto itself.
    struct.pack_into('<I', rom, literals[0x88], MB_BASE + 0x860)
    struct.pack_into('<I', rom, literals[0x8A], MB_BASE + 0x868)
    struct.pack_into('<I', rom, 0x730, MB_BASE + 0x880)
    return bytes(rom)


def make_vote(value: int) -> bytes:
    """No crt0: one ARM PC-relative literal load right after the header."""
    rom = bytearray(0x200)
    _finish_header(rom)
    struct.pack_into('<I', rom, 0xC0, 0xE59F0000 | (0x100 - 0xC8))
    struct.pack_into('<I', rom, 0x100, value)
    return bytes(rom)


def make_indirect() -> bytes:
    """ARM main: stores an IRQ handler, calls Thumb via mov lr,pc; bx, and issues an ARM SWI.

    The Thumb callee returns quotient + remainder of BIOS Div, so both result registers matter.
    An unreferenced Thumb routine at 0x960 adds 1 to r0 across Halt, which preserves registers.
    """
    rom, literals = make_synthetic()
    rom = bytearray(rom)
    struct.pack_into('<I', rom, literals[0xA0], BASE + 0x700)
    rom[0x700:0x740] = bytes(0x40)
    struct.pack_into(
        '<8I',
        rom,
        0x700,
        0xE59F1018,  # ldr r1, =0x03007FFC
        0xE59F0018,  # ldr r0, =ARM handler
        0xE5810000,  # str r0, [r1]
        0xE59F2014,  # ldr r2, =Thumb function | 1
        0xE1A0E00F,  # mov lr, pc
        0xE12FFF12,  # bx r2
        0xEF050000,  # swi 0x050000 (VBlankIntrWait)
        0xE12FFF1E,  # bx lr
    )
    struct.pack_into('<3I', rom, 0x720, 0x03007FFC, BASE + 0x900, BASE + 0x941)
    struct.pack_into('<I', rom, 0x900, 0xE12FFF1E)
    struct.pack_into('<3H', rom, 0x940, 0xDF06, 0x1840, 0x4770)  # svc 6; adds r0, r0, r1; bx lr
    struct.pack_into('<3H', rom, 0x960, 0xDF02, 0x3001, 0x4770)  # svc 2; adds r0, #1; bx lr
    return bytes(rom)


def make_veneers() -> bytes:
    """Thumb main reaches ARM code in IWRAM through a linker veneer and a Thumb routine through a bx r3 helper.

    That routine adds 2 to r0 and leaves through the same veneer, so the veneer is also the target of a tail jump.
    """
    rom = bytearray(make_synthetic()[0])
    rom[0x700:0x780] = bytes(0x80)
    struct.pack_into(
        '<10H',
        rom,
        0x700,
        0xB510,  # push {r4, lr}
        0x2005,  # movs r0, #5
        0xF000,  # bl 0x08000730, the veneer
        0xF814,
        0x4B02,  # ldr r3, =0x08000741
        0xF000,  # bl 0x08000720, the bx r3 helper
        0xF809,
        0xBC10,  # pop {r4}
        0xBC02,  # pop {r1}
        0x4708,  # bx r1
    )
    struct.pack_into('<I', rom, 0x714, BASE + 0x741)
    struct.pack_into('<H', rom, 0x720, 0x4718)  # bx r3
    # What ld puts in front of ARM code that Thumb code cannot reach: bx pc; b .-2; then ARM ldr pc, [pc, #-4]; target.
    struct.pack_into('<2H2I', rom, 0x730, 0x4778, 0xE7FD, 0xE51FF004, 0x03000100)
    struct.pack_into('<2H', rom, 0x740, 0x3002, 0xE7F5)  # adds r0, #2; b 0x08000730
    return bytes(rom)


class LoaderInput:
    def __init__(self, data: bytes | bytearray) -> None:
        self._stream = io.BytesIO(data)

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._stream.seek(offset, whence)

    def tell(self) -> int:
        return self._stream.tell()

    def size(self) -> int:
        return len(self._stream.getbuffer())
