"""GBA hardware register, header and BIOS workspace annotation tables.

Hardware reference: https://mgba-emu.github.io/gbatek/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HardwareAnnotation:
    offset: int
    size: int
    width: int
    name: str
    declaration: str | None = None
    comment: str | None = None


@dataclass(frozen=True, slots=True)
class Register:
    offset: int
    width: int
    name: str
    access_description: str
    count: int = 1


IRQ_VECTORS = (0x03007FFC, 0x03FFFFFC)

HEADER_FIELDS = (
    HardwareAnnotation(0x04, 156, 1, 'GBA_HDR_LOGO'),
    HardwareAnnotation(0xA0, 12, 1, 'GBA_HDR_TITLE', 'char value[12];'),
    HardwareAnnotation(0xAC, 4, 1, 'GBA_HDR_GAME_CODE', 'char value[4];'),
    HardwareAnnotation(0xB0, 2, 1, 'GBA_HDR_MAKER_CODE', 'char value[2];'),
    HardwareAnnotation(0xB2, 1, 1, 'GBA_HDR_FIXED'),
    HardwareAnnotation(0xB3, 1, 1, 'GBA_HDR_UNIT_CODE'),
    HardwareAnnotation(0xB4, 1, 1, 'GBA_HDR_DEVICE_TYPE'),
    HardwareAnnotation(0xB5, 7, 1, 'GBA_HDR_RESERVED1'),
    HardwareAnnotation(0xBC, 1, 1, 'GBA_HDR_VERSION'),
    HardwareAnnotation(0xBD, 1, 1, 'GBA_HDR_CHECKSUM'),
    HardwareAnnotation(0xBE, 2, 1, 'GBA_HDR_RESERVED2'),
)

WORKSPACE = (
    HardwareAnnotation(0x7FF0, 4, 4, 'GBA_SOUND_BUFFER', 'unsigned int value;'),
    HardwareAnnotation(0x7FF8, 2, 2, 'GBA_IRQ_FLAGS', 'unsigned short value;'),
    HardwareAnnotation(0x7FFA, 1, 1, 'GBA_SOFT_RESET_FLAG', 'unsigned char value;'),
    HardwareAnnotation(
        0x7FFC,
        4,
        4,
        'GBA_IRQ_HANDLER',
        'void (* volatile value)(void);',
        'BIOS IRQ dispatch pointer: handler executes in ARM state. Value unknown.',
    ),
)

# fmt: off
REGISTERS = (
    # LCD / graphics
    Register(0x000, 2,  'REG_DISPCNT',    'R/W: display control'),
    Register(0x002, 2,  'REG_GREENSWAP',  'R/W: undocumented green-swap control'),
    Register(0x004, 2,  'REG_DISPSTAT',   'R/W: display status and interrupt control'),
    Register(0x006, 2,  'REG_VCOUNT',     'R: current scanline'),
    Register(0x008, 2,  'REG_BG0CNT',     'R/W: background 0 control'),
    Register(0x00A, 2,  'REG_BG1CNT',     'R/W: background 1 control'),
    Register(0x00C, 2,  'REG_BG2CNT',     'R/W: background 2 control'),
    Register(0x00E, 2,  'REG_BG3CNT',     'R/W: background 3 control'),
    Register(0x010, 2,  'REG_BG0HOFS',    'W: background 0 horizontal offset'),
    Register(0x012, 2,  'REG_BG0VOFS',    'W: background 0 vertical offset'),
    Register(0x014, 2,  'REG_BG1HOFS',    'W: background 1 horizontal offset'),
    Register(0x016, 2,  'REG_BG1VOFS',    'W: background 1 vertical offset'),
    Register(0x018, 2,  'REG_BG2HOFS',    'W: background 2 horizontal offset'),
    Register(0x01A, 2,  'REG_BG2VOFS',    'W: background 2 vertical offset'),
    Register(0x01C, 2,  'REG_BG3HOFS',    'W: background 3 horizontal offset'),
    Register(0x01E, 2,  'REG_BG3VOFS',    'W: background 3 vertical offset'),
    Register(0x020, 2,  'REG_BG2PA',      'W: BG2 affine parameter A'),
    Register(0x022, 2,  'REG_BG2PB',      'W: BG2 affine parameter B'),
    Register(0x024, 2,  'REG_BG2PC',      'W: BG2 affine parameter C'),
    Register(0x026, 2,  'REG_BG2PD',      'W: BG2 affine parameter D'),
    Register(0x028, 4,  'REG_BG2X',       'W: BG2 reference X coordinate'),
    Register(0x02C, 4,  'REG_BG2Y',       'W: BG2 reference Y coordinate'),
    Register(0x030, 2,  'REG_BG3PA',      'W: BG3 affine parameter A'),
    Register(0x032, 2,  'REG_BG3PB',      'W: BG3 affine parameter B'),
    Register(0x034, 2,  'REG_BG3PC',      'W: BG3 affine parameter C'),
    Register(0x036, 2,  'REG_BG3PD',      'W: BG3 affine parameter D'),
    Register(0x038, 4,  'REG_BG3X',       'W: BG3 reference X coordinate'),
    Register(0x03C, 4,  'REG_BG3Y',       'W: BG3 reference Y coordinate'),
    Register(0x040, 2,  'REG_WIN0H',      'W: window 0 horizontal bounds'),
    Register(0x042, 2,  'REG_WIN1H',      'W: window 1 horizontal bounds'),
    Register(0x044, 2,  'REG_WIN0V',      'W: window 0 vertical bounds'),
    Register(0x046, 2,  'REG_WIN1V',      'W: window 1 vertical bounds'),
    Register(0x048, 2,  'REG_WININ',      'R/W: window 0/1 inside control'),
    Register(0x04A, 2,  'REG_WINOUT',     'R/W: window outside/OBJ-window control'),
    Register(0x04C, 2,  'REG_MOSAIC',     'W: mosaic size'),
    Register(0x050, 2,  'REG_BLDCNT',     'R/W: color effects selection'),
    Register(0x052, 2,  'REG_BLDALPHA',   'R/W: alpha blend coefficients'),
    Register(0x054, 2,  'REG_BLDY',       'W: brightness coefficient'),

    # Sound
    Register(0x060, 2,  'REG_SOUND1CNT_L','R/W: channel 1 sweep'),
    Register(0x062, 2,  'REG_SOUND1CNT_H','R/W: channel 1 duty/length/envelope'),
    Register(0x064, 2,  'REG_SOUND1CNT_X','R/W: channel 1 frequency/control'),
    Register(0x068, 2,  'REG_SOUND2CNT_L','R/W: channel 2 duty/length/envelope'),
    Register(0x06C, 2,  'REG_SOUND2CNT_H','R/W: channel 2 frequency/control'),
    Register(0x070, 2,  'REG_SOUND3CNT_L','R/W: channel 3 stop/wave RAM select'),
    Register(0x072, 2,  'REG_SOUND3CNT_H','R/W: channel 3 length/volume'),
    Register(0x074, 2,  'REG_SOUND3CNT_X','R/W: channel 3 frequency/control'),
    Register(0x078, 2,  'REG_SOUND4CNT_L','R/W: channel 4 length/envelope'),
    Register(0x07C, 2,  'REG_SOUND4CNT_H','R/W: channel 4 frequency/control'),
    Register(0x080, 2,  'REG_SOUNDCNT_L', 'R/W: sound master volume/pan'),
    Register(0x082, 2,  'REG_SOUNDCNT_H', 'R/W: sound mixing and direct-sound control'),
    Register(0x084, 2,  'REG_SOUNDCNT_X', 'R/W: sound master enable/status'),
    Register(0x088, 2,  'REG_SOUNDBIAS',  'R/W: PWM bias/control'),
    Register(0x090, 2,  'REG_WAVE_RAM',   'R/W: channel 3 wave pattern RAM, one visible 16-byte bank', count=8),
    Register(0x0A0, 4,  'REG_FIFO_A',     'W: direct-sound FIFO A (4-byte access)'),
    Register(0x0A4, 4,  'REG_FIFO_B',     'W: direct-sound FIFO B (4-byte access)'),

    # DMA channels 0-3
    Register(0x0B0, 4,  'REG_DMA0SAD',    'W: DMA0 source address'),
    Register(0x0B4, 4,  'REG_DMA0DAD',    'W: DMA0 destination address'),
    Register(0x0B8, 2,  'REG_DMA0CNT_L',  'W: DMA0 word count'),
    Register(0x0BA, 2,  'REG_DMA0CNT_H',  'R/W: DMA0 control'),
    Register(0x0BC, 4,  'REG_DMA1SAD',    'W: DMA1 source address'),
    Register(0x0C0, 4,  'REG_DMA1DAD',    'W: DMA1 destination address'),
    Register(0x0C4, 2,  'REG_DMA1CNT_L',  'W: DMA1 word count'),
    Register(0x0C6, 2,  'REG_DMA1CNT_H',  'R/W: DMA1 control'),
    Register(0x0C8, 4,  'REG_DMA2SAD',    'W: DMA2 source address'),
    Register(0x0CC, 4,  'REG_DMA2DAD',    'W: DMA2 destination address'),
    Register(0x0D0, 2,  'REG_DMA2CNT_L',  'W: DMA2 word count'),
    Register(0x0D2, 2,  'REG_DMA2CNT_H',  'R/W: DMA2 control'),
    Register(0x0D4, 4,  'REG_DMA3SAD',    'W: DMA3 source address'),
    Register(0x0D8, 4,  'REG_DMA3DAD',    'W: DMA3 destination address'),
    Register(0x0DC, 2,  'REG_DMA3CNT_L',  'W: DMA3 word count'),
    Register(0x0DE, 2,  'REG_DMA3CNT_H',  'R/W: DMA3 control'),

    # Timers 0-3
    Register(0x100, 2,  'REG_TM0CNT_L',   'R/W: timer 0 counter/reload'),
    Register(0x102, 2,  'REG_TM0CNT_H',   'R/W: timer 0 control'),
    Register(0x104, 2,  'REG_TM1CNT_L',   'R/W: timer 1 counter/reload'),
    Register(0x106, 2,  'REG_TM1CNT_H',   'R/W: timer 1 control'),
    Register(0x108, 2,  'REG_TM2CNT_L',   'R/W: timer 2 counter/reload'),
    Register(0x10A, 2,  'REG_TM2CNT_H',   'R/W: timer 2 control'),
    Register(0x10C, 2,  'REG_TM3CNT_L',   'R/W: timer 3 counter/reload'),
    Register(0x10E, 2,  'REG_TM3CNT_H',   'R/W: timer 3 control'),

    # SIO; nonoverlapping multiplayer layout at 0x120 (the pair aliases the
    # 32-bit SIODATA32 view). No overlapping word item is defined here.
    Register(0x120, 2,  'REG_SIOMULTI0',  'R/W: multiplayer data 0; pair aliases 32-bit SIODATA32'),
    Register(0x122, 2,  'REG_SIOMULTI1',  'R/W: multiplayer data 1; pair aliases 32-bit SIODATA32'),
    Register(0x124, 2,  'REG_SIOMULTI2',  'R/W: multiplayer data 2'),
    Register(0x126, 2,  'REG_SIOMULTI3',  'R/W: multiplayer data 3'),
    Register(0x128, 2,  'REG_SIOCNT',     'R/W: serial control/status'),
    Register(0x12A, 2,  'REG_SIOMLT_SEND','R/W: multiplayer send data; aliases SIODATA8 in other modes'),
    Register(0x130, 2,  'REG_KEYINPUT',   'R: keypad state, active-low (0 = pressed)'),
    Register(0x132, 2,  'REG_KEYCNT',     'R/W: keypad interrupt control'),
    Register(0x134, 2,  'REG_RCNT',       'R/W: serial mode/general-purpose data'),
    Register(0x140, 2,  'REG_JOYCNT',     'R/W: JOY bus control'),
    Register(0x150, 4,  'REG_JOY_RECV',   'R/W: JOY bus receive data'),
    Register(0x154, 4,  'REG_JOY_TRANS',  'R/W: JOY bus transmit data'),
    Register(0x158, 2,  'REG_JOYSTAT',    'R/? per GBATEK: JOY bus receive status'),

    # Interrupt, cartridge waitstate, and power/system controls
    Register(0x200, 2,  'REG_IE',         'R/W: interrupt enable'),
    Register(0x202, 2,  'REG_IF',         'R/W: interrupt request flags/acknowledge'),
    Register(0x204, 2,  'REG_WAITCNT',    'R/W: cartridge waitstate control'),
    Register(0x208, 2,  'REG_IME',        'R/W: interrupt master enable'),
    Register(0x300, 1,  'REG_POSTFLG',    'R/W: post-boot flag'),
    Register(0x301, 1,  'REG_HALTCNT',    'W: halt/stop control'),
    Register(0x800, 4,  'REG_MEMCNT',     'R/W: internal memory control (undocumented)'),
)
# fmt: on
