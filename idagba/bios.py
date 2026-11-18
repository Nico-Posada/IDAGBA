"""GBA BIOS SWI call names and Hex-Rays prototypes.

Undocumented SoundWhatever0..4 (0x20..0x24) have no prototype: they stay inline asm.
"""

from __future__ import annotations

# Numbers and names taken from https://problemkaputt.de/gbatek.htm#biosfunctions
# fmt: off
# ruff: disable[E501]
BIOS_CALL_NAMES = (
    'SoftReset', 'RegisterRamReset', 'Halt', 'Stop', 'IntrWait', 'VBlankIntrWait', 'Div', 'DivArm',
    'Sqrt', 'ArcTan', 'ArcTan2', 'CpuSet', 'CpuFastSet', 'GetBiosChecksum', 'BgAffineSet', 'ObjAffineSet',
    'BitUnPack', 'LZ77UnCompWram', 'LZ77UnCompVram', 'HuffUnComp', 'RLUnCompWram', 'RLUnCompVram',
    'Diff8bitUnFilterWram', 'Diff8bitUnFilterVram', 'Diff16bitUnFilter', 'SoundBias', 'SoundDriverInit',
    'SoundDriverMode', 'SoundDriverMain', 'SoundDriverVSync', 'SoundChannelClear', 'MidiKey2Freq',
    'SoundWhatever0', 'SoundWhatever1', 'SoundWhatever2', 'SoundWhatever3', 'SoundWhatever4',
    'MultiBoot', 'HardReset', 'CustomHalt', 'SoundDriverVSyncOff', 'SoundDriverVSyncOn', 'SoundGetJumpList',
)

# Register arguments and results taken from https://problemkaputt.de/gbatek.htm#biosfunctions
# Div and DivArm return quotient:remainder in R0/R1 (and |quotient| in R3).
BIOS_PROTOTYPES = {
    0x00: 'void __usercall __noreturn SWI_SoftReset(void);',
    0x01: 'void __usercall SWI_RegisterRamReset(unsigned int flags@<R0>);',
    0x02: 'void __usercall __spoils<> SWI_Halt(void);',
    0x03: 'void __usercall SWI_Stop(void);',
    0x04: 'void __usercall SWI_IntrWait(unsigned int discard_old@<R0>, unsigned int flags@<R1>);',
    0x05: 'void __usercall SWI_VBlankIntrWait(void);',
    0x06: '__int64 __usercall SWI_Div@<R1:R0>(int number@<R0>, int denom@<R1>);',
    0x07: '__int64 __usercall SWI_DivArm@<R1:R0>(int denom@<R0>, int number@<R1>);',
    0x08: 'unsigned __int16 __usercall SWI_Sqrt@<R0>(unsigned int value@<R0>);',
    0x09: '__int16 __usercall SWI_ArcTan@<R0>(__int16 tan@<R0>);',
    0x0A: 'unsigned __int16 __usercall SWI_ArcTan2@<R0>(__int16 x@<R0>, __int16 y@<R1>);',
    0x0B: 'void __usercall SWI_CpuSet(const void *src@<R0>, void *dst@<R1>, unsigned int mode@<R2>);',
    0x0C: 'void __usercall SWI_CpuFastSet(const void *src@<R0>, void *dst@<R1>, unsigned int mode@<R2>);',
    0x0D: 'unsigned int __usercall SWI_GetBiosChecksum@<R0>(void);',
    0x0E: 'void __usercall SWI_BgAffineSet(const void *src@<R0>, void *dst@<R1>, unsigned int count@<R2>);',
    0x0F: 'void __usercall SWI_ObjAffineSet(const void *src@<R0>, void *dst@<R1>, unsigned int count@<R2>, unsigned int stride@<R3>);',
    0x10: 'void __usercall SWI_BitUnPack(const void *src@<R0>, void *dst@<R1>, const void *info@<R2>);',
    0x11: 'void __usercall SWI_LZ77UnCompWram(const void *src@<R0>, void *dst@<R1>);',
    0x12: 'void __usercall SWI_LZ77UnCompVram(const void *src@<R0>, void *dst@<R1>);',
    0x13: 'void __usercall SWI_HuffUnComp(const void *src@<R0>, void *dst@<R1>);',
    0x14: 'void __usercall SWI_RLUnCompWram(const void *src@<R0>, void *dst@<R1>);',
    0x15: 'void __usercall SWI_RLUnCompVram(const void *src@<R0>, void *dst@<R1>);',
    0x16: 'void __usercall SWI_Diff8bitUnFilterWram(const void *src@<R0>, void *dst@<R1>);',
    0x17: 'void __usercall SWI_Diff8bitUnFilterVram(const void *src@<R0>, void *dst@<R1>);',
    0x18: 'void __usercall SWI_Diff16bitUnFilter(const void *src@<R0>, void *dst@<R1>);',
    0x19: 'void __usercall SWI_SoundBias(unsigned int level@<R0>);',
    0x1A: 'void __usercall SWI_SoundDriverInit(void *sound_area@<R0>);',
    0x1B: 'void __usercall SWI_SoundDriverMode(unsigned int mode@<R0>);',
    0x1C: 'void __usercall SWI_SoundDriverMain(void);',
    0x1D: 'void __usercall SWI_SoundDriverVSync(void);',
    0x1E: 'void __usercall SWI_SoundChannelClear(void);',
    0x1F: 'unsigned int __usercall SWI_MidiKey2Freq@<R0>(void *wave@<R0>, unsigned __int8 key@<R1>, unsigned __int8 fine@<R2>);',
    0x25: 'int __usercall SWI_MultiBoot@<R0>(void *param@<R0>, unsigned int mode@<R1>);',
    0x26: 'void __usercall __noreturn SWI_HardReset(void);',
    0x27: 'void __usercall SWI_CustomHalt(unsigned __int8 haltcnt@<R2>);',
    0x28: 'void __usercall SWI_SoundDriverVSyncOff(void);',
    0x29: 'void __usercall SWI_SoundDriverVSyncOn(void);',
    0x2A: 'void __usercall SWI_SoundGetJumpList(void *dst@<R0>);',
}
# ruff: enable[E501]
# fmt: on


def decode_swi_number(value: int, *, thumb: bool) -> int:
    return value & 0xFF if thumb else (value >> 16) & 0xFF
