from __future__ import annotations

import struct

import pytest
from roms import BASE, LOAD_VALUES, MB_BASE, make_indirect, make_multiboot, make_synthetic

from idagba.crt0 import StartupRecovery, StartupRecoveryFailure, recover_startup


def test_recovers_shifted_crt0():
    rom, _ = make_synthetic()
    recovered = recover_startup(rom)
    assert isinstance(recovered, StartupRecovery), recovered
    assert recovered.start == 0x08000240
    assert recovered.main == 0x08000701
    assert recovered.constructors == 0x08000781
    copies = {copy.name: copy for copy in recovered.copies}
    expected = {
        'GBA_DATA_LMA': (0x08000800, 0x03000100, 8),
        'GBA_IWRAM_LMA': (0x08000840, 0x03002000, 12),
        'GBA_IWRAM0_LMA': (0x08000870, 0x03002100, 8),
        'GBA_EWRAM_LMA': (0x08000860, 0x02000100, 8),
    }
    assert {name: (copy.source, copy.destination, copy.size) for name, copy in copies.items()} == expected


def _patched(rom: bytes, literals: dict[int, int], *patches: tuple[int, int]) -> bytes:
    patched = bytearray(rom)
    for delta, value in patches:
        struct.pack_into('<I', patched, literals[delta], value)

    return bytes(patched)


def _invalid_startups() -> list[bytes]:
    rom, literals = make_synthetic()
    near = bytearray(rom)
    near[0x268 + 2] ^= 1
    return [
        bytes(near),
        rom[:0x410],  # missing literal pool
        _patched(rom, literals, (0x68, 0x030000FC)),  # backwards
        _patched(rom, literals, (0x70, 0x03000104), (0x72, 0x03000110)),  # overlapping destinations
        _patched(rom, literals, (0x86, 0x08000804)),  # overlapping sources
        _patched(rom, literals, (0x64, BASE + len(rom) - 4)),  # source leaves the file
        _patched(rom, literals, (0xA0, 0x09000001)),  # bad main
    ]


@pytest.mark.parametrize('rom', _invalid_startups())
def test_rejects_invalid_startups(rom: bytes):
    assert isinstance(recover_startup(rom), StartupRecoveryFailure)


def test_rounded_and_empty_copies():
    rom, literals = make_synthetic()
    rounded_result = recover_startup(_patched(rom, literals, (0x68, 0x03000106)))
    assert isinstance(rounded_result, StartupRecovery)
    assert next(copy for copy in rounded_result.copies if copy.name == 'GBA_DATA_LMA').size == 8
    empty = _patched(
        rom,
        literals,
        *((end_offset, LOAD_VALUES[start_offset]) for end_offset, start_offset in (
            (0x68, 0x66), (0x72, 0x70), (0x78, 0x7A), (0x8A, 0x88),
        )),
    )  # fmt: skip
    empty_result = recover_startup(empty)
    assert isinstance(empty_result, StartupRecovery)
    assert not empty_result.copies


def test_multiboot_recovery():
    _, literals = make_synthetic()
    multiboot = make_multiboot()
    mb_recovered = recover_startup(multiboot, MB_BASE)
    assert isinstance(mb_recovered, StartupRecovery), mb_recovered
    assert mb_recovered.base == MB_BASE
    assert mb_recovered.main == MB_BASE + 0x701
    assert {copy.name: (copy.source, copy.destination) for copy in mb_recovered.copies} == {
        'GBA_DATA_LMA': (MB_BASE + 0x800, 0x03000100),
        'GBA_IWRAM_LMA': (MB_BASE + 0x840, 0x03002000),
        'GBA_IWRAM0_LMA': (MB_BASE + 0x870, 0x03002100),
    }
    assert isinstance(recover_startup(multiboot), StartupRecoveryFailure)
    into_image = _patched(multiboot, literals, (0x88, MB_BASE + 0x100), (0x8A, MB_BASE + 0x108))
    assert isinstance(recover_startup(into_image, MB_BASE), StartupRecoveryFailure)


def test_indirect_fixture_recovers():
    indirect = recover_startup(make_indirect())
    assert isinstance(indirect, StartupRecovery)
    assert indirect.main == BASE + 0x700
