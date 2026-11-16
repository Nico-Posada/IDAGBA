from __future__ import annotations

import struct

from roms import BASE, FORMAT, MB_BASE, MB_FORMAT, LoaderInput, make_multiboot, make_synthetic, make_vote

from idagba import recognition
from idagba.recognition import RELAXED_FORMAT, accept_file, recognize
from idagba.rom import arm_branch_target, header_facts


def test_accept_file_restores_position():
    rom, _ = make_synthetic()
    li = LoaderInput(rom)
    li.seek(17)
    accepted = accept_file(li, 'not-an-extension.bin')
    assert isinstance(accepted, dict)
    assert accepted['format'] == FORMAT
    assert accepted['processor'] == 'ARM:ARM7TDMI'
    assert accepted['options'] == 0x8001
    assert li.tell() == 17
    rejected = LoaderInput(bytes(0xC0))
    rejected.seek(9)
    assert accept_file(rejected, 'renamed.gba') == 0
    assert rejected.tell() == 9


def test_recognize_cartridge_and_size_limits():
    rom, _ = make_synthetic()
    assert recognize(rom[:0xC0], len(rom), 'cart.bin') == FORMAT
    unusual = bytearray(rom)
    struct.pack_into('<I', unusual, 0, 0xE12FFF1E)
    assert recognize(unusual[:0xC0], len(unusual), 'cart.bin') == FORMAT
    for bad in (b'', bytes(0xBF), bytes(0xC0), bytes(bytearray(0xC0)[:0xB2] + b'\x96' + bytes(13))):
        assert not recognize(bad[:0xC0], len(bad), 'renamed.gba')

    assert not recognize(rom[:0xC0], 0x02000001, 'large.gba')
    assert recognize(rom[:0xC0], 0x02000000, 'max-size.bin') == FORMAT


def test_logo_tolerance_and_relaxed_format():
    rom, _ = make_synthetic()
    legal = bytearray(rom)
    legal[0x9C] ^= 0x84
    legal[0x9E] ^= 0x03
    assert recognize(legal[:0xC0], len(legal), 'noext') == FORMAT
    damaged = bytearray(rom)
    damaged[4] ^= 1
    relaxed = recognize(damaged[:0xC0], len(damaged), 'HOME.GBA')
    assert recognize(damaged[:0xC0], len(damaged), 'HOME.AgB') == relaxed
    assert relaxed
    assert 'homebrew or damaged' in relaxed
    relaxed_accept = accept_file(LoaderInput(damaged), 'HOME.GBA')
    assert isinstance(relaxed_accept, dict)
    assert relaxed_accept['format'] == relaxed
    assert relaxed_accept['options'] == 1
    assert not recognize(damaged[:0xC0], len(damaged), 'HOME.bin')
    damaged[0] = 0
    assert not recognize(damaged[:0xC0], len(damaged), 'HOME.gba')


def test_header_fact_warnings():
    rom, _ = make_synthetic()
    unusual = bytearray(rom)
    struct.pack_into('<I', unusual, 0, 0xE12FFF1E)
    assert any('entry' in warning.lower() for warning in header_facts(bytes(unusual)).warnings)
    checksum_bad = bytearray(rom)
    checksum_bad[0xA0] ^= 1
    facts = header_facts(bytes(checksum_bad))
    assert any('checksum' in warning.lower() for warning in facts.warnings)
    odd_header = bytearray(rom)
    odd_header[0xB3] = 1
    odd_header[0xB5] = 1
    odd_facts = header_facts(bytes(odd_header))
    assert any('unit' in warning.lower() for warning in odd_facts.warnings)
    assert any('reserved' in warning.lower() for warning in odd_facts.warnings)
    mb_facts = header_facts(make_multiboot(), MB_BASE)
    assert not any('entry' in warning for warning in mb_facts.warnings), mb_facts.warnings


def test_arm_branch_target():
    assert arm_branch_target(0xEA00002E, BASE) == 0x080000C0
    assert arm_branch_target(0xEAFFFFEE, 0x08000100) == 0x080000C0
    assert arm_branch_target(0xEAFFFFFE, 0x08000100) == 0x08000100
    assert arm_branch_target(0xE12FFF1E, BASE) is None


def test_multiboot_recognition():
    multiboot = make_multiboot()
    assert recognize(multiboot, len(multiboot), 'multiboot.gba') == MB_FORMAT
    mb_accept = accept_file(LoaderInput(multiboot), 'multiboot.gba')
    assert isinstance(mb_accept, dict)
    assert mb_accept['format'] == MB_FORMAT
    assert mb_accept['options'] == 0x8001
    ewram_vote = make_vote(MB_BASE + 0x100)
    assert recognize(ewram_vote, len(ewram_vote), 'x.gba') == MB_FORMAT
    cart_vote = make_vote(BASE + 0x100)
    assert recognize(cart_vote, len(cart_vote), 'x.gba') == FORMAT
    assert recognize(cart_vote, len(cart_vote), 'x.mb') == MB_FORMAT


def test_unfixed_header():
    unfixed = bytearray(make_vote(BASE + 0x100))
    unfixed[4:0xA0] = bytes(0x9C)
    unfixed[0xB2] = 0
    assert recognize(unfixed, len(unfixed), 'home.gba') == RELAXED_FORMAT
    assert any('0x96' in warning for warning in header_facts(bytes(unfixed)).warnings)
    assert not recognize(unfixed, len(unfixed), 'home.bin')
    unfixed[4] = 1
    assert not recognize(unfixed, len(unfixed), 'home.gba')


def test_format_marker_names_every_format():
    assert all(recognition.FORMAT_MARKER in name for name in (FORMAT, RELAXED_FORMAT, MB_FORMAT))
