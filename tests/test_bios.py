from __future__ import annotations

import re

from idagba.bios import BIOS_CALL_NAMES, BIOS_PROTOTYPES, decode_swi_number


def test_prototypes_match_call_names():
    assert len(BIOS_CALL_NAMES) == 0x2B
    for number, prototype in BIOS_PROTOTYPES.items():
        assert re.search(rf'\bSWI_{BIOS_CALL_NAMES[number]}\b', prototype), (number, prototype)
    assert set(range(len(BIOS_CALL_NAMES))) - BIOS_PROTOTYPES.keys() == set(range(0x20, 0x25))


def test_decode_swi_number():
    assert decode_swi_number(0x06, thumb=True) == 6
    assert decode_swi_number(0x050000, thumb=False) == 5
