"""ARM7TDMI state on top of the raw SDK: ida_domain has no segment-register API."""

from __future__ import annotations

from typing import TYPE_CHECKING

import ida_allins
import ida_idp
import ida_segregs

from idagba.bios import decode_swi_number
from idagba.errors import require

if TYPE_CHECKING:
    from ida_domain import Database
    from ida_ua import insn_t


def thumb_state(ea: int) -> int:
    return ida_segregs.get_sreg(ea, ida_idp.str2reg('T'))


def set_thumb(ea: int, thumb: int) -> None:
    register = ida_idp.str2reg('T')
    require(register >= 0, 'ARM processor does not expose T state')
    require(
        ida_segregs.split_sreg_range(ea, register, thumb, ida_segregs.SR_auto),
        f'Cannot establish T={thumb} at {ea:#x}',
    )


def swi_number(db: Database, insn: insn_t) -> int | None:
    """BIOS call number of an SVC instruction, or None for anything else."""
    if insn.itype != ida_allins.ARM_svc:
        return None

    operand = db.instructions.get_operand(insn, 0)
    return None if operand is None else decode_swi_number(operand.get_value(), thumb=thumb_state(insn.ea) == 1)
