"""Loader stub for IDAGBA. Gets copied into $IDAUSR/loaders later so IDA can find it."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ida_idaapi import loader_input_t


def accept_file(li: loader_input_t, filename: str) -> dict[str, str | int] | int:
    try:
        from idagba import recognition  # noqa: PLC0415
    except ImportError:
        # The setup for windows does a copy instead of a symlink, so if a user
        # deletes the plugin this can still run.
        return 0

    return recognition.accept_file(li, filename)


def load_file(li: loader_input_t, neflags: int, format_name: str) -> int:
    # this loader gets ran on every new file load, so do a lazy import to avoid importing this fat module every time
    from idagba.loader import load_file as load  # noqa: PLC0415

    return load(li, neflags, format_name)
