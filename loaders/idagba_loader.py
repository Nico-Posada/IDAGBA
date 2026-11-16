"""IDA loader entry for idagba; $IDAUSR/loaders/ resolves here because IDA scans only loaders/ directories.

The functions are defined in this file, not imported: IDA runs a loader function with this
file's namespace as its globals, so an imported function would lose its own module's globals.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ida_idaapi import loader_input_t


def accept_file(li: loader_input_t, filename: str) -> dict[str, str | int] | int:
    try:
        from idagba import recognition  # noqa: PLC0415
    except ImportError:  # a copied entry file (Windows fallback) can outlive an uninstalled plugin
        return 0

    return recognition.accept_file(li, filename)


def load_file(li: loader_input_t, neflags: int, format_name: str) -> int:
    # Deferred: accept_file runs for every file IDA opens and must not pay for importing ida_domain.
    from idagba.loader import load_file as load  # noqa: PLC0415

    return load(li, neflags, format_name)
