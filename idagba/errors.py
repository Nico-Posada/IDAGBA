"""Loader failure signaling shared by the pure checks and the IDA-side loader."""

from __future__ import annotations


class LoadError(Exception):
    """An expected invalid input or failed required IDA operation."""


def require(ok: object, message: str) -> None:
    if not ok:
        raise LoadError(message)
