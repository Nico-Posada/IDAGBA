from __future__ import annotations


class LoadError(Exception):
    """Bad input, or an IDA call that had to work and did not."""


def require(ok: object, message: str) -> None:
    if not ok:
        raise LoadError(message)
