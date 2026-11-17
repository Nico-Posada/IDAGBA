"""Start idalib once, against an isolated IDAUSR whose only plugin is this package."""

from __future__ import annotations

import atexit
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parent.parent


def _ida_directory() -> str | None:
    if os.environ.get('IDADIR'):
        return os.environ['IDADIR']

    config = Path.home() / '.idapro' / 'ida-config.json'
    if config.is_file():
        return json.loads(config.read_text()).get('Paths', {}).get('ida-install-dir') or None

    return None


def start() -> None:
    """Start the IDA kernel, or skip the importing test module when IDA is unavailable."""
    directory = _ida_directory()
    if directory is None:
        pytest.skip('no IDA installation: set IDADIR or ~/.idapro/ida-config.json', allow_module_level=True)
    user = Path(tempfile.mkdtemp(prefix='idagba-idausr-'))
    atexit.register(shutil.rmtree, user, ignore_errors=True)
    (user / 'plugins').mkdir()
    (user / 'plugins' / 'idagba').symlink_to(PACKAGE_ROOT, target_is_directory=True)
    home = Path.home() / '.idapro'
    for source in (home / 'ida.reg', *home.glob('*.hexlic')):
        if source.is_file():
            shutil.copy2(source, user / source.name)

    os.environ.update(IDADIR=directory, IDAUSR=str(user), IDA_NO_HISTORY='1', QT_QPA_PLATFORM='offscreen')
    # Hermetic: IDAPython must use this interpreter's packages, not IDA's own venv.
    os.environ.pop('IDAPYTHON_VENV_EXECUTABLE', None)
    try:
        # Kernel start: loads the plugin, which installs the loader link.
        import idapro  # noqa: F401, PLC0415
    except ImportError as exc:
        pytest.skip(f'idalib is unavailable: {exc}', allow_module_level=True)
