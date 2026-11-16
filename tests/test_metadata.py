from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_manifest_matches_project():
    plugin = json.loads((ROOT / 'ida-plugin.json').read_text())['plugin']
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']
    assert plugin['version'] == project['version']
    assert plugin['requiresPython'] == project['requires-python']
    assert plugin['pythonDependencies'] == project['dependencies']
    assert (ROOT / plugin['entryPoint']).is_file()
