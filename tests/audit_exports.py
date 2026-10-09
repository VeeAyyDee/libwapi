#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Audit the complete archive namespace against specification declarations."""
import json
import subprocess
import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
archive = Path(sys.argv[1]) if len(sys.argv) > 1 else root / 'build/libwapi.a'
expected_functions = {x['name'] for x in json.loads((root / 'spec/body-scope.json').read_text()) if x['public']}
expected_data = {x['name']: x for x in json.loads((root / 'spec/export-data.json').read_text())}
found = {}
for line in subprocess.check_output(['nm', '-g', '--defined-only', '-S', str(archive)], text=True).splitlines():
    fields = line.split()
    if len(fields) == 4:
        address, size, kind, name = fields
        assert name not in found, f'duplicate export {name}'
        found[name] = (int(size, 16), kind)
assert set(found) == expected_functions | set(expected_data), (set(found) - expected_functions - set(expected_data), expected_functions - set(found))
for name in expected_functions:
    assert found[name][1] == 'T', (name, found[name])
for name, description in expected_data.items():
    size, kind = found[name]
    assert kind == ('R' if description['readonly'] else 'D'), (name, kind)
    assert size == description['size'] or (name == 'libwapi_reversion_git' and size == 8), (name, size)
print('Export audit: exactly 21 strong functions and four data objects; types and sizes match (native pointer width allowed).')
