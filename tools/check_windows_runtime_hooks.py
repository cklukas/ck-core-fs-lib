#!/usr/bin/env python3
"""Fail-closed source preflight; never executes or excludes native fixtures."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys

def without_comments(text, cmake=False):
    chars = list(text)
    i = 0
    while i < len(text):
        if text.startswith('R"', i) and not cmake:
            opening = text.find('(', i + 2, i + 19)
            if opening >= 0:
                closing = text.find(')' + text[i + 2:opening] + '"', opening + 1)
                if closing >= 0:
                    i = closing + len(text[i + 2:opening]) + 2
                    continue
        # C++ digit separators are not character-literal delimiters.
        if not cmake and text[i] == "'" and re.search(r"\b(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9][0-9a-fA-F.eEpP+-]*)$", text[:i]):
            i += 1
            continue
        if text[i] in ('"', "'"):
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            continue
        end = None
        if cmake and text[i] == '#':
            end = text.find("\n", i)
        elif not cmake and text.startswith('//', i):
            end = text.find("\n", i)
        elif not cmake and text.startswith('/*', i):
            closing = text.find('*/', i + 2)
            end = len(text) if closing < 0 else closing + 2
        if end is not None:
            if end < 0:
                end = len(text)
            for j in range(i, end):
                if chars[j] != "\n":
                    chars[j] = ' '
            i = end
        else:
            i += 1
    return ''.join(chars)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    inventory_path = source / 'tools/windows_legacy_fixture_inventory.json'
    inventory = json.loads(inventory_path.read_text(encoding='utf-8'))
    if inventory.get('schema') != 1 or not inventory.get('required_sources'):
        raise ValueError('Missing reviewed fixture retention inventory')
    pattern = re.compile(r'\b(?:__imp_\w+|VirtualProtect(?:Ex)?|VirtualAlloc(?:Ex)?|WriteProcessMemory|ReadProcessMemory|NtProtectVirtualMemory|FlushInstructionCache|IMAGE_IMPORT_DESCRIPTOR|IMAGE_THUNK_DATA\w*|IMAGE_DIRECTORY_ENTRY_IMPORT|_ReturnAddress|_AddressOfReturnAddress|PAGE_EXECUTE\w*)\b|/alternatename:', re.I)
    findings = []
    retained = []
    hashes = {}
    for rel in inventory['required_sources']:
        path = source / rel
        if not path.is_file() or not re.search(r'\b(?:wmain|main)\s*\(', without_comments(path.read_text(encoding='utf-8'))):
            findings.append({'path': rel, 'line': 0, 'token': 'missing_fixture_entrypoint', 'text': 'Required migrated fixture must remain; removal is not migration'})
        else:
            retained.append(rel)
    paths = {source / 'CMakeLists.txt'}
    for folder in ['src', 'tests', 'cmake']:
        root = source / folder
        if not root.is_dir():
            raise ValueError('Missing source directory: ' + folder)
        paths.update(p for p in root.rglob('*') if p.is_file() and (p.suffix.lower() in {'.cpp', '.hpp', '.h', '.c', '.cc', '.cmake'} or p.name == 'CMakeLists.txt'))
    for path in sorted(paths):
        data = path.read_bytes()
        rel = path.relative_to(source).as_posix()
        hashes[rel] = hashlib.sha256(data).hexdigest()
        clean = without_comments(data.decode('utf-8'), path.suffix == '.cmake' or path.name == 'CMakeLists.txt')
        for number, line in enumerate(clean.splitlines(), 1):
            for match in pattern.finditer(line):
                findings.append({'path': rel, 'line': number, 'token': match.group(), 'text': line.strip()})
    report = {'schema': 1, 'state': 'BLOCKED' if findings else 'SOURCE_SCAN_CLEAN_NOT_NATIVE_QUALIFICATION', 'source': str(source), 'findings': findings, 'finding_files': sorted({x['path'] for x in findings}), 'retained_fixture_sources': retained, 'source_hashes': hashes, 'inventory_sha256': hashlib.sha256(inventory_path.read_bytes()).hexdigest(), 'limits': 'Conservative source check. No native execution, test exclusion or qualification; complete compiled-hook migration still needs coherent full native receipts.'}
    if args.report:
        with args.report.open('x', encoding='utf-8') as output:
            json.dump(report, output, indent=2)
            output.write('\n')
    print(report['state'] + ': ' + str(len(findings)) + ' findings in ' + str(len(report['finding_files'])) + ' files')
    for finding in findings:
        print('{path}:{line}: {token}: {text}'.format(**finding))
    return 1 if findings else 0

if __name__ == '__main__':
    sys.exit(main())
