"""Require every declared public C export and reject private C++ ABI leakage."""
from pathlib import Path
import re
import subprocess
import sys

nm, library, headers = sys.argv[1:]
declared = set()
for header in Path(headers).glob("*.h"):
    declared.update(re.findall(
        r"(?m)^[A-Z][A-Z0-9_]*API\s+[^;{}]*?\b(ck[a-z0-9_]+)\s*\(",
        header.read_text(encoding="utf-8")))
if not declared:
    raise RuntimeError("no public C declarations found")
raw = subprocess.check_output([nm, "-D", "--defined-only", library], text=True)
symbols = {line.split()[-1] for line in raw.splitlines() if line.split()}
demangled = subprocess.check_output(
    [nm, "-D", "-C", "--defined-only", library], text=True)
private = [line for line in demangled.splitlines() if "ck::files::" in line]
missing = sorted(declared - symbols)
undeclared = sorted(symbol for symbol in symbols if symbol.startswith("ck")
                    and symbol not in declared)
if private or missing or undeclared:
    raise RuntimeError(f"ELF export mismatch: private={private}, "
                       f"missing={missing}, undeclared={undeclared}")
print(f"ELF export audit PASS: {len(declared)} public C functions; "
      "zero private C++ exports, including template arguments")
