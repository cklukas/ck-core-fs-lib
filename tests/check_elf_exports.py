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
missing = sorted(declared - symbols)
# Standard-library instantiations can interpose another SDK too. Checking only
# names containing ck::files misses those default-visible facade definitions.
unexpected = sorted(symbols - declared)
if missing or unexpected:
    raise RuntimeError(f"ELF export mismatch: missing={missing}, "
                       f"unexpected_count={len(unexpected)}, "
                       f"unexpected={unexpected[:20]}")
print(f"ELF export audit PASS: {len(declared)} public C functions; "
      "zero private C++ exports, including template arguments")
