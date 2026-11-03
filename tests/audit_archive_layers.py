"""Reject reverse CK implementation edges in the installed archive layers.

GNU/LLVM nm's POSIX format is used. Standard-library coincidences are excluded;
all ck::files unresolved references, including const methods and vtables, are
checked after subtracting symbols supplied by the allowed lower archives.
"""
import json
import subprocess
import sys

nm, core, platform, native = sys.argv[1:]

def symbols(archive):
    defined, undefined = set(), set()
    output = subprocess.check_output([nm, "-g", "--format=posix", archive], text=True)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2 or len(fields[1]) != 1:
            continue
        name, kind = fields[:2]
        if "2ck5files" not in name:
            continue
        if kind == "U":
            undefined.add(name)
        elif kind not in ("w", "v"):
            defined.add(name)
    return defined, undefined

c, p, n = map(symbols, (core, platform, native))
reverse = {
    "Core_to_Platform_or_Native": sorted((c[1] - c[0]) & (p[0] | n[0])),
    "Platform_to_Native": sorted((p[1] - p[0] - c[0]) & n[0]),
}
print(json.dumps(reverse, indent=2))
if any(reverse.values()):
    sys.exit(1)
