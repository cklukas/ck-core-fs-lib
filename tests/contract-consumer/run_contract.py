"""Give each installed-library consumer case an explicit isolated fixture root."""
from pathlib import Path
import subprocess
import sys
import tempfile

binary, case, scratch = sys.argv[1:]
root = Path(scratch).resolve()
root.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix=case + "-", dir=root) as work:
    result = subprocess.run([binary, case, work], timeout=25)
    sys.exit(result.returncode)
