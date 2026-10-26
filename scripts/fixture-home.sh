#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	printf 'usage: %s DIRECTORY\n' "$0" >&2
	exit 2
fi

root=$1
if [ -e "$root" ]; then
	printf 'fixture directory already exists: %s\n' "$root" >&2
	exit 2
fi

python3 - "$root" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
(root / "folders").mkdir(parents=True)
for i in range(20_000):
    (root / "folders" / f"empty-{i}").mkdir()

for i in range(200):
    git = root / "repositories" / f"repo-{i}" / ".git"
    git.mkdir(parents=True)
    (git / "config").write_text('''[remote "origin"]
\turl = git@github.com:example-org/app.git
''')
PY
