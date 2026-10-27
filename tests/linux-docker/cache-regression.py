import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid


def command(*args, **kwargs):
    return subprocess.run(args, text=True, check=True, capture_output=True, **kwargs).stdout.strip()


dockerfile = (Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("Dockerfile")).resolve()
platform = os.environ.get("PLATFORM", "linux/arm64")
image = "open-pact-cache-regression-" + uuid.uuid4().hex
try:
    with tempfile.TemporaryDirectory(prefix="fictional-cache-") as directory:
        root = Path(directory)
        source = root / "crates/open-pact-client/src/main.rs"
        source.parent.mkdir(parents=True)
        (root / "examples").mkdir()
        (root / "PAPER.md").touch()
        (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/open-pact-client"]\nresolver = "2"\n')
        (root / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "open-pact-client"\nversion = "0.0.0"\n')
        (source.parent.parent / "Cargo.toml").write_text('[package]\nname = "open-pact-client"\nversion = "0.0.0"\nedition = "2021"\n')
        for value in ["first", "second"]:
            source.write_text(f'fn main() {{\n    println!("{value}");\n}}\n')
            os.utime(source, (1_600_000_000, 1_600_000_000))
            result = subprocess.run(["docker", "build", "--platform", platform, "--target", "build", "-f", str(dockerfile), "-t", image, str(root)], text=True, capture_output=True)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            actual = command("docker", "run", "--rm", "--platform", platform, image, "/open-pact-client")
            assert actual == value, (value, actual)
            print(f"PASS exact source with preserved timestamp: {actual}", flush=True)
finally:
    subprocess.run(["docker", "image", "rm", "-f", image], check=False, capture_output=True)
