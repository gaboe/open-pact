import subprocess
import sys

image, platform = sys.argv[1:]
invalid = image + "-fictional-invalid-init"
subprocess.run(
    ["docker", "build", "--platform", platform, "-t", invalid, "-"],
    input=f'FROM {image}\nENTRYPOINT ["/fictional/missing-init"]\n',
    text=True, check=True,
)
try:
    result = subprocess.run(
        [sys.executable, "tests/linux-docker/systemd.py", invalid, platform],
        text=True, capture_output=True, check=True,
    )
    print(result.stdout, end="", flush=True)
    assert "SKIP systemd container start" in result.stdout, result.stdout + result.stderr
    containers = subprocess.check_output(
        ["docker", "ps", "--all", "--filter", "ancestor=" + invalid, "--format", "{{.ID}}"],
        text=True,
    ).split()
    assert not containers, f"Failed start left containers: {containers}"
    print("PASS failed systemd start removes its container", flush=True)
finally:
    containers = subprocess.check_output(
        ["docker", "ps", "--all", "--filter", "ancestor=" + invalid, "--format", "{{.ID}}"],
        text=True,
    ).split()
    for container in containers:
        subprocess.run(["docker", "rm", "--force", container], check=True)
    subprocess.run(["docker", "image", "rm", invalid], check=True)
