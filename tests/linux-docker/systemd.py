import platform as host_platform
import re
import subprocess
import sys
import time


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        print(result.stdout + result.stderr, flush=True)
        result.check_returncode()
    return result


image, platform = sys.argv[1:]
started = run("docker", "run", "--detach", "--tty", "--env", "container=docker", "--privileged", "--cgroupns=private", "--platform", platform,
              "--tmpfs", "/run", "--tmpfs", "/run/lock", image, "/sbin/init", check=False)
if started.returncode:
    print("SKIP systemd container start: " + started.stderr, flush=True)
    sys.exit(0)
container = started.stdout.strip()


def execute(*args, check=True):
    result = run("docker", "exec", container, *args, check=check)
    if result.stdout:
        print(result.stdout, end="", flush=True)
    return result


try:
    ready = False
    for _ in range(30):
        if execute("systemctl", "is-active", "multi-user.target", check=False).returncode == 0:
            ready = True
            break
        if run("docker", "inspect", "--format", "{{.State.Running}}", container).stdout.strip() == "false":
            break
        time.sleep(1)
    if not ready:
        logs = run("docker", "logs", container, check=False)
        state = run("docker", "inspect", "--format", "{{json .State}}", container, check=False)
        print("SKIP systemd manager unavailable: " + logs.stdout + logs.stderr + state.stdout, flush=True)
        sys.exit(0)
    if platform == "linux/amd64" and host_platform.machine().lower() in ("arm64", "aarch64"):
        # The emulator needs writable executable memory in these test-container services.
        for service in ["systemd-logind.service", "systemd-journald.service"]:
            code = "from pathlib import Path; p=Path('/etc/systemd/system/" + service + ".d/fictional-emulation.conf'); p.parent.mkdir(parents=True, exist_ok=True); p.write_text('[Service]\\nMemoryDenyWriteExecute=no\\n')"
            execute("python3", "-c", code)
        execute("systemctl", "daemon-reload")
        execute("systemctl", "reset-failed", "systemd-logind.service", "systemd-journald.service")
        execute("systemctl", "restart", "systemd-journald.service", "systemd-logind.service")
        print("Test container: MemoryDenyWriteExecute=no for logind and journald under x86-on-ARM emulation", flush=True)
    execute("useradd", "--create-home", "fictional-timer")
    uid = execute("id", "-u", "fictional-timer").stdout.strip()
    execute("loginctl", "enable-linger", "fictional-timer")
    execute("systemctl", "start", f"user@{uid}.service")
    home = "/home/fictional-timer/pact"
    user_args = ["runuser", "-u", "fictional-timer", "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}"]
    execute(*user_args, f"OPEN_PACT_SCHEDULE_FIXTURE={home}", "open-pact-checks", "prepare_linux_schedule_home", "--ignored", "--nocapture")
    installed = execute(*user_args, "open-pact-client", "--home", home, "schedule", "install", "--collector", "https://collector.example.org/status", "--vpn-probe", "127.0.0.1:9").stdout
    task = re.search(r"Installed ([^ ]+)\.", installed).group(1)
    assert execute(*user_args, "systemctl", "--user", "is-active", task + ".timer").stdout.strip() == "active"
    execute(*user_args, "systemctl", "--user", "start", task + ".service")
    assert execute(*user_args, "systemctl", "--user", "show", task + ".service", "--property=Result", "--value").stdout.strip() == "success"
    execute(*user_args, "open-pact-client", "--home", home, "schedule", "uninstall")
    print("PASS native systemd user timer install, run off VPN, and uninstall", flush=True)

    def marker():
        execute("journalctl", "--sync")
        output = execute("open-pact-checks", "print_linux_detection_marker", "--ignored", "--nocapture").stdout
        match = re.search(r"linux_detection_marker = Read\(Some\((\d+)\)\)", output)
        assert match, output
        return int(match.group(1))

    def detection(message):
        code = "import ctypes; ctypes.CDLL(None).prctl(15,b'clamonacc',0,0,0); lib=ctypes.CDLL('libsystemd.so.0'); assert lib.sd_journal_send(" + repr(("MESSAGE=/fictional/" + message + ": Fictional.Test FOUND").encode()) + ",None)==0"
        execute("python3", "-c", code)

    initial = execute("open-pact-checks", "print_linux_detection_marker", "--ignored", "--nocapture").stdout
    assert "linux_detection_marker = Read(None)" in initial, initial
    detection("first")
    first = marker()
    detection("second")
    second = marker()
    assert second > first, (first, second)
    print("PASS trusted system journal detects advancing ClamAV fixture records", flush=True)
finally:
    run("docker", "rm", "--force", container, check=False)
