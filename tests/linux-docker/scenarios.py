import json
import os
from pathlib import Path
import shutil
import subprocess


def command(*args, **kwargs):
    return subprocess.run(args, text=True, check=True, capture_output=True, **kwargs).stdout


def check(name, expected, user=None):
    args = ["open-pact-checks", "print_run_all_on_this_machine", "--ignored", "--nocapture", "--test-threads=1"]
    if user:
        args = ["runuser", "-u", user, "--"] + args
    output = command(*args)
    values = {}
    for line in output.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            values[key.split()[-1]] = value
    for key, want in expected.items():
        assert values.get(key) == want, (name, key, values.get(key), want, output)
    print(f"PASS {name}: {expected}", flush=True)


def marker(expected):
    output = command("open-pact-checks", "print_linux_detection_marker", "--ignored", "--nocapture")
    assert f"linux_detection_marker = {expected}" in output, output
    print(f"PASS detection marker {expected}", flush=True)


def shim(name, body):
    path = Path("/tmp/linux-v31-tools") / name
    path.parent.mkdir(exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)


os.environ["PATH"] = "/tmp/linux-v31-tools:" + os.environ["PATH"]
unknown = {key: "unknown" for key in ["password_set", "antimalware_active_threats", "antimalware_full_scan_age_days", "web_protection"]}
check("container without systemd manager", {"os_auto_updates": "unknown", "antimalware_realtime": "off", **unknown})
command("useradd", "-m", "fictional-standard")
command("useradd", "-m", "fictional-admin")
group = "sudo" if Path("/etc/debian_version").exists() else "wheel"
command("usermod", "-aG", group, "fictional-admin")
check("standard account", {"work_account": "standard"}, "fictional-standard")
check("admin group account", {"work_account": "admin"}, "fictional-admin")

# Only the manager is simulated here. apt-config and DNF read real files.
unit = "apt-daily-upgrade.timer" if group == "sudo" else "dnf5-automatic.timer"
def timer(active):
    shim("systemctl", f'case "$*" in *{unit}*) printf "LoadState=loaded\\nUnitFileState=enabled\\nActiveState={active}\\n";; *) echo LoadState=not-found;; esac')

if group == "sudo":
    config = Path("/etc/apt/apt.conf.d/zz-fictional-v31")
    config.write_text('APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Enable "1";\n')
else:
    config = Path("/etc/dnf/automatic.conf")
    config.write_text("[commands]\napply_updates = yes\n")
timer("active")
check("enabled active install timer", {"os_auto_updates": "on"})
config.write_text('APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Enable "0";\n' if group == "sudo" else "[commands]\napply_updates = no\n")
check("installation disabled in config", {"os_auto_updates": "off"})
timer("inactive")
check("inactive timer", {"os_auto_updates": "off"})

# A named process verifies pgrep dispatch. This does not prove fanotify protection.
shutil.copy("/usr/bin/sleep", "/tmp/clamonacc")
process = subprocess.Popen(["/tmp/clamonacc", "120"])
try:
    check("clamonacc process present", {"antimalware_realtime": "on"})
finally:
    process.terminate()
    process.wait()
check("clamonacc process absent", {"antimalware_realtime": "off"})

entry = {"_COMM": "clamonacc", "MESSAGE": "/fictional/sample: Fictional.Test FOUND", "__REALTIME_TIMESTAMP": "1700000000123456"}
shim("journalctl", "cat <<'ENTRY'\n" + json.dumps(entry) + "\nENTRY")
marker("Read(Some(1700000000123456))")
shim("journalctl", "exit 1")
marker("Read(None)")
shim("journalctl", "echo 'Hint: permission denied' >&2; exit 0")
marker("Unknown")

# Real LUKS metadata needs no loop device and contains no volume key.
volume = Path("/tmp/fictional-luks.img")
with volume.open("wb") as handle:
    handle.truncate(32 * 1024 * 1024)
command("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", str(volume), input="fictional-test-key")
metadata = json.loads(command("cryptsetup", "luksDump", "--dump-json-metadata", str(volume)))
assert metadata["keyslots"] and not metadata["tokens"], metadata
root = {"blockdevices": [{"name": "/dev/mapper/fictional-root", "type": "crypt", "fstype": "ext4", "mountpoints": ["/"], "children": [{"name": str(volume), "type": "loop", "fstype": "crypto_LUKS", "mountpoints": [None]}]}]}
shim("lsblk", "cat <<'TREE'\n" + json.dumps(root) + "\nTREE")
Path("/etc/crypttab").write_text("fictional-root UUID=fictional none luks\n")
check("real LUKS with boot passphrase prompt", {"preboot_auth": "user_secret"})
Path("/etc/crypttab").write_text("fictional-root UUID=fictional - tpm2-device=auto\n")
check("boot TPM unlock", {"preboot_auth": "hardware_only"})
Path("/etc/crypttab").write_text("fictional-root UUID=fictional - fido2-device=auto\n")
check("boot FIDO unlock", {"preboot_auth": "hardware_only"})
Path("/etc/crypttab").write_text("fictional-root UUID=fictional - clevis\n")
check("boot clevis unlock", {"preboot_auth": "hardware_only"})
Path("/etc/crypttab").unlink()
check("missing boot mapping", {"preboot_auth": "unknown"})
Path("/etc/crypttab").write_text("fictional-root UUID=fictional none luks\n")
Path("/etc/crypttab").chmod(0o600)
check("unreadable boot configuration", {"preboot_auth": "unknown"}, "fictional-standard")
Path("/etc/crypttab").chmod(0o644)
Path("/tmp/fictional-key").write_text("fictional-test-key")
Path("/etc/crypttab").write_text("fictional-root UUID=fictional /tmp/fictional-key luks\n")
shim("findmnt", "echo /dev/fictional-plain")
root_json = json.dumps(root)
shim("lsblk", "case \"$*\" in *--json*) cat <<'TREE'\n" + root_json + "\nTREE\n;; *) echo \"part ext4\";; esac")
check("keyfile stored on plain filesystem", {"preboot_auth": "none"})
root["blockdevices"][0] = {"name": "/dev/fictional", "type": "part", "fstype": "ext4", "mountpoints": ["/"]}
shim("lsblk", "cat <<'TREE'\n" + json.dumps(root) + "\nTREE")
check("unencrypted root", {"preboot_auth": "none"})
shim("lsblk", "echo 'permission denied' >&2; exit 1")
check("unreadable block tree", {"preboot_auth": "unknown"})
chrome = Path("/opt/google/chrome/chrome")
chrome.parent.mkdir(parents=True, exist_ok=True)
chrome.touch()
profile = Path.home() / ".config/google-chrome/Default"
profile.mkdir(parents=True, exist_ok=True)
(profile / "Preferences").write_text('{"safebrowsing":{"enabled":false}}')
check("Chrome profile disables safe browsing", {"web_protection": "off"})
policy = Path("/etc/opt/chrome/policies/managed")
policy.mkdir(parents=True, exist_ok=True)
(policy / "fictional.json").write_text('{"SafeBrowsingProtectionLevel":1}')
check("Chrome mandatory policy overrides profile", {"web_protection": "on"})
(policy / "conflict.json").write_text('{"SafeBrowsingProtectionLevel":0}')
check("conflicting Chrome mandatory policies", {"web_protection": "unknown"})
print("PASS Linux v3.1 scenarios", flush=True)
