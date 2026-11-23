"""Tests for the release workflows. Run with:

    uv run python -m unittest discover -s scripts/packaging -p 'test_*.py'

client-release.yml is the only workflow that creates, uploads to, checks and
publishes the release. image.yml only adds its notes to that release.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
NOTES_SCRIPT = HERE / "add-image-notes.sh"


def jobs(workflow: str) -> dict[str, str]:
    text = (WORKFLOWS / workflow).read_text()
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z][a-z0-9-]*):\n", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


class OneCreatorTest(unittest.TestCase):
    def test_only_the_client_workflow_creates_or_publishes_a_release(self):
        image = (WORKFLOWS / "image.yml").read_text()
        for forbidden in ("gh release create", "--draft", "--prerelease", "gh release upload"):
            self.assertNotIn(forbidden, image)
        client = (WORKFLOWS / "client-release.yml").read_text()
        self.assertEqual(client.count("gh release create"), 1)
        self.assertEqual(client.count("--draft=false"), 1)

    def test_every_other_workflow_leaves_releases_alone(self):
        for path in WORKFLOWS.glob("*.yml"):
            if path.name == "client-release.yml":
                continue
            self.assertNotIn("gh release create", path.read_text(), path.name)

    def test_the_release_note_job_uses_the_waiting_script(self):
        note = jobs("image.yml")["release-note"]
        self.assertIn("scripts/packaging/add-image-notes.sh", note)
        self.assertIn("actions/checkout", note)


class ReleaseVerifyGateTest(unittest.TestCase):
    def test_the_release_job_verifies_the_signed_sums_before_it_generates_or_uploads(self):
        release = jobs("client-release.yml")["release"]
        self.assertIn("dtolnay/rust-toolchain@1.100.0", release)
        self.assertIn("--example verify_release", release)
        self.assertIn("dist/SHA256SUMS.sigstore.json", release)
        verify = release.index("--example verify_release")
        self.assertLess(verify, release.index("generate-release-metadata.py"))
        self.assertLess(verify, release.index("gh release create"))
        self.assertLess(verify, release.index("gh release upload"))

    def test_the_verify_step_checks_the_exact_files_and_cannot_be_skipped(self):
        release = jobs("client-release.yml")["release"]
        step = re.search(
            r"^      - name: Verify that the release workflow signed SHA256SUMS\n(.*?)(?=^      - |\Z)",
            release,
            flags=re.M | re.S,
        )
        self.assertIsNotNone(step)
        step = step.group(1)
        self.assertRegex(
            step,
            r'(?m)^        run: cargo run --locked --release -p open-pact-client --example verify_release'
            r' -- "\$TAG" "\$GITHUB_REPOSITORY" dist/SHA256SUMS dist/SHA256SUMS\.sigstore\.json$',
        )
        self.assertNotIn("continue-on-error", step)
        self.assertNotIn("always()", step)
        self.assertNotIn("if:", step)

    def test_the_release_job_does_not_keep_the_checkout_token(self):
        release = jobs("client-release.yml")["release"]
        self.assertEqual(release.count("actions/checkout@v6"), 1)
        self.assertIn(
            "      - uses: actions/checkout@v6\n        with:\n          persist-credentials: false\n",
            release,
        )


class ImageVersionGateTest(unittest.TestCase):
    def test_each_image_push_job_checks_the_tag_version_before_it_pushes(self):
        all_jobs = jobs("image.yml")
        for name in ("gateway", "witness"):
            job = all_jobs[name]
            self.assertIn("check-release-version.py", job, name)
            self.assertLess(job.index("check-release-version.py"), job.index("docker/login-action"), name)
            self.assertLess(job.index("check-release-version.py"), job.index("build-push-action"), name)
            gate = job[: job.index("check-release-version.py")]
            self.assertIn("github.ref_type == 'tag'", gate.rsplit("- ", 1)[-1], name)
            self.assertIn('"$GITHUB_REF_NAME"', job, name)


def needs(job: str) -> list[str]:
    match = re.search(r"^    needs: (.+)$", job, flags=re.M)
    if not match:
        return []
    return re.findall(r"[a-z][a-z0-9-]*", match.group(1))


class AssetNameTest(unittest.TestCase):
    def test_the_package_job_keeps_every_asset_name_as_github_stores_it(self):
        package = jobs("client-release.yml")["package"]
        self.assertIn('mv "$path" "${path//\\~/-}"', package)
        rename = package.index('mv "$path"')
        self.assertLess(rename, package.index("sha256sum open-pact-client*"))
        self.assertLess(package.index("^[A-Za-z0-9._-]+$"), package.index("sha256sum open-pact-client*"))


class SigningJobTest(unittest.TestCase):
    """Only a minimal job may mint the Cosign signature that the updater trusts."""

    def setUp(self):
        self.text = (WORKFLOWS / "client-release.yml").read_text()
        self.jobs = jobs("client-release.yml")

    def test_only_the_sign_job_can_request_an_identity_token(self):
        top = self.text.split("\njobs:\n", 1)[0]
        self.assertNotIn("id-token", top)
        self.assertNotIn("write-all", top)
        for name, job in self.jobs.items():
            self.assertNotIn("write-all", job, name)
            if name == "sign":
                self.assertEqual(re.findall(r"id-token: (\w+)", job), ["write"])
            else:
                self.assertNotIn("id-token", job, name)

    def test_only_the_sign_job_runs_cosign(self):
        for name, job in self.jobs.items():
            self.assertEqual("cosign sign-blob" in job, name == "sign", name)
        self.assertEqual(self.text.count("cosign sign-blob"), 2)

    def test_every_action_of_the_sign_job_is_pinned_by_commit_sha(self):
        uses = re.findall(r"^\s+(?:- )?uses: (\S+)", self.jobs["sign"], flags=re.M)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
        self.assertEqual(
            sorted(a.split("@")[0] for a in uses),
            [
                "actions/download-artifact",
                "actions/upload-artifact",
                "sigstore/cosign-installer",
            ],
        )

    def test_the_sign_job_pins_the_cosign_release_and_keeps_no_other_step_type(self):
        sign = self.jobs["sign"]
        self.assertRegex(sign, r"cosign-release: v\d+\.\d+\.\d+\n")
        self.assertNotIn("actions/checkout", sign)
        self.assertEqual(needs(sign), ["package"])

    def test_the_sign_job_checks_every_sum_strictly_before_it_signs(self):
        sign = self.jobs["sign"]
        self.assertIn("sha256sum --check --strict SHA256SUMS", sign)
        self.assertLess(sign.index("sha256sum --check --strict"), sign.index("cosign sign-blob"))

    def test_the_release_job_waits_for_the_signatures_and_holds_no_signing_right(self):
        release = self.jobs["release"]
        self.assertIn("sign", needs(release))
        self.assertIn("name: release-signatures", release)
        self.assertIn("contents: write", release)


MOCK_GH = """#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "$MOCK_DIR/calls"
[ "$1" = release ] || exit 90
case "$2" in
  view)
    n=$(( $(cat "$MOCK_DIR/views" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$MOCK_DIR/views"
    [ -n "${MOCK_APPEAR_AFTER:-}" ] && [ "$n" -gt "$MOCK_APPEAR_AFTER" ] || exit 1
    if [ "${5:-}" = body ]; then cat "$MOCK_DIR/body" 2>/dev/null || true; fi
    ;;
  edit)
    [ "$4" = --notes ] || exit 91
    printf '%s' "$5" > "$MOCK_DIR/body"
    ;;
  *) exit 99 ;;
esac
"""


class NotesScriptTest(unittest.TestCase):
    def run_script(self, appear_after: str | None, body: str = "", attempts: str = "3"):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            gh = tmp_path / "gh"
            gh.write_text(MOCK_GH)
            gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
            (tmp_path / "body").write_text(body)
            env = {
                "PATH": f"{tmp}:{os.environ['PATH']}",
                "MOCK_DIR": tmp,
                "TAG": "v1.2.3",
                "GATEWAY_IMAGE": "example/gateway",
                "WITNESS_IMAGE": "example/witness",
                "GATEWAY_DIGEST": "sha256:" + "a" * 64,
                "WITNESS_DIGEST": "sha256:" + "b" * 64,
                "WAIT_ATTEMPTS": attempts,
                "WAIT_SECONDS": "0",
            }
            if appear_after is not None:
                env["MOCK_APPEAR_AFTER"] = appear_after
            result = subprocess.run(["bash", str(NOTES_SCRIPT)], env=env, capture_output=True, text=True)
            calls = (tmp_path / "calls").read_text().splitlines() if (tmp_path / "calls").exists() else []
            return result, calls, (tmp_path / "body").read_text()

    def test_it_waits_for_the_release_then_only_edits_the_notes(self):
        result, calls, body = self.run_script(appear_after="2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("example/gateway@sha256:" + "a" * 64, body)
        self.assertIn("scripts/verify-release.sh --target witness v1.2.3", body)
        self.assertEqual([c.split()[1] for c in calls if c.startswith("release")].count("edit"), 1)
        for call in calls:
            self.assertNotIn("create", call)
            self.assertNotIn("--draft", call)
            self.assertNotIn("--prerelease", call)

    def test_it_keeps_the_existing_notes_and_adds_the_digests_after_them(self):
        result, _, body = self.run_script(appear_after="0", body="Existing note.")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(body.startswith("Existing note.\n\nImage digests"), body)

    def test_a_second_run_does_not_repeat_the_digests(self):
        _, _, first = self.run_script(appear_after="0")
        result, calls, body = self.run_script(appear_after="0", body=first)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(body, first)
        self.assertFalse([c for c in calls if " edit " in f" {c} "])

    def test_it_fails_clearly_and_creates_nothing_when_no_release_appears(self):
        result, calls, _ = self.run_script(appear_after=None, attempts="4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("client-release.yml", result.stderr)
        self.assertEqual(len(calls), 4)
        self.assertFalse([c for c in calls if " edit " in f" {c} " or " create " in f" {c} "])


VERIFY_SCRIPT = ROOT / "scripts" / "verify-client-release.sh"
MSI = "open-pact-client-x86_64-pc-windows-msvc.msi"
CORE_ASSETS = [
    "open-pact-client-aarch64-apple-darwin",
    "open-pact-client-x86_64-apple-darwin",
    "open-pact-client-x86_64-unknown-linux-musl",
    "open-pact-client-x86_64-pc-windows-msvc.exe",
    "NOTICE",
]
STUB_GH = f"""#!{sys.executable}
import os
import shutil
import sys

args = sys.argv[1:]
if args[:2] == ["release", "view"] and "--jq" in args:
    print(os.environ["MOCK_RELEASE_ASSETS"])
elif args[:2] == ["release", "download"]:
    target = args[args.index("--dir") + 1]
    for index, arg in enumerate(args):
        if arg == "--pattern":
            name = args[index + 1]
            source = os.path.join(os.environ["MOCK_FIXTURES"], name)
            if not os.path.exists(source):
                sys.exit(1)
            shutil.copy(source, os.path.join(target, name))
else:
    sys.exit(99)
"""
STUB_COSIGN = f"""#!{sys.executable}
import os
import sys

with open(os.environ["MOCK_COSIGN_LOG"], "a") as log:
    log.write(sys.argv[-1] + "\\n")
"""


class ClientReleaseMsiTest(unittest.TestCase):
    def setUp(self):
        self.client = jobs("client-release.yml")
        self.text = (WORKFLOWS / "client-release.yml").read_text()

    def test_the_msi_job_builds_from_the_release_client_and_holds_no_identity_token(self):
        msi = self.client["msi"]
        self.assertIn("client-x86_64-pc-windows-msvc", msi)
        self.assertIn("./scripts/packaging/install-wix.ps1", msi)
        self.assertIn("./scripts/packaging/build-msi.ps1", msi)
        self.assertIn("name: client-msi", msi)
        self.assertEqual(needs(msi), ["build"])
        self.assertNotIn("id-token", msi)
        self.assertNotIn("cosign", msi)

    def test_the_package_job_waits_for_the_msi(self):
        self.assertIn("msi", needs(self.client["package"]))

    def test_the_release_checks_the_exact_msi_names_before_it_uploads(self):
        release = self.client["release"]
        self.assertIn(MSI + ".sigstore.json", release)
        self.assertLess(release.index(MSI), release.index("gh release upload"))

    def test_only_the_sign_job_still_runs_cosign(self):
        self.assertEqual(self.text.count("cosign sign-blob"), 2)
        self.assertNotIn("cosign", self.client["msi"])


class MachinePackageWorkflowTest(unittest.TestCase):
    def test_the_pr_job_runs_the_install_sequence_and_keeps_its_fixtures(self):
        job = jobs("windows-packaging.yml")["machine-package"]
        self.assertIn("runs-on: windows-latest", job)
        self.assertIn("./scripts/packaging/install-wix.ps1", job)
        self.assertIn("./packaging/windows/tests/machine-package.ps1", job)
        self.assertIn("name: machine-package-fixtures", job)


class WixInstallerPinTest(unittest.TestCase):
    def test_the_wix_package_is_pinned_by_hash_and_read_from_an_isolated_feed(self):
        text = (HERE / "install-wix.ps1").read_text()
        self.assertRegex(text, r"\$sha256 = '[0-9a-f]{64}'")
        self.assertIn("$version = '5.0.2'", text)
        self.assertIn("<clear />", text)


class VerifyClientReleaseTest(unittest.TestCase):
    def run_verify(self, shipped, listed):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fixtures = tmp_path / "fixtures"
            bin_dir = tmp_path / "bin"
            fixtures.mkdir()
            bin_dir.mkdir()
            for name in shipped:
                (fixtures / name).write_bytes(name.encode())
            sums = "".join(f"{hashlib.sha256((fixtures / name).read_bytes()).hexdigest()}  {name}\n" for name in shipped)
            (fixtures / "SHA256SUMS").write_text(sums)
            for name in [*shipped, "SHA256SUMS"]:
                (fixtures / f"{name}.sigstore.json").write_text("{}")
            for tool, body in (("gh", STUB_GH), ("cosign", STUB_COSIGN)):
                path = bin_dir / tool
                path.write_text(body)
                path.chmod(0o755)
            log = tmp_path / "cosign.log"
            env = {
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "TMPDIR": str(tmp_path),
                "MOCK_RELEASE_ASSETS": "\n".join([*listed, "SHA256SUMS"]),
                "MOCK_FIXTURES": str(fixtures),
                "MOCK_COSIGN_LOG": str(log),
            }
            result = subprocess.run(["bash", str(VERIFY_SCRIPT), "v0.9.0"], env=env, capture_output=True, text=True)
            verified = log.read_text().splitlines() if log.exists() else []
            return result, verified

    def test_a_release_with_the_machine_package_verifies_the_msi_too(self):
        shipped = [*CORE_ASSETS, MSI]
        result, verified = self.run_verify(shipped, shipped)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(MSI, verified)

    def test_an_older_release_without_the_msi_still_verifies(self):
        result, verified = self.run_verify(CORE_ASSETS, CORE_ASSETS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(MSI, verified)

    def test_a_listed_msi_that_was_not_downloaded_fails(self):
        result, _ = self.run_verify(CORE_ASSETS, [*CORE_ASSETS, MSI])
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
