"""Checks who may request an identity token in the release workflows. Run with:

    uv run --with pyyaml python -m unittest scripts/packaging/check_workflow_permissions.py

It is not named test_*.py: the plain `unittest discover` run in the release workflow has no PyYAML.
Policy: the sign job of client-release.yml mints the release signature. The jobs that call
authenticode.yml and its own sign job also hold id-token: write, but their token names
authenticode.yml, which the release verification rejects.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
CALL = "./.github/workflows/authenticode.yml"
PINNED = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def token(job: dict) -> bool:
    return "id-token" in (job.get("permissions") or {})


def third_party(job: dict) -> list[str]:
    uses = [step["uses"] for step in job.get("steps", []) if "uses" in step]
    return [use for use in uses if not use.startswith("./")]


class ReleaseTokenTest(unittest.TestCase):
    def setUp(self):
        self.release = load("client-release.yml")
        self.jobs = self.release["jobs"]

    def test_no_workflow_level_token(self):
        self.assertNotIn("id-token", self.release.get("permissions") or {})

    def test_the_token_is_only_in_the_sign_job_and_the_authenticode_calls(self):
        for name, job in self.jobs.items():
            allowed = name == "sign" or job.get("uses") == CALL
            self.assertEqual(token(job), allowed, name)
            if token(job):
                self.assertEqual(job["permissions"]["id-token"], "write", name)

    def test_every_authenticode_call_needs_the_signing_variable(self):
        calls = [name for name, job in self.jobs.items() if job.get("uses") == CALL]
        self.assertEqual(sorted(calls), ["authenticode-exes", "authenticode-msi"])
        for name in calls:
            self.assertIn("vars.ARTIFACT_SIGNING_ACCOUNT != ''", str(self.jobs[name]["if"]), name)

    def test_the_sign_job_pins_every_action_by_commit_sha(self):
        actions = third_party(self.jobs["sign"])
        self.assertTrue(actions)
        for action in actions:
            self.assertRegex(action, PINNED)


class AuthenticodeWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = load("authenticode.yml")
        self.jobs = self.workflow["jobs"]

    def test_it_is_only_called(self):
        # PyYAML reads the key `on` as True.
        triggers = self.workflow.get("on", self.workflow.get(True))
        self.assertEqual(list(triggers), ["workflow_call"])

    def test_exactly_one_job_holds_the_token(self):
        self.assertEqual([name for name, job in self.jobs.items() if token(job)], ["sign"])
        self.assertNotIn("id-token", self.workflow.get("permissions") or {})

    def test_every_action_is_pinned_by_commit_sha(self):
        actions = third_party(self.jobs["sign"])
        self.assertTrue(actions)
        for action in actions:
            self.assertRegex(action, PINNED)

    def test_it_never_signs_a_release_with_cosign(self):
        self.assertNotIn("cosign", (WORKFLOWS / "authenticode.yml").read_text())


if __name__ == "__main__":
    unittest.main()
