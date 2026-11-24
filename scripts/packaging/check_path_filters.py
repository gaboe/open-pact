# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml"]
# ///
"""Checks the path filters of the CI workflows.

GitHub reads a `paths` list in order. A pattern that matches a changed file sets it in or out,
so the last matching pattern wins, and a `!` pattern takes files out. A `paths-ignore` list skips
a run when every changed file matches it. Run the tests from the repository root:

    uv run --with pyyaml python -m unittest scripts/packaging/check_path_filters.py

The file name does not start with `test_`, so the plain discovery run in CI does not load it.
"""

import posixpath
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
EVENTS = ("push", "pull_request")
DESKTOP = "desktop.yml"
CLIENT_WORKFLOWS = ("windows-checks.yml", "windows-packaging.yml", "contracts.yml")
CRATES = ("crates/open-pact-core", "crates/open-pact-client")
INCLUDE = re.compile(r'include_(?:str|bytes)!\(\s*"([^"]+)"\s*\)')

# Changes that the client workflows must start for.
CLIENT_RUNS_FOR = [
    "crates/open-pact-client/src/lib.rs",
    "crates/open-pact-core/src/lib.rs",
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "packaging/windows/x.wxs",
    "scripts/packaging/build-msi.ps1",
    ".github/workflows/windows-checks.yml",
    "a-new-top-level-file.txt",
]

# Changes that the client workflows must skip.
CLIENT_SKIPS_FOR = [
    "crates/open-pact-gateway/src/main.rs",
    "crates/open-pact-witness/src/main.rs",
    "deploy/helm/open-pact/values.yaml",
    "docs/gateway.md",
    "CHANGELOG-draft.md",
    "desktop/crates/runner/src/lib.rs",
]


def glob_regex(pattern):
    """Translate a GitHub path pattern: ** crosses folders, * and ? do not."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def pattern_matches(pattern, path):
    return glob_regex(pattern).fullmatch(path) is not None


def list_matches(patterns, path):
    """True when the last pattern that matches the path is not a negation."""
    matched = False
    for pattern in patterns:
        if pattern.startswith("!"):
            if pattern_matches(pattern[1:], path):
                matched = False
        elif pattern_matches(pattern, path):
            matched = True
    return matched


def triggers(workflow):
    doc = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    # PyYAML reads the bare key `on` as the boolean True.
    return doc.get("on", doc.get(True))


def runs(workflow, event, changed):
    """Whether GitHub starts the workflow for this event and these changed files."""
    on = triggers(workflow)
    if event not in on:
        return False
    spec = on[event] or {}
    if "paths" in spec:
        return any(list_matches(spec["paths"], path) for path in changed)
    if "paths-ignore" in spec:
        return any(not list_matches(spec["paths-ignore"], path) for path in changed)
    return True


def include_targets():
    """Files that the core and client compile in from outside their own folder."""
    targets = set()
    for crate in CRATES:
        for source in (ROOT / crate).rglob("*.rs"):
            folder = source.parent.relative_to(ROOT).as_posix()
            for found in INCLUDE.finditer(source.read_text(encoding="utf-8")):
                target = posixpath.normpath(posixpath.join(folder, found.group(1)))
                if not any(target.startswith(c + "/") for c in CRATES):
                    targets.add(target)
    return targets


class PathFilterTest(unittest.TestCase):
    def assertRuns(self, workflow, changed):
        for event in EVENTS:
            with self.subTest(workflow=workflow, event=event, changed=changed):
                self.assertTrue(runs(workflow, event, changed))

    def assertSkips(self, workflow, changed):
        for event in EVENTS:
            with self.subTest(workflow=workflow, event=event, changed=changed):
                self.assertFalse(runs(workflow, event, changed))

    def test_include_targets_outside_the_crates_run_desktop_and_client_workflows(self):
        targets = include_targets()
        self.assertLessEqual({"examples/manifest.toml", "PAPER.md", "docs/controls.md"}, targets)
        for target in sorted(targets):
            for workflow in (DESKTOP, *CLIENT_WORKFLOWS):
                self.assertRuns(workflow, [target])

    def test_client_files_run_each_client_workflow(self):
        for path in CLIENT_RUNS_FOR:
            for workflow in CLIENT_WORKFLOWS:
                self.assertRuns(workflow, [path])

    def test_other_files_skip_each_client_workflow(self):
        for path in CLIENT_SKIPS_FOR:
            for workflow in CLIENT_WORKFLOWS:
                self.assertSkips(workflow, [path])

    def test_a_change_of_only_skipped_files_skips_the_client_workflows(self):
        for workflow in CLIENT_WORKFLOWS:
            self.assertSkips(workflow, CLIENT_SKIPS_FOR)

    def test_desktop_runs_for_core_and_client_inputs(self):
        self.assertSkips(DESKTOP, ["crates/open-pact-gateway/src/main.rs"])
        self.assertRuns(DESKTOP, ["examples/manifest.toml"])
        self.assertRuns(DESKTOP, ["crates/open-pact-core/src/lib.rs"])

    def test_patterns_apply_in_order(self):
        self.assertFalse(list_matches(["**", "!desktop/**"], "desktop/a.rs"))
        self.assertTrue(list_matches(["!desktop/**", "**"], "desktop/a.rs"))
        self.assertTrue(list_matches(["**", "!desktop/**", "desktop/keep.rs"], "desktop/keep.rs"))

    def test_star_stays_in_one_folder_and_double_star_crosses_folders(self):
        self.assertTrue(pattern_matches("docs/**", "docs/release-notes/v1.md"))
        self.assertFalse(pattern_matches("*.md", "docs/a.md"))
        self.assertTrue(pattern_matches("*.md", "a.md"))
        self.assertTrue(pattern_matches("a?c", "abc"))
        self.assertFalse(pattern_matches("a?c", "a/c"))

    def test_a_dot_in_a_pattern_is_literal(self):
        self.assertFalse(pattern_matches("PAPER.md", "PAPERxmd"))


if __name__ == "__main__":
    unittest.main()
