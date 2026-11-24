"""Tests for rerun_no_runner.decide. Run with:

    uv run python -m unittest discover -s scripts/packaging -p 'test_*.py'
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rerun_no_runner", HERE / "rerun_no_runner.py")
rerun = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rerun)

NO_RUNNER = {
    "message": "The job was not acquired by Runner of type hosted even after multiple attempts",
}
OTHER_NOTE = {"message": "Process completed with exit code 1."}


def job(job_id, conclusion, steps=None, name="job"):
    return {"id": job_id, "name": name, "conclusion": conclusion, "steps": steps or []}


def step(conclusion, status="completed"):
    return {"name": "step", "status": status, "conclusion": conclusion}


SUCCESS = job(900, "success", [step("success")], name="linux")


RUN = {"id": 7, "run_attempt": 1, "status": "completed", "workflow_id": 3, "event": "push"}


class CurrentTest(unittest.TestCase):
    def test_the_inspected_completed_attempt_is_current(self):
        self.assertTrue(rerun.current(RUN, 1))

    def test_a_moved_attempt_is_not_current(self):
        self.assertFalse(rerun.current(dict(RUN, run_attempt=2), 1))

    def test_a_run_still_in_progress_is_not_current(self):
        self.assertFalse(rerun.current(dict(RUN, status="in_progress"), 1))


class NewestTest(unittest.TestCase):
    def test_the_run_listed_first_is_newest(self):
        self.assertTrue(rerun.newest(RUN, [{"id": 7}, {"id": 6}]))

    def test_a_newer_run_listed_first_is_not_newest(self):
        self.assertFalse(rerun.newest(RUN, [{"id": 8}, {"id": 7}]))

    def test_an_empty_list_is_not_newest(self):
        self.assertFalse(rerun.newest(RUN, []))


class DecideTest(unittest.TestCase):
    def test_a_no_runner_job_alone_among_successes_reruns(self):
        jobs = [job(1, "failure", name="macos-arm64"), SUCCESS]
        self.assertTrue(rerun.decide(jobs, {1: [NO_RUNNER]}, run_attempt=1))

    def test_no_rerun_at_attempt_three(self):
        jobs = [job(1, "failure", name="macos-arm64"), SUCCESS]
        self.assertFalse(rerun.decide(jobs, {1: [NO_RUNNER]}, run_attempt=3))

    def test_a_cancelled_job_without_the_annotation_does_not_rerun(self):
        # A newer push to the same pull request cancels the older run's jobs.
        jobs = [job(1, "cancelled", name="macos-arm64"), SUCCESS]
        self.assertFalse(rerun.decide(jobs, {}, run_attempt=1))

    def test_a_no_runner_job_next_to_a_real_failure_does_not_rerun(self):
        real = job(2, "failure", [step("success"), step("failure")], name="linux")
        jobs = [job(1, "failure", name="macos-arm64"), real]
        self.assertFalse(rerun.decide(jobs, {1: [NO_RUNNER]}, run_attempt=1))

    def test_a_run_with_no_failed_job_does_not_rerun(self):
        self.assertFalse(rerun.decide([SUCCESS], {}, run_attempt=1))

    def test_a_failed_job_that_ran_a_step_does_not_rerun(self):
        ran = job(1, "failure", [step("success"), step("failure")], name="macos-arm64")
        self.assertFalse(rerun.decide([ran, SUCCESS], {1: [NO_RUNNER]}, run_attempt=1))

    def test_skipped_steps_do_not_count_as_ran(self):
        skipped = job(1, "cancelled", [step("skipped")], name="macos-arm64")
        self.assertTrue(rerun.decide([skipped, SUCCESS], {1: [NO_RUNNER]}, run_attempt=2))

    def test_an_unrelated_annotation_does_not_count(self):
        jobs = [job(1, "failure", name="macos-arm64"), SUCCESS]
        self.assertFalse(rerun.decide(jobs, {1: [OTHER_NOTE]}, run_attempt=1))


if __name__ == "__main__":
    unittest.main()
