"""Tests for rerun_no_runner.decide. Run with:

    uv run python -m unittest discover -s scripts/packaging -p 'test_*.py'
"""

from __future__ import annotations

import importlib.util
import io
import unittest
from contextlib import redirect_stdout
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


REPO = {"full_name": "gaboe/open-pact"}
RUN = {
    "id": 7,
    "run_attempt": 1,
    "status": "completed",
    "workflow_id": 3,
    "event": "push",
    "head_repository": REPO,
}


class CurrentTest(unittest.TestCase):
    def test_the_inspected_completed_attempt_is_current(self):
        self.assertTrue(rerun.current(RUN, 1))

    def test_a_moved_attempt_is_not_current(self):
        self.assertFalse(rerun.current(dict(RUN, run_attempt=2), 1))

    def test_a_run_still_in_progress_is_not_current(self):
        self.assertFalse(rerun.current(dict(RUN, status="in_progress"), 1))


class NewestTest(unittest.TestCase):
    def test_the_run_listed_first_is_newest(self):
        self.assertTrue(rerun.newest(RUN, [{"id": 7, "head_repository": REPO}, {"id": 6, "head_repository": REPO}]))

    def test_a_newer_run_listed_first_is_not_newest(self):
        self.assertFalse(rerun.newest(RUN, [{"id": 8, "head_repository": REPO}, {"id": 7, "head_repository": REPO}]))

    def test_an_empty_list_is_not_newest(self):
        self.assertFalse(rerun.newest(RUN, []))

    def test_a_newer_run_from_another_fork_does_not_count(self):
        run = dict(RUN, head_repository={"full_name": "gaboe/open-pact"})
        fork = {"id": 9, "head_repository": {"full_name": "someone/open-pact"}}
        mine = {"id": 7, "head_repository": {"full_name": "gaboe/open-pact"}}
        self.assertTrue(rerun.newest(run, [fork, mine]))

    def test_a_newer_run_from_the_same_repository_counts(self):
        run = dict(RUN, head_repository={"full_name": "gaboe/open-pact"})
        newer = {"id": 9, "head_repository": {"full_name": "gaboe/open-pact"}}
        mine = {"id": 7, "head_repository": {"full_name": "gaboe/open-pact"}}
        self.assertFalse(rerun.newest(run, [newer, mine]))


class UnknownHeadTest(unittest.TestCase):
    def test_a_run_without_a_head_repository_is_skipped(self):
        run = dict(RUN, head_repository=None)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertFalse(rerun.newest(run, [{"id": 7, "head_repository": None}]))
        self.assertIn("unknown head repository", out.getvalue())

    def test_a_row_without_a_head_repository_never_counts_as_newer(self):
        run = dict(RUN, head_repository={"full_name": "gaboe/open-pact"})
        unknown = {"id": 9, "head_repository": None}
        mine = {"id": 7, "head_repository": {"full_name": "gaboe/open-pact"}}
        self.assertTrue(rerun.newest(run, [unknown, mine]))

    def test_no_page_is_read_for_a_run_without_a_head_repository(self):
        calls = []
        rows = rerun.recent_runs_of(dict(RUN, head_repository=None), lambda page: calls.append(page) or [])
        self.assertEqual((rows, calls), ([], []))


def fork_page(start, size=rerun.PAGE_SIZE):
    return [{"id": start - i, "head_repository": {"full_name": "someone/open-pact"}} for i in range(size)]


class RecentRunsTest(unittest.TestCase):
    def setUp(self):
        self.run = dict(RUN, head_repository={"full_name": "gaboe/open-pact"})
        self.mine = {"id": 7, "head_repository": {"full_name": "gaboe/open-pact"}}

    def reader(self, pages):
        calls = []

        def fetch(page):
            calls.append(page)
            return pages.get(page, [])

        return fetch, calls

    def test_reading_stops_at_the_page_with_the_first_same_repository_run(self):
        fetch, calls = self.reader({
            1: fork_page(1000),
            2: [self.mine] + fork_page(900, rerun.PAGE_SIZE - 1),
            3: fork_page(800),
        })
        rows = rerun.recent_runs_of(self.run, fetch)
        self.assertEqual(calls, [1, 2, 1])
        self.assertTrue(rerun.newest(self.run, rows))

    def test_a_run_that_starts_while_later_pages_are_read_is_seen(self):
        newer = {"id": 1001, "head_repository": {"full_name": "gaboe/open-pact"}}
        reads = []

        def fetch(page):
            reads.append(page)
            if page == 1:
                # The first read of page 1 lists forks only; the second sees the new run on top.
                return fork_page(1000) if reads.count(1) == 1 else [newer] + fork_page(1000, rerun.PAGE_SIZE - 1)
            return [self.mine] + fork_page(900, rerun.PAGE_SIZE - 1)

        rows = rerun.recent_runs_of(self.run, fetch)
        with redirect_stdout(io.StringIO()):
            self.assertFalse(rerun.newest(self.run, rows))

    def test_a_flood_of_fork_runs_is_read_for_three_pages_at_most(self):
        fetch, calls = self.reader({
            1: fork_page(1000),
            2: fork_page(900),
            3: fork_page(800),
            4: [self.mine],
        })
        rows = rerun.recent_runs_of(self.run, fetch)
        self.assertEqual(calls, [1, 2, 3, 1])
        self.assertEqual(len(rows), 3 * rerun.PAGE_SIZE)
        with redirect_stdout(io.StringIO()):
            self.assertFalse(rerun.newest(self.run, rows))

    def test_a_short_page_ends_the_reading(self):
        fetch, calls = self.reader({1: fork_page(1000, 5)})
        rows = rerun.recent_runs_of(self.run, fetch)
        self.assertEqual((len(rows), calls), (5, [1]))


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
