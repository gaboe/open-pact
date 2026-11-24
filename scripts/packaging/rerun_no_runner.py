"""Reruns the failed jobs of a run when no hosted runner acquired them.

GitHub cancels a macOS arm64 job after about 15 minutes when no hosted runner picks it up, and it
annotates the job with "not acquired by Runner". The workflow rerun-no-runner.yml runs main() after
a failed or cancelled run and reruns that run's failed jobs with `gh run rerun --failed`.

It reruns only when every failed or cancelled job of the attempt ran no step and has that
annotation. A real failure, or a job cancelled by a newer push, gives False. It stops at attempt 3.
Right before the request it also checks that the run is still the attempt it inspected, and that
it is the newest run of its workflow on its branch and event.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from urllib.parse import quote

MAX_ATTEMPT = 3
FAILED = ("failure", "cancelled")
NO_RUNNER = "not acquired by Runner"


def failed_jobs(jobs):
    return [job for job in jobs if job.get("conclusion") in FAILED]


def ran_a_step(job):
    return any(
        step.get("status") == "completed" and step.get("conclusion") != "skipped"
        for step in job.get("steps") or []
    )


def no_runner(job, annotations_by_job_id):
    if ran_a_step(job):
        return False
    notes = annotations_by_job_id.get(job["id"], [])
    return any(NO_RUNNER in (note.get("message") or "") for note in notes)


def decide(jobs, annotations_by_job_id, run_attempt):
    failed = failed_jobs(jobs)
    if run_attempt >= MAX_ATTEMPT or not failed:
        return False
    return all(no_runner(job, annotations_by_job_id) for job in failed)


def current(run, attempt):
    """True while the run is still the attempt that was inspected, and it has finished."""
    return run.get("run_attempt") == attempt and run.get("status") == "completed"


def newest(run, recent_runs):
    """True when the run is first in its workflow's recent runs, which GitHub lists newest first."""
    return bool(recent_runs) and recent_runs[0].get("id") == run.get("id")


def gh_api(*args):
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise subprocess.CalledProcessError(proc.returncode, proc.args, proc.stdout, proc.stderr)
    return proc.stdout


def gh_items(path, jq):
    """One compact JSON value per line, across every page."""
    out = gh_api("--paginate", "--jq", jq, path)
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def gh_json(path):
    return json.loads(gh_api(path))


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    run_id = os.environ["RUN_ID"]
    attempt = int(os.environ["RUN_ATTEMPT"])
    jobs = gh_items(
        f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100",
        ".jobs[] | tojson",
    )
    failed = failed_jobs(jobs)
    annotations = {
        job["id"]: gh_items(
            f"repos/{repo}/check-runs/{job['id']}/annotations?per_page=100",
            ".[] | tojson",
        )
        for job in failed
    }
    names = ", ".join(job.get("name", str(job["id"])) for job in failed) or "none"
    print(f"attempt={attempt} failed jobs: {names}")
    if not decide(jobs, annotations, attempt):
        print("rerun=no reason=not qualifying")
        return 0
    # Read the run again after the jobs: a newer attempt or a newer run can start meanwhile.
    run = gh_json(f"repos/{repo}/actions/runs/{run_id}")
    if not current(run, attempt):
        reason = "attempt moved" if run.get("run_attempt") != attempt else "run not completed"
        print(f"rerun=no reason={reason}")
        return 0
    recent = gh_json(
        f"repos/{repo}/actions/workflows/{run['workflow_id']}/runs"
        f"?branch={quote(run.get('head_branch') or '', safe='')}"
        f"&event={quote(run['event'], safe='')}&per_page=5"
    )["workflow_runs"]
    if not newest(run, recent):
        print("rerun=no reason=newer run exists")
        return 0
    print("rerun=yes")
    subprocess.run(["gh", "run", "rerun", run_id, "--failed", "--repo", repo], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
