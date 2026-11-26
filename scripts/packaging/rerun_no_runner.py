"""Reruns the failed jobs of a run when no hosted runner acquired them.

GitHub cancels a macOS arm64 job after about 15 minutes when no hosted runner picks it up, and it
annotates the job with "not acquired by Runner". The workflow rerun-no-runner.yml runs main() after
a failed or cancelled run and reruns that run's failed jobs with `gh run rerun --failed`.

It reruns only when every failed or cancelled job of the attempt ran no step and has that
annotation. A real failure, or a job cancelled by a newer push, gives False. It stops at attempt 3.
Right before the request it also checks that the run is still the attempt it inspected, and that
it is the newest run of its workflow on its branch and event. The rerun API takes no attempt
precondition, so a run that changes in the seconds between that read and the request is not caught.
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


def head_repo(run):
    return (run.get("head_repository") or {}).get("full_name")


PAGE_SIZE = 100
MAX_PAGES = 3


def same_repo(run, other):
    """True when both runs come from the same head repository, and that repository is known."""
    name = head_repo(run)
    return name is not None and head_repo(other) == name


def newest(run, recent_runs):
    """True when no newer run of the same head repository and branch exists.

    GitHub lists runs newest first. A branch filter also matches fork PRs that use the same branch
    name, and those runs cannot supersede this one, so only runs from the same head repository count.
    A run without a head repository is skipped, and a row without one never counts.
    """
    if head_repo(run) is None:
        print("rerun=no reason=unknown head repository")
        return False
    same = [r for r in recent_runs if same_repo(run, r)]
    if not same:
        print("rerun=no reason=run not listed")
        return False
    if same[0].get("id") != run.get("id") or any(r.get("id", 0) > run.get("id", 0) for r in same):
        print("rerun=no reason=newer run exists")
        return False
    return True


def recent_runs_of(run, fetch_page):
    """The runs of the branch, newest first, read one page at a time up to MAX_PAGES.

    Reading stops after the first page that holds a run of the same head repository. A busy branch
    can list many fork runs above it, and those cannot supersede this run. fetch_page(page) returns
    one page of workflow_runs rows.
    """
    if head_repo(run) is None:
        return []
    rows = []
    for page in range(1, MAX_PAGES + 1):
        batch = fetch_page(page)
        rows.extend(batch)
        if len(batch) < PAGE_SIZE or any(same_repo(run, r) for r in batch):
            break
    if page > 1:
        # A run that started while the later pages were read lands on page 1: read it again.
        seen = {r.get("id") for r in rows}
        rows = [r for r in fetch_page(1) if r.get("id") not in seen] + rows
    return rows


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
    recent = recent_runs_of(
        run,
        lambda page: gh_json(
            f"repos/{repo}/actions/workflows/{run['workflow_id']}/runs"
            f"?branch={quote(run.get('head_branch') or '', safe='')}"
            f"&event={quote(run['event'], safe='')}&per_page={PAGE_SIZE}&page={page}"
        )["workflow_runs"],
    )
    if not newest(run, recent):
        return 0
    print("rerun=yes")
    subprocess.run(["gh", "run", "rerun", run_id, "--failed", "--repo", repo], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
