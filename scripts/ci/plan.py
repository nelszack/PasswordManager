"""Select CI suites and reuse only a successful, identical-tree PR run."""
import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request
import zipfile

SUITES = ("rust", "extension", "browser", "cloud", "fuzz", "rust_audit", "npm_audit")


def select(paths):
    selected = set()
    for path in paths:
        if (path in ("README.md", "SECURITY.md", "LICENSE", "bugs.txt")
                or path.endswith(".md") and path.startswith(("docs/", "vendor/", "fuzz/", "sync-server/"))):
            continue
        if path.startswith(".github/") or path.startswith("scripts/ci/"):
            return set(SUITES)
        if path in ("Cargo.toml", "Cargo.lock"):
            selected.update(SUITES)
        elif path.startswith(("src/gui/", "assets/")) or path == "src/desktop.rs":
            selected.add("rust")
        elif path.startswith(("src/", "tests/", "vendor/")):
            selected.update(("rust", "browser", "cloud", "fuzz"))
        elif path.startswith("fuzz/"):
            selected.add("fuzz")
            if path in ("fuzz/Cargo.toml", "fuzz/Cargo.lock"):
                selected.add("rust_audit")
        elif path.startswith("sync-server/") or path == "scripts/test_cloud_sync.py":
            selected.add("cloud")
        elif path.startswith("extension/"):
            selected.update(("extension", "browser"))
            if path in ("extension/command_contract.js", "extension/command_contract.d.ts"):
                selected.add("rust")
        elif path in ("package.json", "package-lock.json"):
            selected.update(("extension", "browser", "npm_audit"))
        elif path == "playwright.config.cjs":
            selected.add("browser")
        elif path == "scripts/build_extension.cjs":
            selected.update(("extension", "browser", "rust"))
        elif path == "scripts/validate.cjs":
            selected.update(("extension", "rust"))
        elif path == "scripts/test_gui_accessibility.py":
            selected.add("rust")
        elif path in ("docs/commands.html", "docs/commands.template.html"):
            selected.add("rust")
        else:
            # New build inputs must not silently bypass validation.
            return set(SUITES)
    return selected


def git(*args):
    return subprocess.check_output(["git", *args])


def changed_paths(event_name, event):
    if event_name == "pull_request":
        pr = event["pull_request"]
        revisions = f'{pr["base"]["sha"]}...{pr["head"]["sha"]}'
    elif event_name == "push" and event.get("before", "").strip("0"):
        revisions = f'{event["before"]}..{event["after"]}'
    else:
        return None
    # Include both sides of renames and all deletions, without API pagination limits.
    return git("diff", "--no-renames", "--name-only", "-z", revisions).decode().split("\0")[:-1]


class ArtifactRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, *args, **kwargs):
        redirected = super().redirect_request(request, *args, **kwargs)
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected


class GitHub:
    def __call__(self, route, raw=False):
        request = urllib.request.Request(
            f'{os.environ.get("GITHUB_API_URL", "https://api.github.com")}/{route}',
            headers={"Authorization": f'Bearer {os.environ["GH_TOKEN"]}',
                     "Accept": "application/vnd.github+json"},
        )
        with urllib.request.build_opener(ArtifactRedirect()).open(request, timeout=20) as response:
            data = response.read()
        return data if raw else json.loads(data)


def reusable_run(api, repo, sha, tree, run_id, workflow, required):
    """Only merged, same-repository PRs with an uploaded successful-run proof qualify."""
    prefix = f"repos/{repo}"
    prs = api(f"{prefix}/commits/{sha}/pulls?per_page=100")
    heads = {pr["head"]["sha"] for pr in prs
             if pr.get("merged_at") and pr.get("merge_commit_sha") == sha
             and (pr["head"].get("repo") or {}).get("full_name") == repo}
    if not heads:
        return None
    workflow_id = api(f"{prefix}/actions/runs/{run_id}")["workflow_id"]
    for head in heads:
        query = urllib.parse.urlencode({"event": "pull_request", "status": "success",
                                       "head_sha": head, "per_page": 100})
        runs = api(f"{prefix}/actions/workflows/{workflow_id}/runs?{query}")["workflow_runs"]
        for run in runs:
            if (run["event"] != "pull_request" or run["conclusion"] != "success"
                    or run["head_sha"] != head
                    or (run.get("head_repository") or {}).get("full_name") != repo):
                continue
            artifacts = api(f'{prefix}/actions/runs/{run["id"]}/artifacts?per_page=100')["artifacts"]
            for artifact in artifacts:
                if artifact["name"] != f"{workflow}-tested-tree" or artifact["expired"]:
                    continue
                archive = api(f'{prefix}/actions/artifacts/{artifact["id"]}/zip', raw=True)
                with zipfile.ZipFile(io.BytesIO(archive)) as files:
                    proof = json.loads(files.read("tested-tree.json"))
                tested = proof.pop("suites", [])
                if (required <= set(tested) and proof == {"tree": tree, "run_id": str(run["id"]),
                             "run_attempt": str(run["run_attempt"]), "repository": repo,
                             "workflow": workflow, "event": "pull_request"}):
                    return run["html_url"]
    return None


WORKFLOW_JOBS = {
    "ci": {"test": "rust", "extension": "extension", "cloud-sync": "cloud",
           "mac-architectures": "rust", "browser-e2e": "browser", "coverage": "rust"},
    "security": {"rustsec": "rust_audit", "npm-audit": "npm_audit"},
    "fuzz": {"fuzz": "fuzz"},
}


def check_results(jobs, workflow, event):
    if jobs["plan"]["result"] != "success":
        raise ValueError("CI planning failed")
    selected = jobs["plan"]["outputs"]
    expected = {name for name, suite in WORKFLOW_JOBS[workflow].items()
                if selected[suite] == "true"}
    if workflow == "security" and event == "pull_request" and expected:
        expected.add("dependency-review")
    for name, job in jobs.items():
        allowed = ("success",) if name in expected else ("success", "skipped")
        if job["result"] not in allowed:
            raise ValueError(f"{name}: {job['result']}")
    if expected - jobs.keys():
        raise ValueError(f"Missing checks: {expected - jobs.keys()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", choices=("ci", "security", "fuzz"), required=True)
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--finish", action="store_true")
    args = parser.parse_args()
    event_name = os.environ["GITHUB_EVENT_NAME"]
    if args.finish:
        check_results(json.loads(os.environ["RESULTS"]), args.workflow, event_name)
        return
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    if args.record:
        proof = {"tree": tree, "run_id": os.environ["GITHUB_RUN_ID"],
                 "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                 "repository": os.environ["GITHUB_REPOSITORY"],
                 "workflow": args.workflow, "event": event_name,
                 "suites": sorted(suite for suite in set(WORKFLOW_JOBS[args.workflow].values())
                                  if json.loads(os.environ["SELECTED"])[suite] == "true")}
        Path("tested-tree.json").write_text(json.dumps(proof) + "\n")
        return
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    try:
        paths = changed_paths(event_name, event)
        selected = select(paths) if paths is not None else set(SUITES)
    except (subprocess.CalledProcessError, KeyError, UnicodeError) as error:
        print(f"Could not determine changed files; running all suites: {error}")
        selected = set(SUITES)
    reused = None
    if event_name == "push" and os.environ["GITHUB_REF"] == "refs/heads/main":
        try:
            required = selected & set(WORKFLOW_JOBS[args.workflow].values())
            reused = reusable_run(GitHub(), os.environ["GITHUB_REPOSITORY"],
                                  os.environ["GITHUB_SHA"], tree,
                                  os.environ["GITHUB_RUN_ID"], args.workflow, required)
        except Exception as error:
            # Unavailable APIs, expired artifacts, and incomplete PR runs run tests.
            print(f"Could not verify prior PR result; running selected tests: {error}")
    if reused:
        selected.clear()
    outputs = {suite: str(suite in selected).lower() for suite in SUITES}
    outputs["reused"] = str(bool(reused)).lower()
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for key, value in outputs.items():
            output.write(f"{key}={value}\n")
    summary = (f"Reused successful PR tests for identical tree `{tree}`: {reused}\n"
               if reused else f"Selected suites: {', '.join(sorted(selected)) or 'none (documentation only)'}\n")
    print(summary)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
        output.write(summary)


if __name__ == "__main__":
    main()
