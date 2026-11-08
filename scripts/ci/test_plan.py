"""Regression tests for suite selection, Git ranges, and PR proof validation."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import plan


class SelectionTests(unittest.TestCase):
    def test_boundaries(self):
        cases = {
            "docs/user-guide.md": set(),
            "README.md": set(),
            "vendor/iced_core/README.md": set(),
            "docs/commands.template.html": {"rust"},
            "src/gui/view.rs": {"rust"},
            "assets/icon.png": {"rust"},
            "src/protocol.rs": {"rust", "browser", "cloud", "fuzz"},
            "vendor/iced_core/src/lib.rs": {"rust", "browser", "cloud", "fuzz"},
            "extension/background.js": {"extension", "browser"},
            "extension/command_contract.js": {"extension", "browser", "rust"},
            "sync-server/main.go": {"cloud"},
            "package-lock.json": {"extension", "browser", "npm_audit"},
            "fuzz/Cargo.lock": {"fuzz", "rust_audit"},
            "Cargo.lock": set(plan.SUITES),
            ".github/workflows/ci.yml": set(plan.SUITES),
            "scripts/ci/plan.py": set(plan.SUITES),
            "new-build-input.toml": set(plan.SUITES),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(plan.select([path]), expected)
        self.assertEqual(plan.select(["src/gui/view.rs", "sync-server/main.go"]), {"rust", "cloud"})

    def test_real_git_ranges_include_renames_deletions_and_entire_pr(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args], stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-b", "main")
            git("config", "user.email", "ci@example.invalid")
            git("config", "user.name", "CI fixture")
            root = Path(directory)
            (root / "original.rs").write_text("original\n")
            git("add", ".")
            git("commit", "-m", "base")
            base = git("rev-parse", "HEAD")
            git("checkout", "-b", "pr")
            git("mv", "original.rs", "renamed.rs")
            git("commit", "-am", "rename")
            before = git("rev-parse", "HEAD")
            git("rm", "renamed.rs")
            (root / "new.rs").write_text("new\n")
            git("add", ".")
            git("commit", "-m", "delete and add")
            head = git("rev-parse", "HEAD")
            git("checkout", "main")
            (root / "unrelated.rs").write_text("base advanced\n")
            git("add", ".")
            git("commit", "-m", "advance main")
            advanced = git("rev-parse", "HEAD")
            original_git = plan.git
            with patch.object(plan, "git", side_effect=lambda *args: original_git("-C", directory, *args)):
                pr = {"pull_request": {"base": {"sha": advanced}, "head": {"sha": head}}}
                self.assertEqual(set(plan.changed_paths("pull_request", pr)), {"original.rs", "new.rs"})
                self.assertEqual(set(plan.changed_paths("push", {"before": base, "after": before})), {"original.rs", "renamed.rs"})
                self.assertEqual(set(plan.changed_paths("push", {"before": before, "after": head})), {"renamed.rs", "new.rs"})
                self.assertIsNone(plan.changed_paths("push", {"before": "0" * 40, "after": head}))
                self.assertIsNone(plan.changed_paths("schedule", {}))


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.repo = "owner/repo"
        self.pr = {"merged_at": "today", "merge_commit_sha": "merged",
                   "head": {"sha": "head", "repo": {"full_name": self.repo}}}
        self.run = {"id": 42, "run_attempt": 1, "head_sha": "head", "event": "pull_request",
                    "head_repository": {"full_name": self.repo}, "conclusion": "success",
                    "html_url": "https://github.com/owner/repo/actions/runs/42"}
        self.artifact = {"name": "ci-tested-tree", "id": 7, "expired": False}
        self.proof = {"tree": "tree", "run_id": "42", "run_attempt": "1", "repository": self.repo,
                      "workflow": "ci", "event": "pull_request", "suites": ["rust"]}
        self.calls = []

    def api(self, route, raw=False):
        self.calls.append(route)
        if "/commits/" in route:
            return [self.pr]
        if route.endswith("/actions/runs/99"):
            return {"workflow_id": 3}
        if "/workflows/3/runs?" in route:
            return {"workflow_runs": [self.run]}
        if "/runs/42/artifacts?" in route:
            return {"artifacts": [self.artifact]}
        if route.endswith("/artifacts/7/zip"):
            self.assertTrue(raw)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w") as files:
                files.writestr("tested-tree.json", json.dumps(self.proof))
            return archive.getvalue()
        self.fail(f"Unexpected API request: {route}")

    def reuse(self):
        return plan.reusable_run(self.api, self.repo, "merged", "tree", "99", "ci", {"rust"})

    def test_verified_merge_or_squash_reuses_exact_tree(self):
        self.assertEqual(self.reuse(), self.run["html_url"])
        self.assertTrue(any("head_sha=head" in call for call in self.calls))

    def test_recorded_proof_round_trips_through_verifier(self):
        env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ID": "42",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": self.repo,
               "SELECTED": json.dumps({suite: str(suite == "rust").lower() for suite in plan.SUITES})}
        with patch.dict(os.environ, env), \
                patch("sys.argv", ["plan.py", "--workflow", "ci", "--record"]), \
                patch.object(plan, "git", return_value=b"tree\n"), \
                patch.object(plan.Path, "write_text") as write:
            plan.main()
        self.proof = json.loads(write.call_args.args[0])
        self.assertEqual(self.reuse(), self.run["html_url"])
        self.proof["suites"] = []
        self.assertIsNone(self.reuse())

    def test_invalid_candidates_never_skip_tests(self):
        cases = [
            ("pr", "merged_at", None), ("pr", "merge_commit_sha", "other"),
            ("pr", "head", {"sha": "head", "repo": {"full_name": "fork/repo"}}),
            ("pr", "head", {"sha": "head", "repo": None}),
            ("run", "conclusion", "failure"), ("run", "conclusion", None),
            ("run", "event", "push"), ("run", "head_sha", "old-head"),
            ("run", "head_repository", {"full_name": "fork/repo"}),
            ("artifact", "expired", True), ("artifact", "name", "fuzz-tested-tree"),
            ("proof", "suites", []), ("proof", "suites", ["extension"]),
            ("proof", "tree", "different-files"), ("proof", "run_id", "41"),
            ("proof", "run_attempt", "2"), ("proof", "workflow", "security"),
            ("proof", "event", "push"), ("proof", "repository", "other/repo"),
        ]
        for object_name, field, value in cases:
            with self.subTest(object=object_name, field=field, value=value):
                target = getattr(self, object_name)
                original = copy.deepcopy(target)
                target[field] = value
                self.assertIsNone(self.reuse())
                setattr(self, object_name, original)

    def test_api_error_falls_back_to_selected_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps({"before": "before", "after": "after"}))
            output = Path(directory) / "output"
            env = {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(event),
                   "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "merged",
                   "GITHUB_REPOSITORY": self.repo, "GITHUB_RUN_ID": "99",
                   "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(Path(directory) / "summary")}
            with patch.dict(os.environ, env), patch("sys.argv", ["plan.py", "--workflow", "ci"]), \
                    patch.object(plan, "git", return_value=b"tree\n"), \
                    patch.object(plan, "changed_paths", return_value=["src/protocol.rs"]), \
                    patch.object(plan, "reusable_run", side_effect=OSError("API unavailable")):
                plan.main()
            values = dict(line.split("=") for line in output.read_text().splitlines())
            self.assertEqual(values["reused"], "false")
            self.assertEqual(values["rust"], "true")
            self.assertEqual(values["browser"], "true")


    def test_planner_reuse_full_fallback_and_manual_full_run(self):
        cases = [
            ("push", ["src/gui/view.rs"], "https://github.com/owner/repo/actions/runs/42", set()),
            ("push", subprocess.CalledProcessError(128, "git"), None, set(plan.SUITES)),
            ("workflow_dispatch", None, None, set(plan.SUITES)),
            ("schedule", None, None, set(plan.SUITES)),
        ]
        for event_name, paths, prior, expected in cases:
            with self.subTest(event=event_name, paths=paths), tempfile.TemporaryDirectory() as directory:
                event = Path(directory) / "event.json"
                event.write_text("{}")
                output = Path(directory) / "output"
                env = {"GITHUB_EVENT_NAME": event_name, "GITHUB_EVENT_PATH": str(event),
                       "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "merged",
                       "GITHUB_REPOSITORY": self.repo, "GITHUB_RUN_ID": "99",
                       "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(Path(directory) / "summary")}
                path_mock = {"side_effect": paths} if isinstance(paths, Exception) else {"return_value": paths}
                with patch.dict(os.environ, env), patch("sys.argv", ["plan.py", "--workflow", "ci"]), \
                        patch.object(plan, "git", return_value=b"tree\n"), \
                        patch.object(plan, "changed_paths", **path_mock), \
                        patch.object(plan, "reusable_run", return_value=prior) as reuse:
                    plan.main()
                values = dict(line.split("=") for line in output.read_text().splitlines())
                self.assertEqual({key for key in plan.SUITES if values[key] == "true"}, expected)
                self.assertEqual(values["reused"], str(bool(prior)).lower())
                if event_name != "push":
                    reuse.assert_not_called()


class ResultTests(unittest.TestCase):
    def test_required_jobs_cannot_be_skipped_failed_cancelled_or_missing(self):
        jobs = {"plan": {"result": "success", "outputs": {"fuzz": "true"}},
                "fuzz": {"result": "success"}}
        plan.check_results(jobs, "fuzz", "pull_request")
        for result in ("failure", "cancelled", "skipped"):
            jobs["fuzz"]["result"] = result
            with self.assertRaises(ValueError):
                plan.check_results(jobs, "fuzz", "pull_request")
        del jobs["fuzz"]
        with self.assertRaises(ValueError):
            plan.check_results(jobs, "fuzz", "pull_request")
        jobs["plan"]["outputs"]["fuzz"] = "false"
        jobs["fuzz"] = {"result": "skipped"}
        plan.check_results(jobs, "fuzz", "pull_request")
        jobs["plan"]["result"] = "failure"
        with self.assertRaises(ValueError):
            plan.check_results(jobs, "fuzz", "pull_request")


if __name__ == "__main__":
    unittest.main()
