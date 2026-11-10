"""Scanning repositories from GitHub: links, LadPock's own copies, and the dashboard flow. Nothing here talks to GitHub."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from helpers import FIXTURES, isolated_home

from ladpock import github
from ladpock.db import DB
from ladpock.scan import run_scan
from ladpock.ui.server import make_server

TOKEN = "test-token-github-0123456789"


def fake_fetch(full_name, log=lambda _: None):
    """Stands in for git: lays down a small project where LadPock's copy would go."""
    dest = github.copy_path(full_name)
    if not dest.exists():
        shutil.copytree(FIXTURES / "clean-flows", dest)
    log(f"Copying {full_name} from GitHub ...")
    return dest


class Links(unittest.TestCase):
    def test_profile_and_repository_links(self):
        cases = {
            "https://github.com/octo": ("octo", None),
            "github.com/octo/": ("octo", None),
            "octo": ("octo", None),
            "https://github.com/octo/app": ("octo", "app"),
            "https://www.github.com/octo/app.git": ("octo", "app"),
            "http://github.com/octo/my.app": ("octo", "my.app"),
            "git@github.com:octo/app.git": ("octo", "app"),
            "ssh://git@github.com/octo/app": ("octo", "app"),
            "octo/app": ("octo", "app"),
            "https://github.com/octo/app/tree/main/src": ("octo", "app"),
            "https://github.com/octo/app/blob/main/README.md": ("octo", "app"),
            "https://github.com/octo/app/pulls": ("octo", "app"),
            "https://github.com/octo/app?tab=readme": ("octo", "app"),
            "  https://github.com/octo/app#readme  ": ("octo", "app"),
            "https://github.com/octo-cat/app_2-x": ("octo-cat", "app_2-x"),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(github.parse_link(text), expected)

    def test_things_that_arent_github_links(self):
        for text in ("", "not a link!", "https://gitlab.com/octo/app", "https://github.com/octo/app/extra/parts",
                     "https://github.com/-octo", "https://github.com/settings", "https://github.com/orgs",
                     "https://github.com/octo/..", "https://evil.example/github.com/octo", "octo/app; rm -rf /",
                     "https://github.com/octo/app\nhttps://evil.example", "-c core.hooksPath=x"):
            with self.subTest(text=text), self.assertRaises(github.GitHubError):
                github.parse_link(text)


class Copies(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home()

    def tearDown(self):
        self.home.cleanup()

    def test_copy_paths_stay_inside_ladpocks_folder(self):
        path = github.copy_path("octo/app")
        self.assertEqual(path, Path(self.home.name) / "github" / "octo" / "app")
        for bad in ("octo/..", "../octo", "octo/app/../../x", "octo/a b", "-x/app"):
            with self.subTest(bad=bad), self.assertRaises(github.GitHubError):
                github.copy_path(bad)

    def test_managed_name_only_for_ladpocks_own_copies(self):
        path = github.copy_path("octo/app")
        path.mkdir(parents=True)
        self.assertEqual(github.managed_name(path), "octo/app")
        self.assertEqual(github.managed_name(path / "src"), None)  # a folder inside a copy isn't a copy
        self.assertEqual(github.managed_name(path.parent), None)
        self.assertEqual(github.managed_name(tempfile.gettempdir()), None)

    def test_remove_copy_refuses_anything_else(self):
        with tempfile.TemporaryDirectory() as tmp:
            keep = Path(tmp) / "octo" / "app"
            keep.mkdir(parents=True)
            self.assertFalse(github.remove_copy(keep))
            self.assertTrue(keep.is_dir())
        self.assertFalse(github.remove_copy(github.root()))

    def test_remove_copy_deletes_read_only_git_files(self):
        path = github.copy_path("octo/app")
        (path / ".git" / "objects").mkdir(parents=True)
        locked = path / ".git" / "objects" / "pack"
        locked.write_text("x")
        os.chmod(locked, stat.S_IREAD)
        self.assertTrue(github.remove_copy(path))
        self.assertFalse(path.exists())
        self.assertFalse(path.parent.exists())  # the empty owner folder goes too

    def test_git_runs_with_everything_in_the_repository_switched_off(self):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            if "clone" in args:
                Path(args[-1]).mkdir(parents=True)
                (Path(args[-1]) / ".git").mkdir()
            return subprocess.CompletedProcess(args, 0, "", "")

        with mock.patch.object(github.shutil, "which", lambda name: f"/usr/bin/{name}"), mock.patch.object(github, "_run", run):
            dest = github.fetch("octo/app")
            github.fetch("octo/app")  # the second time it updates instead
        clone, fetch, reset, clean = calls
        for args in calls:
            text = " ".join(args)
            for setting in ("core.hooksPath=", "core.symlinks=false", "protocol.file.allow=never", "protocol.ext.allow=never",
                            "core.fsmonitor=false", "submodule.recurse=false"):
                self.assertIn(setting, text)
            self.assertIn("credential.https://github.com.helper=!/usr/bin/gh auth git-credential", text)
        self.assertEqual(clone[-3:], ["--", "https://github.com/octo/app.git", str(dest)])
        self.assertIn("--depth", clone)
        self.assertIn("--no-recurse-submodules", clone)
        self.assertIn("--no-recurse-submodules", fetch)
        self.assertEqual(reset[-3:], ["reset", "--hard", "FETCH_HEAD"])
        self.assertEqual(clean[-2:], ["-fdx", "-q"])

    def test_a_failed_clone_leaves_nothing_behind(self):
        def run(args, **kwargs):
            Path(args[-1]).mkdir(parents=True)
            return subprocess.CompletedProcess(args, 128, "", "remote: Repository not found.\nfatal: repository not found")

        with mock.patch.object(github.shutil, "which", lambda name: f"/usr/bin/{name}"), mock.patch.object(github, "_run", run):
            with self.assertRaises(github.GitHubError) as caught:
                github.fetch("octo/secret")
        self.assertIn("doesn't exist or you don't have access", str(caught.exception))
        self.assertFalse(github.copy_path("octo/secret").exists())

    def test_without_git(self):
        with mock.patch.object(github.shutil, "which", lambda name: None), self.assertRaises(github.GitHubError) as caught:
            github.fetch("octo/app")
        self.assertIn("Git isn't installed", str(caught.exception))

    def test_listing_through_the_github_cli(self):
        out = json.dumps([
            {"nameWithOwner": "octo/old", "isPrivate": False, "isArchived": True, "pushedAt": "2020-01-01T00:00:00Z", "diskUsage": 5},
            {"nameWithOwner": "octo/app", "isPrivate": True, "primaryLanguage": {"name": "TypeScript"}, "pushedAt": "2026-01-01T00:00:00Z"},
        ])
        with mock.patch.object(github, "_gh", lambda: "/usr/bin/gh"), \
                mock.patch.object(github, "_run", lambda args, **kw: subprocess.CompletedProcess(args, 0, out, "")):
            repos, via = github.list_repos("octo")
        self.assertEqual(via, "gh")
        self.assertEqual([r.full_name for r in repos], ["octo/app", "octo/old"])  # most recently pushed first
        self.assertTrue(repos[0].private)
        self.assertEqual(repos[0].language, "TypeScript")
        self.assertTrue(repos[1].archived)

    def test_scan_refreshes_a_copy_first_and_carries_on_if_it_cant(self):
        folder = fake_fetch("octo/app")
        db = DB()
        calls = []
        with mock.patch.object(github, "fetch", lambda name, log=None: calls.append(name) or folder):
            result = run_scan(folder, db, offline=False, external=False)
        self.assertEqual(calls, ["octo/app"])
        self.assertEqual(db.list_projects()[0]["name"], "octo/app")
        self.assertEqual(result.scorecard.grade, "A+")

        def broken(name, log=None):
            raise github.GitHubError("Couldn't reach GitHub")

        with mock.patch.object(github, "fetch", broken):
            result = run_scan(folder, db, offline=False, external=False)
        self.assertTrue(any("used the copy from last time" in e for e in result.errors))
        with mock.patch.object(github, "fetch", lambda *a, **k: self.fail("offline scans don't fetch")):
            run_scan(folder, db, offline=True, external=False)
        db.close()


class Dashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = isolated_home()
        cls.server = make_server(0, TOKEN)
        cls.port = cls.server.app.port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.home.cleanup()

    def api(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Host": f"127.0.0.1:{self.port}", "X-LadPock-Token": TOKEN}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw or b"{}")

    def wait_for(self, job_id):
        job = {}
        for _ in range(300):
            _, job = self.api("GET", f"/api/jobs/{job_id}")
            if job["status"] != "running":
                return job
            time.sleep(0.1)
        return job

    def test_tools(self):
        with mock.patch.object(github, "tools", lambda: {"git": True, "gh": True, "gh_login": "octo"}):
            status, data = self.api("GET", "/api/github?fresh=1")
        self.assertEqual(status, 200)
        self.assertEqual(data, {"git": True, "gh": True, "gh_login": "octo"})

    def test_bad_links_and_names_are_refused(self):
        self.assertEqual(self.api("POST", "/api/github/repos", {"link": "https://gitlab.com/x/y"})[0], 400)
        self.assertEqual(self.api("POST", "/api/github/add", {"repos": []})[0], 400)
        self.assertEqual(self.api("POST", "/api/github/add", {"repos": ["octo/../../etc"]})[0], 400)
        self.assertEqual(self.api("POST", "/api/github/add", {"repos": "octo/app"})[0], 400)

    def test_paste_a_link_add_scan_and_remove(self):
        listing = [github.Repo("octo/app", private=True, language="Python"), github.Repo("octo/fork", fork=True)]
        with mock.patch.object(github, "list_repos", lambda owner, repo=None: (listing, "gh")):
            status, found = self.api("POST", "/api/github/repos", {"link": "https://github.com/octo"})
        self.assertEqual(status, 200)
        self.assertEqual((found["owner"], found["single"], found["via"]), ("octo", False, "gh"))
        self.assertEqual([r["full_name"] for r in found["repos"]], ["octo/app", "octo/fork"])
        self.assertFalse(found["repos"][0]["added"])

        with mock.patch.object(github, "fetch", fake_fetch):
            status, started = self.api("POST", "/api/github/add", {"repos": ["octo/app"], "scan": True})
            self.assertEqual(status, 202)
            job = self.wait_for(started["job"])
        self.assertEqual(job["status"], "done", job.get("error"))
        self.assertEqual(job["steps"][0], "octo/app: Copy from GitHub")
        self.assertEqual([a["repo"] for a in job["result"]["added"]], ["octo/app"])

        _, projects = self.api("GET", "/api/status")
        project = next(p for p in projects["projects"] if p["github"] == "octo/app")
        self.assertEqual(project["name"], "octo/app")
        self.assertEqual(project["grade"], "A+")

        with mock.patch.object(github, "list_repos", lambda owner, repo=None: (listing, "gh")):
            found = self.api("POST", "/api/github/repos", {"link": "octo"})[1]
        self.assertTrue(found["repos"][0]["added"])

        copy = github.copy_path("octo/app")
        self.assertTrue(copy.is_dir())
        self.assertEqual(self.api("DELETE", f"/api/projects/{project['id']}")[0], 200)
        self.assertFalse(copy.exists())  # LadPock's copy goes with the project

    def test_a_repository_that_cant_be_copied_is_reported(self):
        def broken(name, log=None):
            raise github.GitHubError(f"Couldn't get {name}: it doesn't exist or you don't have access.")

        with mock.patch.object(github, "fetch", broken):
            started = self.api("POST", "/api/github/add", {"repos": ["octo/missing"], "scan": False})[1]
            job = self.wait_for(started["job"])
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["result"]["failed"][0]["repo"], "octo/missing")
        self.assertEqual(job["result"]["added"], [])


if __name__ == "__main__":
    unittest.main()
