"""The scanner installer, tested against a local fake release server. No real downloads."""

from __future__ import annotations

import hashlib
import http.server
import io
import json
import sys
import tarfile
import threading
import unittest
import zipfile
from pathlib import Path

from helpers import isolated_home

from ladpock.scanners import install as installer

FAKE_BINARY = b"#!/bin/sh\necho fake-scanner 1.0.0\n"


def make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_tgz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeReleases(http.server.BaseHTTPRequestHandler):
    files: dict[str, bytes] = {}

    def log_message(self, *args):
        pass

    def do_GET(self):
        data = self.files.get(self.path.lstrip("/"))
        if data is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def pins_for(file: str, data: bytes, archive: str, member: str | None = None, sha: str | None = None,
             size: int | None = None) -> dict:
    asset = {"file": file, "size": size if size is not None else len(data),
             "sha256": sha or hashlib.sha256(data).hexdigest(), "archive": archive}
    if member:
        asset["member"] = member
    return {"fake": {"version": "1.0.0", "released": "2026-01-01", "repo": "example/fake", "license": "MIT",
                     "adds": "test", "binary": "fake", "assets": {installer.platform_key(): asset}}}


class Installer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeReleases)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.home = isolated_home()
        self.target = installer.target_path("fake")

    def tearDown(self):
        self.home.cleanup()

    def install(self, pins, **kw):
        return installer.install("fake", pins=pins, base_url=self.base, allow_loopback_http=True, log=lambda _: None, **kw)

    def test_zip_tar_and_raw_installs(self):
        member = "fake.exe" if sys.platform == "win32" else "fake"
        cases = [
            ("fake.zip", make_zip({"README.md": b"x", member: FAKE_BINARY}), "zip"),
            ("fake.tar.gz", make_tgz({"LICENSE": b"x", f"dir/{member}": FAKE_BINARY}), "tar.gz"),
            ("fake-raw", FAKE_BINARY, "none"),
        ]
        for file, data, kind in cases:
            with self.subTest(kind):
                FakeReleases.files[file] = data
                progress = []
                path = self.install(pins_for(file, data, kind, member if kind != "none" else None),
                                    progress=progress.append)
                self.assertEqual(Path(path).read_bytes(), FAKE_BINARY)
                self.assertEqual(round(progress[-1], 3), 1.0)
                if sys.platform != "win32":
                    self.assertTrue(Path(path).stat().st_mode & 0o100)

    def test_checksum_mismatch_installs_nothing(self):
        FakeReleases.files["tampered"] = FAKE_BINARY
        with self.assertRaises(installer.InstallError) as ctx:
            self.install(pins_for("tampered", FAKE_BINARY, "none", sha="0" * 64))
        self.assertIn("doesn't match", str(ctx.exception))
        self.assertFalse(self.target.exists())
        self.assertEqual([p.name for p in installer.bin_dir().iterdir()], [])  # temp files cleaned up

    def test_bigger_than_pinned_is_refused(self):
        FakeReleases.files["big"] = FAKE_BINARY * 10
        with self.assertRaises(installer.InstallError):
            self.install(pins_for("big", FAKE_BINARY * 10, "none", size=len(FAKE_BINARY)))
        self.assertFalse(self.target.exists())

    def test_archive_paths_are_never_used(self):
        member = "fake"
        data = make_tgz({f"../../escape/{member}": FAKE_BINARY})
        FakeReleases.files["evil.tar.gz"] = data
        path = self.install(pins_for("evil.tar.gz", data, "tar.gz", member))
        self.assertEqual(Path(path).parent, installer.bin_dir())
        self.assertFalse((installer.bin_dir().parent.parent / "escape").exists())

    def test_ambiguous_archive_is_refused(self):
        data = make_zip({"a/fake": FAKE_BINARY, "b/fake": b"other"})
        FakeReleases.files["two.zip"] = data
        with self.assertRaises(installer.InstallError):
            self.install(pins_for("two.zip", data, "zip", "fake"))

    def test_plain_http_is_refused_without_the_test_flag(self):
        FakeReleases.files["raw"] = FAKE_BINARY
        with self.assertRaises(installer.InstallError):
            installer.install("fake", pins=pins_for("raw", FAKE_BINARY, "none"), base_url=self.base, log=lambda _: None)
        with self.assertRaises(installer.InstallError):
            installer.download_verified("http://example.com/x", Path(self.home.name) / "x", 1, "0" * 64,
                                        allow_loopback_http=True)

    def test_remove_only_touches_ladpock_copies(self):
        FakeReleases.files["raw2"] = FAKE_BINARY
        pins = pins_for("raw2", FAKE_BINARY, "none")
        self.install(pins)
        self.assertTrue(installer.remove("fake", pins))
        self.assertFalse(installer.remove("fake", pins))


class Pins(unittest.TestCase):
    def test_pinned_manifest_is_well_formed(self):
        pins = installer.load_pins()
        self.assertEqual(set(pins), {"gitleaks", "osv-scanner", "opengrep"})
        for name, info in pins.items():
            self.assertRegex(info["version"], r"^\d+\.\d+\.\d+$")
            self.assertIn("/", info["repo"])
            for key, asset in info["assets"].items():
                with self.subTest(f"{name} {key}"):
                    self.assertRegex(key, r"^(windows|linux|darwin)-(x64|arm64)$")
                    self.assertRegex(asset["sha256"], r"^[0-9a-f]{64}$")
                    self.assertGreater(asset["size"], 1_000_000)
                    self.assertIn(asset["archive"], ("zip", "tar.gz", "none"))
                    if asset["archive"] != "none":
                        self.assertIn("member", asset)
                    if name == "gitleaks":
                        self.assertIn(info["version"], asset["file"])
                    url = installer.release_url(info, asset)
                    self.assertTrue(url.startswith(f"https://github.com/{info['repo']}/releases/download/v{info['version']}/"))

    def test_this_platform_is_supported(self):
        key = installer.platform_key()
        if key in ("windows-x64", "linux-x64", "darwin-arm64"):
            self.assertTrue(all(key in info["assets"] for info in installer.load_pins().values()))


class ScannersApi(unittest.TestCase):
    def test_status_and_validation(self):
        from test_ui import TOKEN
        from ladpock.ui.server import make_server
        import http.client

        home = isolated_home()
        server = make_server(0, TOKEN)
        port = server.app.port
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def call(method, path, body=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            headers = {"Host": f"127.0.0.1:{port}", "X-LadPock-Token": TOKEN}
            if method == "POST":
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=json.dumps(body or {}).encode() if method == "POST" else None, headers=headers)
            resp = conn.getresponse()
            payload = json.loads(resp.read() or b"{}")
            conn.close()
            return resp.status, payload

        try:
            status, data = call("GET", "/api/scanners")
            self.assertEqual(status, 200)
            self.assertEqual({t["name"] for t in data["tools"]}, {"gitleaks", "osv-scanner", "opengrep"})
            self.assertEqual(call("POST", "/api/scanners/install", {"names": ["not-a-tool"]})[0], 400)
            self.assertEqual(call("POST", "/api/scanners/install", {})[0], 400)
            self.assertEqual(call("POST", "/api/scanners/remove", {"name": "gitleaks"})[1], {"removed": False})
        finally:
            server.shutdown()
            server.server_close()
            home.cleanup()


if __name__ == "__main__":
    unittest.main()
