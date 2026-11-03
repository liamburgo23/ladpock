"""The double-click launcher, written into a throwaway home folder."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from ladpock import launcher

ARGV = ["/opt/ladpock/bin/ladpock", "ui"]


class Launcher(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_linux_menu_entry(self):
        made = launcher.install("linux", self.home, desktop=True, argv=ARGV)
        self.assertEqual([p.name for p in made], ["ladpock.desktop", "ladpock.desktop"])
        text = made[0].read_text(encoding="utf-8")
        self.assertIn("Exec='/opt/ladpock/bin/ladpock' 'ui'", text)
        self.assertIn("Terminal=true", text)
        self.assertEqual(len(launcher.remove("linux", self.home)), 2)
        self.assertFalse(made[0].exists())

    def test_macos_command_file(self):
        made = launcher.install("darwin", self.home, argv=ARGV)
        self.assertEqual(made, [self.home / "Applications" / "LadPock.command"])
        self.assertTrue(made[0].read_text(encoding="utf-8").startswith("#!/bin/sh"))

    @unittest.skipUnless(sys.platform == "win32" and shutil.which("powershell"), "Windows shortcuts need PowerShell")
    def test_windows_shortcut(self):
        made = launcher.install("win32", self.home, desktop=True, argv=[sys.executable, "-m", "ladpock", "ui"])
        self.assertEqual([p.name for p in made], ["LadPock.lnk", "LadPock.lnk"])
        self.assertTrue(all(p.exists() and p.stat().st_size > 0 for p in made))
        self.assertIn("Start Menu", str(made[0]))
        self.assertEqual(len(launcher.remove("win32", self.home)), 2)

    def test_command_uses_this_install(self):
        argv = launcher.command()
        self.assertEqual(argv[-1], "ui")


if __name__ == "__main__":
    unittest.main()
