"""Install a built wheel into a fresh virtual environment and check the installed
`ladpock` command really works: the CLI, a scan, the MCP server, and the files
the dashboard and scanners need.

    python scripts/check_package.py dist/ladpock-X.Y.Z-py3-none-any.whl
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def run(cmd: list, env: dict, cwd: Path, stdin: str | None = None, ok=(0,)) -> subprocess.CompletedProcess:
    proc = subprocess.run([str(c) for c in cmd], env=env, cwd=cwd, input=stdin, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300)
    if proc.returncode not in ok:
        sys.exit(f"FAILED ({proc.returncode}): {' '.join(map(str, cmd))}\n{proc.stdout}\n{proc.stderr}")
    return proc


def main(wheel_arg: str) -> None:
    wheel = Path(wheel_arg).resolve()
    version = wheel.name.split("-")[1]
    with tempfile.TemporaryDirectory(prefix="ladpock-package-") as tmp:
        root = Path(tmp)
        venv.create(root / "venv", with_pip=True)
        bin_dir = root / "venv" / ("Scripts" if os.name == "nt" else "bin")
        python = bin_dir / ("python.exe" if os.name == "nt" else "python")
        exe = bin_dir / ("ladpock.exe" if os.name == "nt" else "ladpock")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}  # only the installed copy may be used
        env["LADPOCK_HOME"] = str(root / "home")
        run([python, "-m", "pip", "install", "--quiet", "--no-deps", "--no-index", wheel], env, root)

        out = run([exe, "--version"], env, root).stdout
        assert version in out, f"--version said {out!r}, expected {version}"

        checks = run([exe, "checks"], env, root).stdout.splitlines()
        assert len([line for line in checks if line.startswith("LP-")]) >= 100, "fewer checks than expected"

        project = root / "demo"
        (project / "lib").mkdir(parents=True)
        key = "sk_" + "live_" + "PackageCheck" + "0123456789abcdef"
        (project / "lib" / "pay.ts").write_text(f'export const stripe = "{key}";\n', encoding="utf-8")
        scan = run([exe, "scan", project, "--offline", "--no-color", "--fail-on", "critical"], env, root, ok=(1,))
        assert "Hardcoded credential" in scan.stdout and key not in scan.stdout, "scan output unexpected"

        messages = "\n".join(json.dumps(m) for m in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )) + "\n"
        replies = [json.loads(line) for line in run([exe, "mcp"], env, root, stdin=messages).stdout.splitlines()]
        assert replies[0]["result"]["serverInfo"]["version"] == version
        tools = {t["name"] for t in replies[1]["result"]["tools"]}
        assert {"ladpock_scan", "ladpock_findings", "ladpock_fix_start", "ladpock_fix_check", "ladpock_accept_risk"} <= tools, tools

        run([python, "-c",
             "import json, pathlib, ladpock; from ladpock.ui.server import STATIC; "
             "base = pathlib.Path(ladpock.__file__).parent; "
             "assert {'index.html', 'app.js', 'app.css'} <= {p.name for p in STATIC.iterdir()}; "
             "assert list((base / 'rules' / 'opengrep').glob('*.yaml')); "
             "assert json.loads((base / 'scanners' / 'pins.json').read_text())"], env, root)
    print(f"OK: ladpock {version} installs and runs (CLI, scan, MCP server, dashboard files, rules, scanner pins)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
