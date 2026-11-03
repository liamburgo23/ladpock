"""Installs the optional scanners: pinned versions, verified before use.

How a file gets onto your computer:
1. The exact version, file name, size and SHA-256 come from pins.json, which
   ships inside LadPock. Nothing about what to install is read from the network.
2. It's downloaded over HTTPS from the project's GitHub release into a
   temporary folder, stopping if it's bigger than the pinned size.
3. Its SHA-256 must match the pin exactly. If not, it's deleted and nothing is
   installed. A rewritten tag, a compromised mirror or a corrupted download all
   fail here.
4. Only the one expected file is taken out of an archive (never paths from it),
   and it's moved into LadPock's own bin folder. Nothing is added to PATH, and
   nothing runs with extra privileges.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .. import __version__
from ..paths import data_dir
from .base import version_of, which

PINS_FILE = Path(__file__).resolve().parent / "pins.json"
CHUNK = 256 * 1024


class InstallError(Exception):
    """A scanner couldn't be installed. Nothing was changed."""


@dataclass
class ToolStatus:
    name: str
    version: str
    adds: str
    license: str
    repo: str
    released: str
    supported: bool  # a pinned build exists for this computer
    download_size: int | None
    file: str | None
    installed: bool
    managed: bool  # installed by LadPock (so LadPock may update or remove it)
    path: str | None
    installed_version: str | None
    up_to_date: bool

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def bin_dir() -> Path:
    path = data_dir() / "bin"
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_pins() -> dict:
    pins = json.loads(PINS_FILE.read_text(encoding="utf-8"))
    return {k: v for k, v in pins.items() if not k.startswith("_")}


def platform_key() -> str | None:
    system = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(sys.platform)
    machine = platform.machine().lower()
    arch = "x64" if machine in ("amd64", "x86_64", "x64") else "arm64" if machine in ("arm64", "aarch64") else None
    return f"{system}-{arch}" if system and arch else None


def target_path(binary: str) -> Path:
    return bin_dir() / (binary + (".exe" if sys.platform == "win32" else ""))


def release_url(info: dict, asset: dict) -> str:
    return f"https://github.com/{info['repo']}/releases/download/v{info['version']}/{asset['file']}"


def status(pins: dict | None = None) -> list[ToolStatus]:
    pins = pins or load_pins()
    key = platform_key()
    out = []
    for name, info in pins.items():
        asset = info["assets"].get(key or "")
        found = which(info["binary"])
        managed = bool(found) and Path(found).resolve().parent == bin_dir().resolve()
        installed_version = version_of(found, "version" if name == "gitleaks" else "--version") if found else None
        out.append(ToolStatus(
            name=name, version=info["version"], adds=info["adds"], license=info["license"], repo=info["repo"],
            released=info["released"], supported=asset is not None, download_size=asset["size"] if asset else None,
            file=asset["file"] if asset else None, installed=bool(found), managed=managed, path=found,
            installed_version=installed_version,
            up_to_date=bool(installed_version and info["version"] in installed_version),
        ))
    return out


def _check_url(url: str, allow_loopback_http: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme == "https":
        return
    if allow_loopback_http and parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost"):
        return  # tests serve fake releases locally
    raise InstallError(f"Refusing to download over {parts.scheme}: {url}")


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_loopback_http: bool):
        self.allow_loopback_http = allow_loopback_http

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl, self.allow_loopback_http)  # GitHub redirects to its file storage, also HTTPS
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_verified(url: str, dest: Path, size: int, sha256: str, *, progress: Callable[[float], None] | None = None,
                      allow_loopback_http: bool = False, timeout: float = 120) -> None:
    """Download to dest, enforcing the exact size and SHA-256. Deletes dest and raises on any mismatch."""
    _check_url(url, allow_loopback_http)
    opener = urllib.request.build_opener(_HttpsOnlyRedirects(allow_loopback_http))
    request = urllib.request.Request(url, headers={"User-Agent": f"LadPock/{__version__}"})
    digest = hashlib.sha256()
    received = 0
    try:
        with opener.open(request, timeout=timeout) as resp, open(dest, "wb") as out:
            while True:
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                received += len(chunk)
                if received > size:
                    raise InstallError(f"Download is bigger than the pinned {size} bytes; stopped")
                digest.update(chunk)
                out.write(chunk)
                if progress:
                    progress(received / size)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        dest.unlink(missing_ok=True)
        raise InstallError(f"Download failed: {getattr(exc, 'reason', exc)}") from exc
    except InstallError:
        dest.unlink(missing_ok=True)
        raise
    if received != size or digest.hexdigest() != sha256:
        dest.unlink(missing_ok=True)
        raise InstallError("The download doesn't match the pinned checksum, so it was deleted and nothing was installed. "
                           "This can mean a corrupted download or a tampered release.")


def _extract_member(archive: Path, kind: str, member: str, dest: Path) -> None:
    """Copy exactly one named file out of an archive. Paths inside the archive are never used."""
    if kind == "zip":
        with zipfile.ZipFile(archive) as zf:
            names = [n for n in zf.namelist() if n.rsplit("/", 1)[-1] == member and not n.endswith("/")]
            if len(names) != 1:
                raise InstallError(f"Expected one {member} in the archive, found {len(names)}")
            with zf.open(names[0]) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
    elif kind == "tar.gz":
        with tarfile.open(archive, "r:gz") as tf:
            found = [m for m in tf.getmembers() if m.name.rsplit("/", 1)[-1] == member]
            if len(found) != 1 or not found[0].isfile():
                raise InstallError(f"Expected one regular file {member} in the archive")
            src = tf.extractfile(found[0])
            if src is None:
                raise InstallError(f"Couldn't read {member} from the archive")
            with src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
    else:
        raise InstallError(f"Unknown archive type {kind}")


def install(name: str, *, pins: dict | None = None, progress: Callable[[float], None] | None = None,
            log: Callable[[str], None] = print, base_url: str | None = None, allow_loopback_http: bool = False) -> str:
    """Install one pinned scanner into LadPock's bin folder. Returns the installed path."""
    pins = pins or load_pins()
    if name not in pins:
        raise InstallError(f"Unknown scanner '{name}'. Choose from: {', '.join(pins)}")
    info = pins[name]
    key = platform_key()
    asset = info["assets"].get(key or "")
    if not asset:
        raise InstallError(f"{name} {info['version']} has no build for this computer ({key or platform.machine()})")
    url = f"{base_url.rstrip('/')}/{asset['file']}" if base_url else release_url(info, asset)
    target = target_path(info["binary"])
    log(f"Downloading {asset['file']} ({asset['size'] / 1e6:.1f} MB) from {urlsplit(url).netloc} ...")
    with tempfile.TemporaryDirectory(dir=bin_dir()) as tmp:
        downloaded = Path(tmp) / "download"
        download_verified(url, downloaded, asset["size"], asset["sha256"], progress=progress,
                          allow_loopback_http=allow_loopback_http)
        log(f"Checksum verified ({asset['sha256'][:12]}...).")
        staged = Path(tmp) / "staged"
        if asset["archive"] == "none":
            downloaded.replace(staged)
        else:
            _extract_member(downloaded, asset["archive"], asset["member"], staged)
        if sys.platform != "win32":
            staged.chmod(staged.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        try:
            os.replace(staged, target)
        except PermissionError as exc:
            raise InstallError(f"Couldn't replace {target.name}; is it running? ({exc})") from exc
    log(f"Installed {name} {info['version']} to {target}")
    return str(target)


def remove(name: str, pins: dict | None = None) -> bool:
    """Remove a scanner LadPock installed. Copies installed some other way are left alone."""
    pins = pins or load_pins()
    if name not in pins:
        raise InstallError(f"Unknown scanner '{name}'")
    target = target_path(pins[name]["binary"])
    if target.exists():
        target.unlink()
        return True
    return False
