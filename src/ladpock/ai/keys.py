"""Where your Anthropic API key lives: Windows Credential Manager.

It's never written to LadPock's database or settings, never logged, and never
sent back to the dashboard (only a masked form like sk-ant-...4f2a). On other
systems, or if you prefer, set ANTHROPIC_API_KEY (or use `ant auth login`)
and the Anthropic SDK picks it up itself.
"""

from __future__ import annotations

import os
import sys

TARGET = "LadPock:anthropic-api-key"


class KeyError_(Exception):
    """The key couldn't be stored or read."""


def _win():
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIAL), wintypes.DWORD]
    advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(CREDENTIAL))]
    advapi.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    advapi.CredFree.argtypes = [ctypes.c_void_p]
    return ctypes, CREDENTIAL, advapi


CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE = 1, 2


def supported() -> bool:
    return sys.platform == "win32"


def store(key: str) -> None:
    key = key.strip()
    if not key.startswith("sk-ant-") or len(key) < 30 or any(c.isspace() for c in key):
        raise KeyError_("That doesn't look like an Anthropic API key (they start with sk-ant-)")
    if not supported():
        raise KeyError_("Storing a key is supported on Windows. Elsewhere, set ANTHROPIC_API_KEY or run `ant auth login`.")
    ctypes, CREDENTIAL, advapi = _win()
    blob = key.encode("utf-8")
    buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    cred = CREDENTIAL(Type=CRED_TYPE_GENERIC, TargetName=TARGET, CredentialBlobSize=len(blob),
                      CredentialBlob=ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
                      Persist=CRED_PERSIST_LOCAL_MACHINE, UserName="ladpock")
    if not advapi.CredWriteW(ctypes.byref(cred), 0):
        raise KeyError_(f"Windows Credential Manager refused the key (error {ctypes.get_last_error()})")


def load() -> str | None:
    if not supported():
        return None
    ctypes, CREDENTIAL, advapi = _win()
    pointer = ctypes.POINTER(CREDENTIAL)()
    if not advapi.CredReadW(TARGET, CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
        return None
    try:
        cred = pointer.contents
        return bytes(cred.CredentialBlob[: cred.CredentialBlobSize]).decode("utf-8")
    finally:
        advapi.CredFree(pointer)


def delete() -> bool:
    if not supported():
        return False
    ctypes, _, advapi = _win()
    return bool(advapi.CredDeleteW(TARGET, CRED_TYPE_GENERIC, 0))


def masked(key: str | None) -> str | None:
    return f"{key[:7]}…{key[-4:]}" if key else None


def status() -> dict:
    key = load()
    return {"stored": bool(key), "masked": masked(key), "env": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "can_store": supported()}
