"""Talks to a model server on this computer. Refuses anything that isn't loopback,
so "local AI" can't quietly become "send my code somewhere"."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_URL = "http://127.0.0.1:11434"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class LocalModelError(Exception):
    """The local model server couldn't be reached or gave an unusable answer."""


@dataclass
class ModelInfo:
    name: str
    size: int
    parameters: str = ""
    thinking: bool = False

    @property
    def size_gb(self) -> float:
        return round(self.size / 1e9, 1)


@dataclass
class ChatStats:
    prompt_tokens: int = 0
    prompt_seconds: float = 0.0
    output_tokens: int = 0
    output_seconds: float = 0.0
    load_seconds: float = 0.0
    extra: dict = field(default_factory=dict)


class OllamaClient:
    def __init__(self, base_url: str | None = None, model: str | None = None, think: bool = False, timeout: float = 900):
        base_url = base_url or os.environ.get("LADPOCK_OLLAMA_URL") or DEFAULT_URL
        host = urlsplit(base_url).hostname or ""
        if host not in LOOPBACK:
            raise LocalModelError(f"Local AI only talks to this computer, not {host}")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.think = think
        self.timeout = timeout
        self._thinking_models: set[str] | None = None

    def _request(self, path: str, payload: dict | None = None, timeout: float | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base_url + path, data=data,
                                     headers={"Content-Type": "application/json"} if data else {})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise LocalModelError(f"Model server said {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise LocalModelError(f"Can't reach Ollama at {self.base_url} ({getattr(exc, 'reason', exc)})") from exc

    def available(self) -> bool:
        try:
            self._request("/api/version", timeout=2)
            return True
        except LocalModelError:
            return False

    def models(self) -> list[ModelInfo]:
        data = self._request("/api/tags", timeout=5)
        out = []
        for m in data.get("models", []):
            details = m.get("details") or {}
            caps = m.get("capabilities") or []
            if "embedding" in caps and "completion" not in caps:
                continue
            out.append(ModelInfo(m.get("name", ""), int(m.get("size") or 0), details.get("parameter_size", ""),
                                 "thinking" in caps))
        self._thinking_models = {m.name for m in out if m.thinking}
        return sorted(out, key=lambda m: m.name)

    def chat(self, system: str, user: str, schema: dict) -> tuple[dict, ChatStats]:
        if not self.model:
            raise LocalModelError("No model chosen")
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": schema,
            "keep_alive": "15m",
            "options": {"temperature": 0, "num_ctx": 16384},
        }
        if self._thinking_models is None:
            try:
                self.models()
            except LocalModelError:
                self._thinking_models = set()
        if self.model in (self._thinking_models or set()):
            payload["think"] = self.think
        data = self._request("/api/chat", payload)
        content = (data.get("message") or {}).get("content", "")
        stats = ChatStats(
            prompt_tokens=int(data.get("prompt_eval_count") or 0),
            prompt_seconds=(data.get("prompt_eval_duration") or 0) / 1e9,
            output_tokens=int(data.get("eval_count") or 0),
            output_seconds=(data.get("eval_duration") or 0) / 1e9,
            load_seconds=(data.get("load_duration") or 0) / 1e9,
        )
        return parse_json(content), stats


def parse_json(text: str) -> dict:
    text = text.strip()
    try:
        value = json.loads(text)
    except ValueError:
        match = re.search(r"\{.*\}", text, re.S)  # some models wrap JSON in prose or code fences
        if not match:
            raise LocalModelError("The model didn't return JSON")
        try:
            value = json.loads(match.group(0))
        except ValueError as exc:
            raise LocalModelError("The model returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise LocalModelError("The model returned JSON that isn't an object")
    return value


def gpu_memory_bytes() -> int | None:
    """Total memory of the first NVIDIA GPU, if nvidia-smi is available."""
    exe = shutil.which("nvidia-smi")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10).stdout
        return int(out.strip().splitlines()[0]) * 1024 * 1024
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


def pick_model(models: list[ModelInfo], gpu_bytes: int | None) -> ModelInfo | None:
    """Largest model that fits in GPU memory (coding models preferred), else the smallest."""
    if not models:
        return None
    if gpu_bytes:
        fitting = [m for m in models if m.size <= gpu_bytes * 0.95]
        if fitting:
            return max(fitting, key=lambda m: ("coder" in m.name, m.size))
        return min(models, key=lambda m: m.size)
    return max(models, key=lambda m: ("coder" in m.name, -abs(m.size - 20e9)))
