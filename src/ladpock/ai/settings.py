"""Which local model to use, remembered between runs."""

from __future__ import annotations

from ..db import DB
from .client import LocalModelError, OllamaClient, gpu_memory_bytes, pick_model


def make_client(db: DB, model: str | None = None, think: bool | None = None) -> OllamaClient:
    """A client for the chosen model: explicit > saved > best fit for this GPU."""
    client = OllamaClient(think=bool(think) if think is not None else db.get_meta("ai_think") == "1")
    chosen = model or db.get_meta("ai_model")
    installed = client.models()  # raises LocalModelError if Ollama isn't running
    names = {m.name for m in installed}
    if chosen and chosen not in names:
        raise LocalModelError(f"Model '{chosen}' isn't installed. Installed: {', '.join(sorted(names)) or 'none'}")
    if not chosen:
        best = pick_model(installed, gpu_memory_bytes())
        if not best:
            raise LocalModelError("No models installed. Install one with: ollama pull qwen2.5-coder:14b")
        chosen = best.name
    client.model = chosen
    return client


def save(db: DB, model: str | None = None, think: bool | None = None) -> None:
    if model is not None:
        db.set_meta("ai_model", model)
    if think is not None:
        db.set_meta("ai_think", "1" if think else "0")


def status(db: DB) -> dict:
    client = OllamaClient()
    info = {"available": False, "models": [], "model": db.get_meta("ai_model"), "think": db.get_meta("ai_think") == "1",
            "suggested": None, "gpu_gb": None}
    gpu = gpu_memory_bytes()
    info["gpu_gb"] = round(gpu / 1e9, 1) if gpu else None
    try:
        models = client.models()
    except LocalModelError as exc:
        info["error"] = str(exc)
        return info
    info["available"] = True
    info["models"] = [{"name": m.name, "size_gb": m.size_gb, "parameters": m.parameters,
                       "fits_gpu": bool(gpu and m.size <= gpu * 0.95)} for m in models]
    best = pick_model(models, gpu)
    info["suggested"] = best.name if best else None
    if not info["model"] or info["model"] not in {m.name for m in models}:
        info["model"] = info["suggested"]
    return info
