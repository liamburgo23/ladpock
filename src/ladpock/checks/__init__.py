"""Importing this package registers every built-in check."""

from . import apps, code, flows, infra, languages, modern, native, react, routes_checks, secrets, supabase, supply_chain, tauri, web  # noqa: F401
from .base import REGISTRY, CheckInfo, ScanContext, inline_ignored, run_all
from .. import probe  # noqa: F401,E402  (registers the live checks so they're in the catalogue and scoring)

__all__ = ["REGISTRY", "CheckInfo", "ScanContext", "inline_ignored", "run_all"]
