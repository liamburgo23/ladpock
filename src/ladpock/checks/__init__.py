"""Importing this package registers every built-in check."""

from . import apps, code, infra, languages, react, routes_checks, secrets, supabase, supply_chain, tauri, web  # noqa: F401
from .base import REGISTRY, CheckInfo, ScanContext, inline_ignored, run_all

__all__ = ["REGISTRY", "CheckInfo", "ScanContext", "inline_ignored", "run_all"]
