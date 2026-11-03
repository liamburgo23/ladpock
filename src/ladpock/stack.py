"""Works out what a project is built with, so the right rule packs run."""

from __future__ import annotations

import json
import re
import tomllib

from .files import FileIndex, basename

LABELS = {
    "nextjs": "Next.js", "react": "React", "vite": "Vite", "express": "Express", "fastify": "Fastify",
    "hono": "Hono", "sveltekit": "SvelteKit", "nuxt": "Nuxt", "remix": "Remix", "astro": "Astro",
    "supabase": "Supabase", "firebase": "Firebase", "stripe": "Stripe", "nextauth": "Auth.js",
    "clerk": "Clerk", "prisma": "Prisma", "drizzle": "Drizzle", "openai": "OpenAI",
    "anthropic": "Anthropic", "ai-sdk": "Vercel AI SDK", "fastapi": "FastAPI", "flask": "Flask",
    "django": "Django", "node": "Node.js", "python": "Python", "docker": "Docker",
    "github-actions": "GitHub Actions", "tauri": "Tauri", "rust": "Rust", "koa": "Koa", "nestjs": "NestJS",
    "kubernetes": "Kubernetes", "terraform": "Terraform",
}

# Stacks with dedicated, framework-aware checks. Everything else still gets the
# generic checks (secrets, dependencies, injection patterns, config).
DEEP_PACKS = {"nextjs", "react", "supabase", "firebase", "stripe", "github-actions", "tauri", "express", "fastify",
              "hono", "koa", "nestjs", "fastapi", "flask", "django", "docker", "kubernetes", "terraform"}

_NPM = {
    "next": "nextjs", "react": "react", "vite": "vite", "express": "express", "fastify": "fastify",
    "hono": "hono", "@sveltejs/kit": "sveltekit", "nuxt": "nuxt", "@remix-run/node": "remix",
    "astro": "astro", "@supabase/supabase-js": "supabase", "@supabase/ssr": "supabase",
    "firebase": "firebase", "firebase-admin": "firebase", "stripe": "stripe", "@stripe/stripe-js": "stripe",
    "next-auth": "nextauth", "@auth/core": "nextauth", "@clerk/nextjs": "clerk", "prisma": "prisma",
    "@prisma/client": "prisma", "drizzle-orm": "drizzle", "openai": "openai",
    "@anthropic-ai/sdk": "anthropic", "ai": "ai-sdk", "@tauri-apps/api": "tauri", "@tauri-apps/cli": "tauri",
    "koa": "koa", "@koa/router": "koa", "@nestjs/core": "nestjs", "@nestjs/common": "nestjs", "@hono/node-server": "hono",
}
_PY = {
    "fastapi": "fastapi", "flask": "flask", "django": "django", "supabase": "supabase", "stripe": "stripe",
    "openai": "openai", "anthropic": "anthropic", "firebase-admin": "firebase", "djangorestframework": "django",
    "quart": "flask", "starlette": "fastapi",
}
_PY_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _python_names(index: FileIndex, rel: str) -> set[str]:
    text = index.read(rel) or ""
    name = basename(rel)
    names: set[str] = set()
    if name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return names
        deps = list(data.get("project", {}).get("dependencies", []))
        poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        deps += list(poetry) if isinstance(poetry, dict) else []
        for dep in deps:
            m = _PY_NAME.match(str(dep))
            if m:
                names.add(m.group(1).lower())
        return names
    for line in text.splitlines():
        if line.strip().startswith(("#", "-")):
            continue
        m = _PY_NAME.match(line)
        if m:
            names.add(m.group(1).lower())
    return names


def detect(index: FileIndex) -> list[str]:
    found: list[str] = []

    def add(key: str) -> None:
        if key not in found:
            found.append(key)

    for rel in index.iter(include_lockfiles=True):  # skips test folders and fixtures
        name = basename(rel)
        if name == "package.json":
            add("node")
            try:
                data = json.loads(index.read(rel) or "{}")
            except json.JSONDecodeError:
                continue
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for dep in (data.get(section) or {}):
                    if dep in _NPM:
                        add(_NPM[dep])
        elif name in ("pyproject.toml", "Pipfile") or (name.startswith("requirements") and name.endswith(".txt")):
            add("python")
            for dep in _python_names(index, rel):
                if dep in _PY:
                    add(_PY[dep])
        elif name.startswith("next.config."):
            add("nextjs")
        elif name in ("firestore.rules", "storage.rules", "database.rules.json", "firebase.json"):
            add("firebase")
        elif name == "Dockerfile" or name.startswith(("Dockerfile.", "Containerfile")) or (
                name.lower().startswith(("docker-compose", "compose.")) and name.endswith((".yml", ".yaml"))):
            add("docker")
        elif name.endswith((".tf", ".tfvars")):
            add("terraform")
        elif name.endswith((".yml", ".yaml")) and not rel.startswith(".github/") and re.search(
                r"(?m)^apiVersion:\s*\S+[\s\S]*^kind:\s*(?:Deployment|Pod|Service|StatefulSet|DaemonSet|Ingress|Secret|"
                r"ConfigMap|Job|CronJob)\b", index.read(rel) or ""):
            add("kubernetes")
        elif name in ("tauri.conf.json", "tauri.conf.json5", "Tauri.toml"):
            add("tauri")
        elif name == "Cargo.toml":
            add("rust")
            if re.search(r"(?m)^\s*tauri\s*=", index.read(rel) or ""):
                add("tauri")
        if rel.startswith("supabase/") or "/supabase/migrations/" in rel:
            add("supabase")
        if rel.startswith(".github/workflows/"):
            add("github-actions")
    if "nextjs" in found and "react" not in found:
        found.append("react")
    return found


def coverage(stack: list[str]) -> tuple[list[str], list[str]]:
    """(deep-check labels, generic-only labels) for display."""
    deep = [LABELS.get(s, s) for s in stack if s in DEEP_PACKS]
    generic = [LABELS.get(s, s) for s in stack if s not in DEEP_PACKS and s not in ("node", "python")]
    return deep, generic
