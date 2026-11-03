"""Containers and infrastructure as code: Dockerfiles, Docker Compose,
Kubernetes manifests, Terraform, and GitHub Actions workflows.

These files decide who can reach your app and what a compromised container can
do, and AI assistants copy insecure examples of them as readily as code.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..files import basename, ext
from ..masking import is_placeholder
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check

YAML = frozenset({".yml", ".yaml"})
TF = frozenset({".tf", ".tfvars", ".hcl"})
DB_PORTS = {"5432", "3306", "27017", "27018", "6379", "9200", "9300", "5984", "11211", "1433", "1521", "8086", "9042",
            "2379", "5672", "15672", "7474", "7687", "8529", "26257", "6380", "3307", "33060"}
ADMIN_PORTS = {"22", "3389", "5900", "2375", "2376", "6443", "10250", "10255", "2049", "445", "139"}


def is_dockerfile(rel: str) -> bool:
    name = basename(rel)
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile") or name == "Containerfile"


def is_compose(rel: str) -> bool:
    name = basename(rel).lower()
    return ext(rel) in YAML and (name.startswith(("docker-compose", "compose.", "compose-")) or name == "compose.yaml")


def is_workflow(rel: str) -> bool:
    return rel.startswith(".github/workflows/") and ext(rel) in YAML


def k8s_files(ctx: ScanContext) -> Iterator[tuple[str, str]]:
    for rel in ctx.index.iter(YAML):
        if is_workflow(rel) or is_compose(rel):
            continue
        text = ctx.index.read(rel) or ""
        if re.search(r"(?m)^apiVersion:\s*\S+", text) and re.search(r"(?m)^kind:\s*\w+", text):
            yield rel, text


def _files(ctx: ScanContext, pred) -> Iterator[str]:
    yield from ctx.index.iter(pred=pred)


def _lines(ctx: ScanContext, rel: str) -> Iterator[tuple[int, str]]:
    for i, line in enumerate(ctx.index.lines(rel), 1):
        if not line.lstrip().startswith("#"):
            yield i, line


# ---------- Dockerfiles ----------


@check(
    "LP-DOCKER-001", "Container runs as root", "config", Severity.MEDIUM,
    why="Without a USER instruction the app runs as root inside the container. If it's ever compromised, the attacker "
        "has full control of the container and a much easier path to the host.",
    fix="Create an unprivileged user and switch to it before CMD (for example RUN adduser -D app && USER app), or use "
        "a base image that already runs as non-root (distroless :nonroot, node's 'node' user).",
    cwe=("CWE-250",),
)
def docker_root(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in _files(ctx, is_dockerfile):
        lines = ctx.index.lines(rel)
        stages = [i for i, line in enumerate(lines) if re.match(r"(?i)^\s*FROM\s", line)]
        if not stages:
            continue
        final = lines[stages[-1]]
        if re.search(r"(?i)\bscratch\b|nonroot|chainguard|distroless.*:nonroot", final):
            continue
        users = [line for line in lines[stages[-1]:] if re.match(r"(?i)^\s*USER\s+\S", line)]
        if users and not re.match(r"(?i)^\s*USER\s+(?:root|0)(?::\S+)?\s*$", users[-1]):
            continue
        yield ctx.finding(info, rel, stages[-1] + 1, final, confidence="medium" if not users else "high")


SECRET_NAME = r"\w*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS)\w*"


@check(
    "LP-DOCKER-002", "Secret baked into the container image", "secrets", Severity.HIGH,
    why="Values set with ENV or ARG, and files copied into the image, stay in its layers. Anyone who can pull the "
        "image (a registry, a CI cache, a teammate) can read them with docker history or by unpacking it.",
    fix="Pass secrets at runtime (environment from your platform's secret store, Docker secrets, or mounted files), "
        "or use BuildKit's RUN --mount=type=secret for build-time secrets. Rotate anything already baked in.",
    cwe=("CWE-538", "CWE-798"),
)
def docker_secret(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    env = re.compile(rf"(?i)^\s*(?:ENV|ARG)\s+({SECRET_NAME})(?:\s*=\s*|\s+)(\S+)")
    copy = re.compile(r"(?i)^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*(?:\S*/)?(?:\.env(?:\.\w+)?|id_rsa|id_ed25519|\S*\.pem|\S*\.key|"
                      r"credentials\.json|service-account\S*\.json|\.npmrc|\.pypirc)\s")
    for rel in _files(ctx, is_dockerfile):
        for i, line in _lines(ctx, rel):
            match = env.match(line)
            if match:
                value = match.group(2).strip("'\"")
                if value and not value.startswith("$") and not is_placeholder(value):
                    yield ctx.finding(info, rel, i, line, confidence="high")
            elif copy.match(line) and not re.search(r"(?i)\.env\.(?:example|sample|template)", line):
                yield ctx.finding(info, rel, i, line,
                                  message="A credentials file is copied into the image. " + info.why)


@check(
    "LP-DOCKER-003", "Script downloaded and run in one step", "supply-chain", Severity.MEDIUM,
    why="curl ... | sh runs whatever the server returns at that moment, unchecked. A compromised or spoofed download "
        "runs straight on your build machine or inside your image.",
    fix="Download to a file, check its SHA-256 against a pinned value, then run it. Better, install from your package "
        "manager or a pinned release.",
    cwe=("CWE-494",),
)
def pipe_to_shell(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"(?i)\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:-\S+\s+)*(?:ba|z|da)?sh\b|"
                         r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;\n]*\|\s*(?:iex|Invoke-Expression)\b")
    targets = lambda rel: is_dockerfile(rel) or ext(rel) in {".sh", ".ps1", ".bash"} or is_workflow(rel)  # noqa: E731
    for rel in _files(ctx, targets):
        for i, line in _lines(ctx, rel):
            if pattern.search(line):
                yield ctx.finding(info, rel, i, line)


@check(
    "LP-DOCKER-004", "Base image not pinned", "supply-chain", Severity.LOW,
    why="FROM node or node:latest pulls whatever the tag points to today, so builds change underneath you and a "
        "compromised tag ships straight into your image.",
    fix="Pin a specific version tag, ideally with its digest (FROM node:22.11-alpine@sha256:...), and let Dependabot "
        "or Renovate propose updates.",
    cwe=("CWE-1357",),
)
def unpinned_base(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    from_line = re.compile(r"(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?")
    for rel in _files(ctx, is_dockerfile):
        stages: set[str] = set()
        for i, line in _lines(ctx, rel):
            match = from_line.match(line)
            if not match:
                continue
            image = match.group(1)
            if match.group(2):
                stages.add(match.group(2).lower())
            if image.lower() in stages or image.lower() == "scratch" or "$" in image or "@sha256:" in image:
                continue
            tag = image.rsplit("/", 1)[-1].partition(":")[2]
            if not tag or tag == "latest":
                yield ctx.finding(info, rel, i, line, confidence="high")


# ---------- containers: Compose and Kubernetes ----------


@check(
    "LP-INFRA-001", "Container can take over the host", "config", Severity.HIGH,
    why="Privileged containers, host networking or PID namespaces, extra kernel capabilities and a mounted Docker "
        "socket all let anything running in the container control the machine it runs on.",
    fix="Remove privileged mode and host namespaces, drop all capabilities and add back only what's needed, never "
        "mount /var/run/docker.sock into an app container, and set allowPrivilegeEscalation: false.",
    cwe=("CWE-250", "CWE-269"),
)
def host_takeover(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(
        r"^\s*(?:-\s*)?(?:privileged:\s*true|network_mode:\s*['\"]?host|pid:\s*['\"]?host|ipc:\s*['\"]?host|"
        r"hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true|allowPrivilegeEscalation:\s*true|runAsUser:\s*0\b)|"
        r"/var/run/docker\.sock|^\s*-\s*['\"]?(?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE)['\"]?\s*$|"
        r"^\s*path:\s*['\"]?/['\"]?\s*$"
    )
    files = [rel for rel in ctx.index.iter(YAML) if is_compose(rel)] + [rel for rel, _ in k8s_files(ctx)]
    for rel in files:
        lines = ctx.index.lines(rel)
        for i, line in _lines(ctx, rel):
            if not pattern.search(line):
                continue
            capability = re.match(r"^\s*-\s*['\"]?(?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE)", line)
            if capability and _parent_key(lines, i - 1) not in ("cap_add", "add"):
                continue  # dropping ALL is the right thing to do
            if re.match(r"^\s*path:", line) and not any("hostPath" in l for l in lines[max(0, i - 4): i - 1]):
                continue
            yield ctx.finding(info, rel, i, line, confidence="high")


def _parent_key(lines: list[str], index: int) -> str | None:
    """The YAML key a list item belongs to (cap_add, drop ...)."""
    for k in range(index - 1, max(-1, index - 12), -1):
        match = re.match(r"^\s*([\w-]+)\s*:\s*$", lines[k])
        if match:
            return match.group(1)
    return None


@check(
    "LP-INFRA-002", "Database or admin port open on every network interface", "config", Severity.MEDIUM,
    why="Publishing a database, cache or admin port as 5432:5432 binds it to every network interface, so anyone who "
        "can reach the machine (often the whole internet on a cloud VM) can try to log in. Docker also bypasses most "
        "host firewalls like ufw.",
    fix="Don't publish database ports at all (other containers reach them over the Compose network), or bind them "
        "to localhost: 127.0.0.1:5432:5432.",
    cwe=("CWE-668",),
)
def open_db_port(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    port = re.compile(r"^\s*-\s*['\"]?(?:(0\.0\.0\.0|\[::\]|[\d.]+):)?(\d+):(\d+)(?:/\w+)?['\"]?\s*$")
    for rel in ctx.index.iter(YAML):
        if not is_compose(rel):
            continue
        for i, line in _lines(ctx, rel):
            match = port.match(line)
            if not match:
                continue
            host_ip, _, inner = match.groups()
            if host_ip and host_ip not in ("0.0.0.0", "[::]"):
                continue
            if inner in DB_PORTS or inner in ADMIN_PORTS:
                yield ctx.finding(info, rel, i, line, confidence="high")


@check(
    "LP-INFRA-003", "Database with a default or empty password", "auth", Severity.MEDIUM,
    why="Default credentials like postgres/postgres, an empty root password or 'trust' authentication are the first "
        "thing automated scanners try against exposed databases.",
    fix="Set a long random password from a secret (an env file that isn't committed, Docker secrets, or your "
        "platform's secret store) and never use trust authentication outside a throwaway local setup.",
    cwe=("CWE-1393", "CWE-521"),
)
def default_db_password(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    weak = r"(?:postgres|password|pass|example|admin|root|secret|changeme|123456|mysql|mongo|test)?"
    pattern = re.compile(
        rf"(?i)\b(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MARIADB_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|"
        rf"RABBITMQ_DEFAULT_PASS|REDIS_PASSWORD|MSSQL_SA_PASSWORD|SA_PASSWORD)['\"]?\s*[:=]\s*['\"]?{weak}['\"]?\s*$|"
        r"\bMYSQL_ALLOW_EMPTY_PASSWORD['\"]?\s*[:=]\s*['\"]?(?:yes|true|1)|\bPOSTGRES_HOST_AUTH_METHOD['\"]?\s*[:=]\s*['\"]?trust"
    )
    files = [rel for rel in ctx.index.iter(YAML) if is_compose(rel)] + [rel for rel, _ in k8s_files(ctx)]
    for rel in files + list(_files(ctx, is_dockerfile)):
        for i, line in _lines(ctx, rel):
            if pattern.search(line.replace("- ", "", 1)):
                yield ctx.finding(info, rel, i, line)


@check(
    "LP-INFRA-004", "Kubernetes Secret committed with its values", "secrets", Severity.HIGH,
    why="A Secret manifest only base64-encodes its values, which isn't encryption. Committing it publishes the "
        "credentials to everyone with access to the repository and its history.",
    fix="Keep real Secret values out of git: use Sealed Secrets, SOPS, External Secrets or your cloud's secret "
        "manager, and rotate anything that was committed.",
    cwe=("CWE-312", "CWE-798"),
)
def k8s_secret(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, text in k8s_files(ctx):
        for doc_start, doc in _documents(text):
            if not re.search(r"(?m)^kind:\s*Secret\s*$", doc):
                continue
            match = re.search(r"(?m)^(?:data|stringData):\s*\n((?:[ \t]+\S.*\n?)+)", doc)
            if not match:
                continue
            values = re.findall(r"(?m)^[ \t]+[\w.-]+:\s*['\"]?([^'\"\s#{][^'\"\n]*)", match.group(1))
            if any(v.strip() and not is_placeholder(v) for v in values):
                lineno = text.count("\n", 0, doc_start + match.start()) + 1
                yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1], confidence="high")


def _documents(text: str) -> Iterator[tuple[int, str]]:
    start = 0
    for match in re.finditer(r"(?m)^---\s*$", text):
        yield start, text[start: match.start()]
        start = match.end()
    yield start, text[start:]


@check(
    "LP-INFRA-005", "Container has no CPU or memory limit", "abuse", Severity.LOW,
    why="Without limits, one runaway or attacked container can use all the node's CPU and memory and take down "
        "everything else running there.",
    fix="Set resources.requests and resources.limits for every container (memory especially).",
    cwe=("CWE-770",),
)
def k8s_no_limits(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, text in k8s_files(ctx):
        for doc_start, doc in _documents(text):
            if not re.search(r"(?m)^kind:\s*(?:Deployment|StatefulSet|DaemonSet|Pod|Job|CronJob|ReplicaSet)\s*$", doc):
                continue
            match = re.search(r"(?m)^\s*containers:\s*$", doc)
            if match and not re.search(r"(?m)^\s*limits:\s*$", doc):
                lineno = text.count("\n", 0, doc_start + match.start()) + 1
                yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1])


# ---------- Terraform ----------


def tf_files(ctx: ScanContext) -> Iterator[str]:
    yield from ctx.index.iter(TF)


@check(
    "LP-TF-001", "Storage bucket open to the public", "config", Severity.HIGH,
    why="A public bucket or blob container lets anyone on the internet list or download its files. Leaked backups, "
        "uploads and exports from public buckets are one of the most common causes of data breaches.",
    fix="Keep buckets private (block all public access), serve public files through a CDN with signed URLs or an "
        "origin access identity, and grant access to specific identities instead of allUsers.",
    cwe=("CWE-284", "CWE-732"),
)
def public_bucket(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(
        r"\bacl\s*=\s*\"public-read(?:-write)?\"|\b(?:block_public_acls|block_public_policy|ignore_public_acls|"
        r"restrict_public_buckets)\s*=\s*false\b|\"allUsers\"|\"allAuthenticatedUsers\"|"
        r"\ballow_nested_items_to_be_public\s*=\s*true\b|\ballow_blob_public_access\s*=\s*true\b|"
        r"\bcontainer_access_type\s*=\s*\"(?:blob|container)\"|\"Principal\"\s*:\s*\"\*\"|\bpublic_access_prevention\s*=\s*\"inherited\""
    )
    for rel in tf_files(ctx):
        for i, line in _lines(ctx, rel):
            if pattern.search(line):
                yield ctx.finding(info, rel, i, line, confidence="high")


@check(
    "LP-TF-002", "Firewall open to the internet on a sensitive port", "config", Severity.HIGH,
    why="Allowing 0.0.0.0/0 to reach SSH, RDP, a database or every port exposes it to constant automated attacks "
        "from the whole internet.",
    fix="Restrict the source to your own IP ranges or a VPN, use SSM / IAP / a bastion for admin access, and keep "
        "databases on private subnets reachable only from your app.",
    cwe=("CWE-284",),
)
def open_firewall(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    anywhere = re.compile(r"\"0\.0\.0\.0/0\"|\"::/0\"|source_address_prefix\s*=\s*\"(?:\*|Internet)\"")
    risky = re.compile(r"\b(?:from_port|to_port|port|destination_port_range|destination_port_ranges|ports)\s*=\s*\[?\s*\"?"
                       r"(\d+|\*)\"?|\bprotocol\s*=\s*\"(?:-1|all|\*)\"")
    for rel in tf_files(ctx):
        lines = ctx.index.lines(rel)
        for i, line in _lines(ctx, rel):
            if not anywhere.search(line):
                continue
            block = _tf_block(lines, i - 1)
            if re.search(r"\begress\b|direction\s*=\s*\"Outbound\"|type\s*=\s*\"egress\"", block):
                continue
            ports = {m.group(1) for m in risky.finditer(block) if m.group(1)}
            all_ports = bool(re.search(r"\bprotocol\s*=\s*\"(?:-1|all|\*)\"", block)) or "*" in ports or \
                bool(re.search(r"from_port\s*=\s*0\b[\s\S]*to_port\s*=\s*65535", block))
            sensitive = ports & (DB_PORTS | ADMIN_PORTS)
            if all_ports or sensitive:
                detail = "every port" if all_ports else "port " + ", ".join(sorted(sensitive))
                yield ctx.finding(info, rel, i, line, confidence="high",
                                  message=f"The whole internet can reach {detail}. " + info.why)


def _tf_block(lines: list[str], index: int) -> str:
    """The innermost { } block around a line (ingress {...}, a security group rule, a firewall resource)."""
    start = index
    depth = 0
    while start > 0:
        line = lines[start]
        depth += line.count("}") - line.count("{") if start != index else 0
        if depth < 0:
            break
        start -= 1
    end = index
    depth = 0
    while end < len(lines) - 1:
        line = lines[end]
        depth += line.count("{") - line.count("}") if end != index else 0
        if depth < 0:
            break
        end += 1
    return "\n".join(lines[max(0, start - 1): end + 1])


@check(
    "LP-TF-003", "Database reachable from the internet or stored unencrypted", "config", Severity.HIGH,
    why="A publicly accessible database is one leaked or guessed password away from a full breach, and unencrypted "
        "storage means snapshots and disks expose the data directly.",
    fix="Set publicly_accessible = false and keep databases in private subnets, and turn on storage encryption "
        "(storage_encrypted = true / encryption at rest) for databases, disks and snapshots.",
    cwe=("CWE-311", "CWE-668"),
)
def exposed_database(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    public = re.compile(r"\bpublicly_accessible\s*=\s*true\b")
    unencrypted = re.compile(r"\b(?:storage_encrypted|encrypted|enable_encryption)\s*=\s*false\b")
    for rel in tf_files(ctx):
        for i, line in _lines(ctx, rel):
            if public.search(line):
                yield ctx.finding(info, rel, i, line, confidence="high")
            elif unencrypted.search(line):
                yield ctx.finding(info, rel, i, line, severity=Severity.MEDIUM,
                                  message="Encryption at rest is turned off. " + info.why)


@check(
    "LP-TF-004", "Access policy grants every permission", "authz", Severity.HIGH,
    why="A policy allowing every action (\"*\") turns any leaked key or compromised service into full control of "
        "your cloud account: data, billing and the ability to delete everything.",
    fix="Grant only the specific actions on the specific resources each role needs, and use your cloud's access "
        "analyzer to tighten existing policies.",
    cwe=("CWE-269", "CWE-732"),
)
def wildcard_policy(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"\"Action\"\s*:\s*(?:\[\s*)?\"\*\"|\bactions\s*=\s*\[\s*\"\*\"\s*\]|\"\*:\*\"|"
                         r"\brole\s*=\s*\"roles/(?:owner|editor)\"")
    for rel in ctx.index.iter(TF | {".json"}):
        for i, line in _lines(ctx, rel):
            if pattern.search(line):
                yield ctx.finding(info, rel, i, line, confidence="high")


@check(
    "LP-TF-005", "Password or key written in infrastructure code", "secrets", Severity.HIGH,
    why="Terraform files and their variables are usually committed and shared. A literal password or access key "
        "in them is readable by everyone with the repository, and also ends up in plan output and state.",
    fix="Pass secrets in through a secret manager data source or sensitive variables set from CI secrets, mark them "
        "sensitive = true, and rotate anything that was committed.",
    cwe=("CWE-798",),
)
def tf_secret(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"(?i)^\s*\"?(\w*(?:password|secret|token|access_key|secret_key|api_key|private_key)\w*)\"?\s*=\s*"
                         r"\"([^\"$]{4,})\"")
    for rel in tf_files(ctx):
        for i, line in _lines(ctx, rel):
            match = pattern.search(line)
            if match and not is_placeholder(match.group(2)) and not re.search(r"(?i)arn:|\.id\b|_name$", match.group(2)):
                if re.search(r"(?i)description|_arn|_id|_name|_length|_version|_rotation", match.group(1)):
                    continue
                yield ctx.finding(info, rel, i, line, confidence="high")
    for rel in ctx.index.iter({".tfstate"}):
        if ctx.git_files is None or rel in ctx.git_files:
            yield ctx.finding(info, rel, None, None, confidence="medium",
                              message="Terraform state holds every resource's attributes, including generated "
                                      "passwords and keys, in plain text. Keep it in a remote backend, not in git.")


# ---------- GitHub Actions ----------

UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|"
    r"head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|"
    r"pages\.\S*page_name|commits\.\S*\.(?:message|author\.\w+)|head_commit\.(?:message|author\.\w+)|"
    r"workflow_run\.head_branch)|head_ref)\s*\}\}"
)


@check(
    "LP-SUP-006", "Workflow puts untrusted text straight into a script", "supply-chain", Severity.HIGH,
    why="Issue titles, PR titles and bodies, comments and branch names are written by anyone. Placing them directly "
        "in a run: script with ${{ }} lets that text run commands in your workflow, with your repository token and "
        "secrets.",
    fix="Pass the value through an environment variable instead (env: TITLE: ${{ github.event.issue.title }}, then "
        "use \"$TITLE\" in the script), which keeps it as data.",
    cwe=("CWE-78", "CWE-94"),
    stacks=("github-actions",),
)
def workflow_injection(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(YAML, include_tests=True):
        if not is_workflow(rel):
            continue
        for i, line in _lines(ctx, rel):
            if not UNTRUSTED.search(line):
                continue
            if re.match(r"^\s*(?:-\s*)?[\w-]+\s*:\s*['\"]?\$\{\{", line) and not re.match(r"^\s*(?:-\s*)?(?:run|script)\s*:", line):
                continue  # env:/with: assignment, the safe way to pass it
            if re.match(r"^\s*if\s*:", line):
                continue
            yield ctx.finding(info, rel, i, line, confidence="high")


@check(
    "LP-SUP-007", "Workflow gives its token write access to everything", "supply-chain", Severity.MEDIUM,
    why="permissions: write-all lets every step (including third-party actions) push code, edit releases and change "
        "settings with the workflow's token.",
    fix="Set permissions: contents: read at the top of the workflow and grant extra scopes only to the jobs that "
        "need them.",
    cwe=("CWE-250",),
    stacks=("github-actions",),
)
def workflow_write_all(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter(YAML, include_tests=True):
        if not is_workflow(rel):
            continue
        for i, line in _lines(ctx, rel):
            if re.match(r"^\s*permissions\s*:\s*write-all\b", line):
                yield ctx.finding(info, rel, i, line, confidence="high")
