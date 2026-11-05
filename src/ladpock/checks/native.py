# ladpock-ignore-file: LP-NATIVE-001, LP-NATIVE-002, LP-NATIVE-003, LP-NATIVE-004, LP-SHELL-001, LP-SHELL-002, LP-SHELL-003, LP-SHELL-004, LP-SHELL-005, LP-SOL-001, LP-SOL-002, LP-SOL-003 (this file defines those patterns)
"""Software that isn't a web app: C and C++, shell and PowerShell scripts, Solidity
contracts, and things any desktop or command-line program can get wrong.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..files import JS_EXT, PY_EXT
from ..jsparse import capped, line_of, match_bracket, strip_comments
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, grep, near, regex_check

C = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm"})
SCRIPT = frozenset({".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd"})
BUILD_NAMES = {"Makefile", "Dockerfile", "Procfile"}
CI = frozenset({".yml", ".yaml"})
SOL = frozenset({".sol"})
RUST = frozenset({".rs"})
CS = frozenset({".cs"})

# ---------- C and C++ ----------

_NO_BOUNDS = re.compile(r"(?<![\w.>])(gets|strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat|lstrcpy\w?|lstrcat\w?)\s*\(")
_SCANF_S = re.compile(r"(?<![\w.>])f?scanf\s*\([^;\n]*\"[^\"\n]*%s")


@check(
    "LP-NATIVE-001", "Function with no bounds check (buffer overflow)", "injection", Severity.HIGH,
    why="This writes to a buffer without knowing how big it is. Input longer than the buffer overwrites memory next to it, which is "
        "the classic way to crash a program or take it over.",
    fix="Use a version that takes the buffer's size (snprintf, strlcpy, fgets), or in C++ use std::string.",
    cwe=("CWE-120", "CWE-787"),
)
def no_bounds(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, lineno, line, match in grep(ctx, _NO_BOUNDS, exts=C):
        unavoidable = match.group(1) == "gets"
        yield ctx.finding(info, rel, lineno, line, confidence="high" if unavoidable else "medium")
    for rel, lineno, line, _ in grep(ctx, _SCANF_S, exts=C):
        yield ctx.finding(info, rel, lineno, line)


regex_check(
    "LP-NATIVE-002", "Text printed using a variable as the format", "injection", Severity.HIGH,
    why="If the variable can hold user input, someone can put %x or %n in it to read or overwrite the program's memory.",
    fix='Always give a fixed format: printf("%s", text).',
    pattern=r"(?<![\w.>])(?:printf\s*\(\s*[a-zA-Z_]\w*(?:->\w+|\.\w+|\[[^\]]*\])*\s*\)|fprintf\s*\(\s*\w+\s*,\s*[a-zA-Z_]\w*(?:->\w+|\.\w+)*\s*\)|syslog\s*\(\s*\w+\s*,\s*[a-zA-Z_]\w*\s*\))",
    exts=C, cwe=("CWE-134",),
)
regex_check(
    "LP-NATIVE-003", "Program runs a shell command it built itself", "injection", Severity.HIGH,
    why="Anything in this string that came from input can add commands of its own, for example ; rm -rf ~.",
    fix="Call the program directly with its arguments in a list (execve or posix_spawn), and don't go through a shell.",
    pattern=r"(?<![\w.>])(?:system|popen|_popen|_wsystem|ShellExecuteA?W?)\s*\(\s*(?!\")(?:NULL\s*,\s*[^,]+,\s*)?[a-zA-Z_]",
    exts=C, cwe=("CWE-78",), unless=r"#define|\bvoid\b|\bint\s+system\b",
)
regex_check(
    "LP-NATIVE-004", "Temporary file name that can be guessed", "injection", Severity.MEDIUM,
    why="The name is chosen before the file is created, so another program can create it first, or put a link there, and make your "
        "program overwrite or read something else.",
    fix="Use a function that creates the file safely in one step: mkstemp, tempfile.mkstemp or NamedTemporaryFile.",
    pattern=r"(?<![\w.>])(?:tmpnam|tempnam|mktemp|tmpnam_s)\s*\(|\btempfile\.mktemp\s*\(|\bos\.tmpnam\s*\(",
    exts=C | PY_EXT, cwe=("CWE-377",),
)

_DOWNLOAD_CALL = r"(?:DownloadFile\w*|DownloadData\w*|GetByteArrayAsync|GetStreamAsync|urlretrieve|urlopen|requests\.get|httpx\.get|fetch|axios\.get|http\.Get|wget|curl|Invoke-WebRequest|iwr)"
regex_check(
    "LP-NATIVE-005", "Program downloaded over plain HTTP", "supply-chain", Severity.HIGH,
    why="Anyone between you and that server can swap the file, and this program is about to be installed or run. It's a common way "
        "for an update feature to become a way in.",
    fix="Download over HTTPS and check the file's signature or checksum before using it.",
    pattern=_DOWNLOAD_CALL + r"""[^\n]{0,80}['"`\s]http://[^\s'"`]+\.(?:exe|msi|dll|dmg|pkg|deb|rpm|sh|ps1|bat|jar|apk|appimage|bin|whl|tgz)\b""",
    exts=C | PY_EXT | JS_EXT | CS | SCRIPT | CI | RUST | frozenset({".go", ".java", ".kt", ".swift", ".rb", ".php"}), cwe=("CWE-494", "CWE-319"),
    flags=re.I, names=BUILD_NAMES,
)

# ---------- shell and PowerShell ----------

regex_check(
    "LP-SHELL-001", "Script runs text as a command", "injection", Severity.HIGH,
    why="Whatever is in that variable is run as code. If any of it comes from an argument, a file, a pull request title or the "
        "network, whoever controls it can run commands as you.",
    fix="Run the command directly with its arguments, or use a case statement for the options you expect.",
    pattern=r"""^\s*eval\s+["']?[^"'#\n]*\$|\b(?:Invoke-Expression|iex)\s+(?:\(|["']?\$)""",
    exts=SCRIPT, cwe=("CWE-78", "CWE-95"), flags=re.I,
)
regex_check(
    "LP-SHELL-002", "Files made writable by everyone", "config", Severity.MEDIUM,
    why="Any user or program on the machine can then change these files, including scripts your app or a root job will run.",
    fix="Give the owner what it needs and no more, for example chmod 750 for a program or 640 for a config file.",
    pattern=r"\bchmod\s+(?:-\w+\s+)*(?:0?777|a\+w|o\+w|ugo\+w)\b|\bos\.chmod\([^)\n]*0o?777\b|\bfs\.chmod(?:Sync)?\([^)\n]*0o?777\b",
    exts=SCRIPT | CI | PY_EXT | JS_EXT, names=BUILD_NAMES, cwe=("CWE-732",),
)
regex_check(
    "LP-SHELL-003", "Deletes a path that could turn out empty", "vibe", Severity.MEDIUM,
    why="If the variable is empty or unset, this becomes rm -rf /. Mistakes like this have wiped home folders and whole machines.",
    fix='Stop if it\'s unset: rm -rf "${DIR:?}/" and start the script with set -u.',
    pattern=r"""\brm\s+-[a-zA-Z]*(?:rf|fr)[a-zA-Z]*\s+["']?\$\{?\w+\}?(?:/\S*)?["']?""",
    exts=SCRIPT | CI, names=BUILD_NAMES, cwe=("CWE-73",), unless=r":\?", confidence="low",
)
regex_check(
    "LP-SHELL-004", "Script turns off a safety check", "config", Severity.MEDIUM,
    why="This turns off the check that stops scripts, downloads or connections being tampered with. It makes the error go away by "
        "removing the protection.",
    fix="Fix the underlying problem: sign the script, install the right certificate, or add the host's key to known_hosts.",
    pattern=r"\bcurl\b[^\n|]*\s(?:-k\b|-[a-zA-Z]*k[a-zA-Z]*\b|--insecure\b)|\bwget\b[^\n|]*--no-check-certificate\b|\bStrictHostKeyChecking[= ]+no\b|"
            r"\bUserKnownHostsFile[= ]+/dev/null\b|-ExecutionPolicy\s+(?:Bypass|Unrestricted)\b|Set-ExecutionPolicy\s+(?:\S+\s+)?(?:Bypass|Unrestricted)\b|"
            r"\bgit\s+config\b[^\n]*http\.sslVerify\s+false\b|\bAutoAddPolicy\(\)|\bgit\s+-c\s+http\.sslVerify=false\b",
    exts=SCRIPT | CI | PY_EXT, names=BUILD_NAMES, cwe=("CWE-295", "CWE-322"), flags=re.I,
)
regex_check(
    "LP-SHELL-005", "Password written on a command line", "secrets", Severity.HIGH,
    why="Passwords on a command line are visible to anyone listing processes on the machine, and they end up in shell history and "
        "CI logs. This one is also in your code, so anyone who can read the repository has it.",
    fix="Read it from an environment variable or a secret store, and change it, since it has been exposed.",
    pattern=r"""\bsshpass\s+-p\s*['"]?[^\s$'"]{3,}|\bmysql\b[^\n]*\s-p[^\s$'"-][^\s]*|\bcurl\b[^\n]*\s(?:-u|--user)\s+['"]?[^\s:$'"]+:[^\s$'"]{3,}|"""
            r"""--password[= ]['"]?[^\s$'"{%<]{3,}|\bConvertTo-SecureString\s+['"][^'"$]+['"]\s+-AsPlainText""",
    exts=SCRIPT | CI, names=BUILD_NAMES, cwe=("CWE-214", "CWE-798"),
    unless=r"(?i)\bpassword\b[= ]+['\"]?(?:password|changeme|example|your|\*+|xxx)|\$\{\{",
)

# ---------- Rust ----------

_SHELL_IN_RUST = re.compile(r"""Command::new\(\s*"(?:sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh)"\s*\)""")
_FORMATTED_ARG = re.compile(r"\.args?\(\s*(?:\[[^\]\n]*)?&?format!\(")


@check(
    "LP-RUST-002", "Shell command built with format!", "injection", Severity.HIGH,
    why="The values placed in this string are read by a shell, so a value containing ; or $(...) runs commands of its own.",
    fix='Run the program directly and pass each value with .arg(value): Command::new("git").arg("clone").arg(url).',
    cwe=("CWE-78",),
)
def rust_shell(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, lineno, line, _ in grep(ctx, _FORMATTED_ARG, exts=RUST):
        if near(ctx.index.lines(rel), lineno, _SHELL_IN_RUST, 4):
            yield ctx.finding(info, rel, lineno, line)


regex_check(
    "LP-RUST-003", "SQL query built with format!", "injection", Severity.HIGH,
    why="Values placed straight into SQL can change what the query does, so someone can read or destroy data (SQL injection).",
    fix='Use bind parameters: sqlx::query("SELECT ... WHERE id = $1").bind(id).',
    pattern=r"(?:\bquery(?:_as|_scalar)?(?:::<[^>]*>)?|\.execute|\.query_row|\.prepare|\.query_map|\.fetch_one|\.fetch_all)\(\s*&?format!\(",
    exts=RUST, cwe=("CWE-89",),
)

# ---------- Solidity ----------

regex_check(
    "LP-SOL-001", "Contract trusts tx.origin", "authz", Severity.HIGH,
    why="tx.origin is whoever started the transaction, not who called this contract. A malicious contract a user interacts with can "
        "pass this check as that user and take what's theirs.",
    fix="Use msg.sender for authorization.",
    pattern=r"\btx\.origin\b",
    exts=SOL, cwe=("CWE-477", "CWE-346"), unless=r"msg\.sender\s*==\s*tx\.origin|tx\.origin\s*==\s*msg\.sender", confidence="high",
)

_FUNCTION = re.compile(r"\bfunction\s+(\w+)\s*\(([^)]*)\)([^{;]*)\{")
_SENDS_VALUE = re.compile(r"\.call\s*\{[^}]*value\s*:|\.call\.value\(|\.send\(|\.transfer\(")
_STATE_WRITE = re.compile(r"(?m)(?:^|[;{])\s*\w+(?:\[[^\]]*\])+\s*[-+*/]?=[^=]|(?:^|[;{])\s*\w+(?:\.\w+)*\s*[-+*/]=")
_REENTRANCY_GUARD = re.compile(r"\bnonReentrant\b|\bReentrancyGuard\b")
_SENSITIVE_FN = re.compile(r"(?i)^(?:mint\w*|withdraw\w*|setOwner|changeOwner|transferOwnership|upgradeTo\w*|setAdmin|addAdmin|kill|destroy|pause|unpause|setFee\w*|setPrice\w*|sweep\w*|drain\w*|burnFrom|setImplementation|initialize)$")
_ACCESS_MODIFIER = re.compile(r"(?i)\b(?:only\w+|requiresAuth|auth|restricted|initializer|whenAdmin|isAdmin|isOwner)\b")
_ACCESS_CHECK = re.compile(r"\b(?:require|if)\s*\([^;{]*msg\.sender|_checkOwner\(|_checkRole\(|hasRole\(|\bassert\s*\([^;]*msg\.sender|_msgSender\(\)\s*[=!]=")
_WEAK_RANDOM = re.compile(r"\bkeccak256\s*\([^;]*\b(?:block\.(?:timestamp|difficulty|prevrandao|number|coinbase)|blockhash)\b|\bblock\.(?:timestamp|difficulty|prevrandao)\s*%")
_OLD_COMPILER = re.compile(r"\bpragma\s+solidity\s+[\^~>=<\s]*0\.[0-7]\.\d+")


def _contract_functions(ctx: ScanContext) -> Iterator[tuple[str, str, re.Match[str], str]]:
    for rel in ctx.index.sources(SOL):
        code = strip_comments(ctx.index.read(rel) or "", quotes='"\'')
        for match in capped(_FUNCTION.finditer(code)):
            close = match_bracket(code, match.end() - 1, quotes='"\'')
            yield rel, code, match, code[match.end(): close] if close != -1 else ""


@check(
    "LP-SOL-002", "Contract sends money before updating its records", "authz", Severity.HIGH,
    why="Sending ETH runs the receiver's code, which can call this function again before the balance is updated and take the money "
        "repeatedly (reentrancy, the bug behind the DAO hack).",
    fix="Update balances before sending (checks-effects-interactions), and add OpenZeppelin's nonReentrant.",
    cwe=("CWE-841",),
)
def reentrancy(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, code, match, body in _contract_functions(ctx):
        send = _SENDS_VALUE.search(body)
        if send and not _REENTRANCY_GUARD.search(match.group(3)) and _STATE_WRITE.search(body, send.end()):
            yield ctx.finding(info, rel, line_of(code, match.start()), match.group(0)[:150])


@check(
    "LP-SOL-003", "Sensitive contract function anyone can call", "authz", Severity.CRITICAL,
    why="This function looks like it mints, withdraws or changes ownership, and it's callable by anyone. Contracts can't be patched "
        "after deployment, so this can mean losing everything held in it.",
    fix="Add an access check such as OpenZeppelin's onlyOwner or AccessControl's onlyRole. Get an audit before deploying a contract "
        "that holds value.",
    cwe=("CWE-284", "CWE-862"),
)
def open_contract_function(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, code, match, body in _contract_functions(ctx):
        name, header = match.group(1), match.group(3)
        if not _SENSITIVE_FN.match(name) or not re.search(r"\b(?:public|external)\b", header):
            continue
        if re.search(r"\b(?:view|pure)\b", header) or _ACCESS_MODIFIER.search(header) or _ACCESS_CHECK.search(body):
            continue
        # withdraw() that only sends the caller their own balance is the normal pattern.
        if re.match(r"(?i)withdraw", name) and re.search(r"\[\s*msg\.sender\s*\]", body):
            continue
        yield ctx.finding(info, rel, line_of(code, match.start()), match.group(0)[:150])


regex_check(
    "LP-SOL-004", "Randomness a miner can predict", "crypto", Severity.MEDIUM,
    why="Everything on the chain is public, and block values can be influenced by whoever produces the block, so a lottery or mint "
        "based on them can be gamed.",
    fix="Use a verifiable randomness service such as Chainlink VRF, or a commit-reveal scheme.",
    pattern=_WEAK_RANDOM.pattern,
    exts=SOL, cwe=("CWE-330",),
)
regex_check(
    "LP-SOL-005", "Old Solidity version with unchecked arithmetic", "config", Severity.MEDIUM,
    why="Before version 0.8, numbers silently wrap around on overflow, which has been used to mint huge token balances out of nothing.",
    fix="Move to Solidity 0.8 or later, where overflow reverts, and pin an exact compiler version.",
    pattern=_OLD_COMPILER.pattern,
    exts=SOL, cwe=("CWE-190",),
)
regex_check(
    "LP-SOL-006", "Contract can run code it's handed, or destroy itself", "authz", Severity.HIGH,
    why="delegatecall runs another contract's code with this contract's storage and funds, so calling an address that isn't fixed gives "
        "whoever chooses it full control. selfdestruct can remove the contract and send away what it holds.",
    fix="Only delegatecall a fixed, trusted implementation behind a reviewed proxy pattern, and remove selfdestruct.",
    pattern=r"\.delegatecall\s*\(|\bselfdestruct\s*\(|\bsuicide\s*\(",
    exts=SOL, cwe=("CWE-829", "CWE-284"), confidence="low",
)
