"""Desktop and mobile apps: Electron, Android, iOS, React Native / Expo and Flutter.

App code runs on the user's device, so the questions are different from a web
server's: what can a compromised web page inside the app reach, what does the
app store on the device, and will it talk to anyone who intercepts its traffic.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..files import JS_EXT, basename
from ..jsparse import line_of, match_bracket, strip_comments
from ..models import Finding, Severity
from .base import CheckInfo, ScanContext, check, grep, near

ELECTRON = ("electron",)
MAIN_JS = JS_EXT - {".vue", ".svelte", ".astro"}


def _electron_text(ctx: ScanContext) -> Iterator[tuple[str, str]]:
    for rel in ctx.index.iter(MAIN_JS):
        text = ctx.index.read(rel) or ""
        if "electron" in text:
            yield rel, text


def _flag(ctx: ScanContext, info: CheckInfo, pattern: re.Pattern[str], **options) -> Iterator[Finding]:
    for rel, text in _electron_text(ctx):
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if pattern.search(line) and not line.lstrip().startswith("//"):
                yield ctx.finding(info, rel, i, line, **options)


# ---------- Electron ----------


@check(
    "LP-ELEC-001", "Web page inside the app can use Node.js", "config", Severity.HIGH,
    why="With nodeIntegration on, any script that runs in the window (a dependency, an ad, or XSS from content you "
        "display) can read files, run programs and install malware on the user's computer.",
    fix="Set nodeIntegration: false (the default) and expose only the specific functions the page needs through a "
        "preload script with contextBridge.",
    cwe=("CWE-94", "CWE-829"),
    stacks=ELECTRON,
)
def node_integration(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    yield from _flag(ctx, info, re.compile(r"\bnodeIntegration(?:InWorker|InSubFrames)?\s*:\s*true\b"), confidence="high")


@check(
    "LP-ELEC-002", "Context isolation or the sandbox turned off", "config", Severity.HIGH,
    why="Context isolation keeps the page's JavaScript away from the preload script's privileged APIs, and the "
        "sandbox limits what a compromised renderer can do. Turning either off makes a page bug much more dangerous.",
    fix="Keep contextIsolation: true and sandbox: true (the defaults in current Electron) and pass data through "
        "contextBridge.",
    cwe=("CWE-653",),
    stacks=ELECTRON,
)
def isolation_off(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    yield from _flag(ctx, info, re.compile(r"\b(?:contextIsolation|sandbox)\s*:\s*false\b"), confidence="high")


@check(
    "LP-ELEC-003", "Browser security features turned off in the app", "config", Severity.HIGH,
    why="webSecurity: false turns off the same-origin policy, allowRunningInsecureContent loads scripts over plain "
        "HTTP, and the remote module hands the page main-process objects. Each one opens the app to attacks the "
        "browser normally blocks.",
    fix="Remove these overrides. Fix CORS or mixed-content problems properly instead (serve over HTTPS, call APIs "
        "from the main process).",
    cwe=("CWE-693",),
    stacks=ELECTRON,
)
def web_security_off(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    yield from _flag(ctx, info, re.compile(r"\bwebSecurity\s*:\s*false\b|\ballowRunningInsecureContent\s*:\s*true\b|"
                                           r"\benableRemoteModule\s*:\s*true\b|\bexperimentalFeatures\s*:\s*true\b"),
                     confidence="high")


@check(
    "LP-ELEC-004", "Whole IPC channel exposed to the web page", "authz", Severity.HIGH,
    why="Exposing ipcRenderer (or a send/invoke that forwards any channel name) lets script in the page call every "
        "handler in the main process, including ones meant only for internal use.",
    fix="Expose one named function per action through contextBridge (for example saveNote: (text) => "
        "ipcRenderer.invoke('save-note', text)), never ipcRenderer itself or a generic channel forwarder.",
    cwe=("CWE-749",),
    stacks=ELECTRON,
)
def ipc_exposed(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    whole = re.compile(r"exposeInMainWorld\(\s*['\"`]\w+['\"`]\s*,\s*(?:\{\s*(?:\.\.\.)?\s*)?ipcRenderer\b")
    generic = re.compile(r"\bipcRenderer\.(?:send|invoke|sendSync|on)\(\s*(?:channel|ch|name|event|eventName)\s*[,)]")
    for rel, text in _electron_text(ctx):
        if "exposeInMainWorld" not in text:
            continue
        lines = ctx.index.lines(rel)
        for i, line in enumerate(lines, 1):
            if whole.search(line):
                yield ctx.finding(info, rel, i, line, confidence="high")
            elif generic.search(line) and not near(lines, i, re.compile(r"includes\(\s*(?:channel|ch|name)|valid\w*Channels|"
                                                                          r"allowed\w*|ALLOWED"), 6):
                yield ctx.finding(info, rel, i, line)


@check(
    "LP-ELEC-005", "Link opened in the system without checking the address", "injection", Severity.MEDIUM,
    why="shell.openExternal hands the address to the operating system. A file:, smb: or custom-protocol link from "
        "page content can launch programs or leak credentials.",
    fix="Parse the URL first and only open https: (and maybe mailto:) links, for example "
        "if (new URL(url).protocol === 'https:') shell.openExternal(url).",
    cwe=("CWE-939",),
    stacks=ELECTRON,
)
def open_external(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"\bshell\.openExternal\(\s*(?!['\"`]https?://[^'\"`$]*['\"`])")
    checked = re.compile(r"new\s+URL\(|\.protocol\b|startsWith\(\s*['\"`]https|isSafeUrl|allowedHosts|ALLOWED")
    for rel, text in _electron_text(ctx):
        lines = ctx.index.lines(rel)
        for i, line in enumerate(lines, 1):
            if pattern.search(line) and not near(lines, i, checked, 5):
                yield ctx.finding(info, rel, i, line)


@check(
    "LP-ELEC-006", "New windows and navigation aren't restricted", "config", Severity.LOW,
    why="Without a window-open handler and a will-navigate check, a link or script in the page can open or navigate "
        "the app window to any website, which then runs with your app's privileges.",
    fix="Add webContents.setWindowOpenHandler(() => ({ action: 'deny' })) (opening allowed links with a checked "
        "shell.openExternal) and a 'will-navigate' handler that blocks unexpected destinations.",
    cwe=("CWE-601",),
    stacks=ELECTRON,
)
def unrestricted_navigation(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    files = list(_electron_text(ctx))
    every = "\n".join(text for _, text in files)
    if "setWindowOpenHandler" in every or "will-navigate" in every:
        return
    for rel, text in files:
        match = re.search(r"new\s+BrowserWindow\(", text)
        if match:
            lineno = text.count("\n", 0, match.start()) + 1
            yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1])
            return


@check(
    "LP-ELEC-007", "App window loads a page over plain HTTP", "config", Severity.MEDIUM,
    why="Anyone on the same network can change a page loaded over http:// before it reaches the app, and that page "
        "runs inside your app window.",
    fix="Load the app's own pages from disk (loadFile) or over https://.",
    cwe=("CWE-319",),
    stacks=ELECTRON,
)
def http_load(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    yield from _flag(ctx, info, re.compile(r"\bloadURL\(\s*['\"`]http://(?!localhost|127\.0\.0\.1|\[::1\])"))


@check(
    "LP-ELEC-008", "No Content Security Policy for the app's pages", "config", Severity.MEDIUM,
    why="A Content Security Policy limits which scripts can run in the window. Without one, any injected script "
        "runs with whatever access the window has.",
    fix="Add a strict CSP, either as a <meta http-equiv=\"Content-Security-Policy\"> tag in each HTML page or via "
        "session.defaultSession.webRequest.onHeadersReceived. Start from default-src 'self'.",
    cwe=("CWE-693",),
    stacks=ELECTRON,
)
def electron_csp(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".html", ".htm", ".js", ".ts", ".mjs", ".cjs"}):
        if "Content-Security-Policy" in (ctx.index.read(rel) or ""):
            return
    for rel, text in _electron_text(ctx):
        match = re.search(r"new\s+BrowserWindow\(", text)
        if match:
            lineno = text.count("\n", 0, match.start()) + 1
            yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1])
            return


IPC_HANDLER = re.compile(r"\bipcMain\.(?:handle|on|handleOnce|once)\(\s*['\"`]([\w:./-]+)['\"`]\s*,")
RISKY = re.compile(r"\bfs(?:/promises)?\.\w+\(|\b(?:readFile|writeFile|unlink|rm|readdir|createWriteStream|createReadStream)\w*\(|"
                   r"\b(?:exec|execSync|execFile|spawn|spawnSync|fork)\(|shell\.(?:openPath|trashItem)\(")
PATH_GUARD = re.compile(r"startsWith\(|path\.relative\(|isPathInside|\.includes\(|allowed|ALLOWED|whitelist|allowlist|"
                        r"validChannels|basename\(")


@check(
    "LP-ELEC-009", "IPC handler uses page input for files or programs", "injection", Severity.MEDIUM,
    why="Arguments sent from the window are untrusted. A handler that reads, writes or runs whatever path or "
        "command the page passes lets a compromised page reach the whole computer.",
    fix="Only accept IDs or names, map them to paths inside an allowed folder, check the resolved path with "
        "path.relative / startsWith, and never pass page input to exec or spawn.",
    cwe=("CWE-22", "CWE-78"),
    stacks=ELECTRON,
)
def ipc_file_access(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel, text in _electron_text(ctx):
        code = strip_comments(text)
        for match in IPC_HANDLER.finditer(code):
            open_idx = code.find("(", match.start())
            close = match_bracket(code, open_idx)
            if close < 0:
                continue
            body = code[match.end(): close]
            params = re.search(r"\(\s*(?:_?\w+)\s*,\s*([^)]*)\)\s*=>|function\s*\(\s*\w+\s*,\s*([^)]*)\)", body)
            names = [n.strip().split("=")[0].strip(" {}") for n in ((params.group(1) or params.group(2)) if params else "").split(",")]
            names = [n for n in names if n]
            if not names or not RISKY.search(body) or PATH_GUARD.search(body):
                continue
            if any(re.search(rf"\b{re.escape(n)}\b", m.group(0) + body[m.end(): m.end() + 120])
                   for n in names for m in RISKY.finditer(body)):
                yield ctx.finding(info, rel, line_of(code, match.start()), f"ipcMain handler '{match.group(1)}'")


# ---------- mobile ----------


@check(
    "LP-MOB-001", "App allows unencrypted HTTP traffic", "config", Severity.MEDIUM,
    why="Cleartext traffic can be read and changed by anyone on the same Wi-Fi or network path, including login "
        "tokens and API responses.",
    fix="Use HTTPS everywhere. Remove usesCleartextTraffic / cleartextTrafficPermitted on Android and "
        "NSAllowsArbitraryLoads on iOS; if one legacy host needs HTTP, allow only that domain.",
    cwe=("CWE-319",),
)
def cleartext(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(r"android:usesCleartextTraffic\s*=\s*\"true\"|cleartextTrafficPermitted\s*=\s*\"true\"")
    for rel, lineno, line, _ in grep(ctx, pattern, exts={".xml"}, skip_comments=False):
        yield ctx.finding(info, rel, lineno, line, confidence="high")
    for rel in ctx.index.iter({".plist"}, names={"Info.plist"}):
        lines = ctx.index.lines(rel)
        for i, line in enumerate(lines, 1):
            if "NSAllowsArbitraryLoads" in line and i < len(lines) and "<true/>" in (line + lines[i]):
                yield ctx.finding(info, rel, i, line, confidence="high")


@check(
    "LP-MOB-002", "Android app is debuggable or allows data backups", "config", Severity.HIGH,
    why="A debuggable release lets anyone with the phone attach a debugger and read memory and storage. allowBackup "
        "lets the app's private data (tokens, databases) be copied off the device with adb.",
    fix="Never set android:debuggable=\"true\" in the manifest (build tools set it for debug builds only), and set "
        "android:allowBackup=\"false\" or use backup rules that exclude credentials.",
    cwe=("CWE-489", "CWE-530"),
)
def android_debuggable(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".xml"}):
        if basename(rel) != "AndroidManifest.xml":
            continue
        for i, line in enumerate(ctx.index.lines(rel), 1):
            if re.search(r"android:debuggable\s*=\s*\"true\"", line):
                yield ctx.finding(info, rel, i, line, confidence="high")
            elif re.search(r"android:allowBackup\s*=\s*\"true\"", line):
                yield ctx.finding(info, rel, i, line, severity=Severity.LOW,
                                  message="android:allowBackup is on, so the app's private data can be copied off the device.")


@check(
    "LP-MOB-003", "Android component open to other apps", "authz", Severity.MEDIUM,
    why="An exported activity, service, receiver or content provider without a permission can be started or queried "
        "by any app on the phone, which may reach screens or data meant to be internal.",
    fix="Set android:exported=\"false\" unless other apps really need it, and protect exported components with "
        "android:permission (a signature-level permission for your own apps).",
    cwe=("CWE-926",),
)
def exported_components(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    for rel in ctx.index.iter({".xml"}):
        if basename(rel) != "AndroidManifest.xml":
            continue
        text = ctx.index.read(rel) or ""
        for match in re.finditer(r"<(activity|activity-alias|service|receiver|provider)\b[^>]*>", text, re.S):
            tag = match.group(0)
            if 'android:exported="true"' not in tag or "android:permission" in tag:
                continue
            close = text.find(f"</{match.group(1)}>", match.end())
            inner = text[match.end(): close if close > 0 else match.end()]
            if "android.intent.category.LAUNCHER" in inner or "android.intent.category.BROWSABLE" in inner:
                continue  # the app's own entry point and deep links have to be exported
            lineno = text.count("\n", 0, match.start()) + 1
            yield ctx.finding(info, rel, lineno, ctx.index.lines(rel)[lineno - 1], confidence="low")


@check(
    "LP-MOB-004", "Login token stored in plain app storage", "auth", Severity.MEDIUM,
    why="AsyncStorage, SharedPreferences and UserDefaults are plain files. On a rooted or jailbroken phone, from a "
        "backup, or through another bug, tokens stored there can be read and reused.",
    fix="Store tokens and secrets in the platform keystore: expo-secure-store or react-native-keychain, "
        "flutter_secure_storage, EncryptedSharedPreferences / Android Keystore, or the iOS Keychain.",
    cwe=("CWE-312", "CWE-922"),
)
def insecure_token_storage(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    secret = r"[^'\"`]*(?:token|jwt|session|auth|password|secret|credential|api_?key)"
    pattern = re.compile(
        rf"(?i)AsyncStorage\.(?:setItem|multiSet)\(\s*['\"`]{secret}|\bset(?:String|Item)\(\s*(?:key:\s*)?['\"]{secret}|"
        rf"\.putString\(\s*['\"]{secret}|UserDefaults\.standard\.set\([^)]*forKey:\s*\"{secret}|"
        rf"\bMMKV\b.*\.set\(\s*['\"`]{secret}"
    )
    # localStorage is the browser's, covered by LP-AUTH-004.
    safe = re.compile(r"SecureStore|Keychain|EncryptedSharedPreferences|FlutterSecureStorage|secureStorage|localStorage|"
                      r"sessionStorage")
    for rel, lineno, line, _ in grep(ctx, pattern, exts=JS_EXT | {".dart", ".java", ".kt", ".swift"}):
        if not safe.search(line):
            yield ctx.finding(info, rel, lineno, line)


@check(
    "LP-MOB-005", "WebView with risky settings", "config", Severity.MEDIUM,
    why="Letting a WebView load any origin, read local files, mix HTTP into HTTPS or call native code through a "
        "JavaScript bridge means one malicious page can read the app's files or call its native functions.",
    fix="Restrict originWhitelist to your own domains, keep file access and universal file-URL access off, never "
        "allow mixed content, and avoid addJavascriptInterface (or expose only minimal, checked methods).",
    cwe=("CWE-749", "CWE-79"),
)
def risky_webview(ctx: ScanContext, info: CheckInfo) -> Iterator[Finding]:
    pattern = re.compile(
        r"originWhitelist=\{\s*\[\s*['\"]\*['\"]\s*\]\s*\}|allowFileAccess(?:FromFileURLs)?=\{\s*true\s*\}|"
        r"allowUniversalAccessFromFileURLs=\{\s*true\s*\}|mixedContentMode=['\"{]+always|"
        r"setAllowUniversalAccessFromFileURLs\(\s*true\s*\)|setAllowFileAccessFromFileURLs\(\s*true\s*\)|"
        r"\baddJavascriptInterface\(|setMixedContentMode\([^)]*MIXED_CONTENT_ALWAYS_ALLOW|"
        r"allowUniversalAccessFromFileURLs\s*=\s*true|allowsArbitraryLoadsInWebContent"
    )
    for rel, lineno, line, _ in grep(ctx, pattern, exts=JS_EXT | {".java", ".kt", ".swift", ".dart", ".plist"}):
        yield ctx.finding(info, rel, lineno, line)
