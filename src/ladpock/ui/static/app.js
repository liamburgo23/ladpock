"use strict";

// Everything shown here can come from scanned code, so the DOM is only ever
// built with textContent (see h()). Never use innerHTML with data.

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PROFILES = {
  quick: "Secrets and dependencies only. Seconds.",
  standard: "Every check, plus installed scanners and live vulnerability data.",
  full: "Standard, plus a search of git history for secrets (needs Gitleaks).",
};
const memory = {};
const state = { token: null, status: null, refreshing: false, refreshed: false, poll: null, view: 0 };

// ---------- small helpers ----------

function store(key, value) {
  try { localStorage.setItem(key, value); } catch (e) { memory[key] = value; }
}
function load(key) {
  try { return localStorage.getItem(key) ?? memory[key] ?? null; } catch (e) { return memory[key] ?? null; }
}

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value == null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "style") el.style.cssText = value;  // CSSOM, so the strict CSP still allows it
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

function $(selector) { return document.querySelector(selector); }

function ago(iso) {
  if (!iso) return "never";
  const seconds = (Date.now() - new Date(iso).getTime()) / 1000;
  if (seconds < 90) return "just now";
  const minutes = seconds / 60;
  if (minutes < 90) return `${Math.round(minutes)} min ago`;
  const hours = minutes / 60;
  if (hours < 36) return `${Math.round(hours)} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

function plural(n, word, many) { return `${n} ${n === 1 ? word : (many || word + "s")}`; }

function gradeEl(grade, big) {
  const letter = grade ? grade[0] : "none";
  return h("span", { class: `grade grade-${letter}${big ? " big" : ""}`, "aria-label": grade ? `Grade ${grade}` : "Not scanned" }, grade || "–");
}

function sevPill(sev) { return h("span", { class: `pill sev-${sev}` }, sev); }

function spinner(text) { return h("div", { class: "loading" }, h("span", { class: "spinner" }), text); }

let toastTimer;
function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3500);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const area = h("textarea", { style: "position:fixed;opacity:0" });
    area.value = text;
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
}

// ---------- API ----------

async function api(method, path, body) {
  const headers = { "X-LadPock-Token": state.token || "" };
  if (method === "POST") {
    headers["Content-Type"] = "application/json";  // the server only accepts JSON writes
    body = body || {};
  }
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status;
    if (res.status === 401) showLocked();
    throw err;
  }
  return data;
}

function readToken() {
  const match = location.hash.match(/token=([A-Za-z0-9_-]+)/);
  if (match) {
    store("ladpock-token", match[1]);
    history.replaceState(null, "", location.pathname + "#/");
    return match[1];
  }
  return load("ladpock-token");
}

function showLocked() {
  $("#app").replaceChildren(h("div", { class: "card empty" },
    h("h1", null, "Open LadPock from your terminal"),
    h("p", { class: "muted" }, "For your security, the dashboard needs the private link printed when you ran `ladpock ui`. It changes every time LadPock starts."),
  ));
}

// ---------- feeds (top bar) ----------

function drawFeeds() {
  const el = $("#feeds");
  if (!state.status) { el.replaceChildren(); return; }
  if (state.refreshing) {
    el.replaceChildren(h("span", { class: "feed" }, h("span", { class: "dot busy" }), "Updating vulnerability data…"));
    return;
  }
  const parts = state.status.feeds.map((f) => h("span", { class: "feed", title: f.error || "" },
    h("span", { class: `dot${f.error || !f.updated ? " warn" : ""}` }), `${f.name} ${f.error ? "update failed" : ago(f.updated)}`));
  el.replaceChildren(...parts, h("button", { class: "btn small", onclick: refreshFeeds }, "Refresh"));
}

async function refreshFeeds() {
  if (state.refreshing) return;
  state.refreshing = true;
  drawFeeds();
  try {
    state.status = await api("POST", "/api/refresh");
    const problems = Object.values(state.status.problems || {});
    if (problems.length) toast(`Some projects couldn't be checked: ${problems[0]}`);
    if (currentRoute().name === "home") drawHome();
  } catch (e) {
    if (e.status !== 409) toast(`Couldn't update vulnerability data: ${e.message}`);
  } finally {
    state.refreshing = false;
    drawFeeds();
  }
}

// ---------- routing ----------

function currentRoute() {
  const hash = location.hash.replace(/^#/, "") || "/";
  const project = hash.match(/^\/project\/(\d+)(?:\/(\w+))?/);
  if (project) return { name: "project", id: Number(project[1]), tab: project[2] || "findings" };
  if (hash.startsWith("/add")) return { name: "add" };
  return { name: "home" };
}

async function route() {
  clearInterval(state.poll);
  state.view += 1;
  const view = state.view;
  const r = currentRoute();
  try {
    if (!state.status) {
      state.status = await api("GET", "/api/status");
      drawFeeds();
    }
    if (!state.refreshed) {
      state.refreshed = true;
      refreshFeeds();  // fresh vulnerability data every time you open LadPock, whichever page you land on
    }
    if (r.name === "project") await renderProject(r.id, r.tab, view);
    else if (r.name === "add") await renderAdd(await startFolder(), view);
    else await renderHome(view);
  } catch (e) {
    if (e.status === 401) return;
    $("#app").replaceChildren(h("div", { class: "card empty" }, h("h2", null, "Something went wrong"), h("p", { class: "muted" }, e.message),
      h("a", { class: "btn", href: "#/" }, "Back to your projects")));
  }
}

// ---------- home ----------

async function renderHome(view) {
  $("#app").replaceChildren(spinner("Loading your projects"));
  const status = await api("GET", "/api/status");
  if (view !== state.view) return;
  if (!state.refreshing) state.status = status;  // don't overwrite fresher data from an in-flight refresh
  drawFeeds();
  drawHome();
}

function drawHome() {
  const s = state.status;
  const parts = [];
  if (s.new.length) parts.push(newBanner(s));
  const projects = s.projects;
  const head = h("div", { class: "section-title" },
    h("h1", null, "Your projects"),
    h("a", { class: "btn primary", href: "#/add" }, "+ Add project"));
  let body;
  if (!projects.length) {
    body = h("div", { class: "card empty" },
      h("h2", null, "Add your first project"),
      h("p", { class: "muted" }, "Pick a folder on this computer. LadPock reads it, never runs it, and nothing leaves your machine except package names for vulnerability lookups."),
      h("a", { class: "btn primary", href: "#/add" }, "Choose a folder"));
  } else {
    body = h("div", { class: "card flush list" }, projects.map(projectRow));
  }
  $("#app").replaceChildren(h("div", { class: "stack" }, parts, head, body,
    h("p", { class: "faint" }, "A good grade means no obvious problems were found, not that a project is guaranteed secure.")));
}

function newBanner(s) {
  const affected = new Set(s.new.map((a) => a.project)).size;
  const exploited = s.new.filter((a) => a.kev).length;
  return h("section", { class: "banner", "aria-labelledby": "new-adv" },
    h("div", { class: "row spread" },
      h("h2", { id: "new-adv" }, `${plural(s.new.length, "new advisory", "new advisories")} ${s.new.length === 1 ? "affects" : "affect"} ${plural(affected, "project")} since you last checked`),
      h("button", { class: "btn small", onclick: async (ev) => { await api("POST", "/api/ack"); ev.target.closest(".banner").remove(); toast("Marked as seen"); } }, "Mark as seen")),
    exploited ? h("p", null, h("strong", null, `${exploited} ${exploited === 1 ? "is" : "are"} on CISA's list of vulnerabilities being actively exploited.`)) : null,
    h("ul", null, s.new.slice(0, 10).map((a) => h("li", null,
      sevPill(a.severity),
      h("a", { href: `#/project/${a.project_id}/deps` }, a.project),
      h("span", { class: "mono" }, `${a.package} ${a.version}`),
      h("span", { class: "muted" }, a.cves[0] || a.id),
      a.fixed ? h("span", { class: "muted" }, `fixed in ${a.fixed}`) : null,
      a.kev ? h("span", { class: "pill kev" }, "actively exploited") : null))),
    s.new.length > 10 ? h("p", { class: "faint" }, `…and ${s.new.length - 10} more`) : null);
}

function projectRow(p) {
  return h("a", { class: "project-row", href: `#/project/${p.id}` },
    gradeEl(p.grade),
    h("div", { class: "grow" },
      h("div", { class: "name" }, p.name),
      h("div", { class: "faint mono" }, p.path),
      p.stack.length ? h("div", { class: "row", style: "margin-top:4px" }, p.stack.slice(0, 6).map((s) => h("span", { class: "chip" }, s))) : null),
    h("div", { class: "faint", style: "text-align:right" },
      h("div", null, p.exists ? (p.last_scan_at ? `Scanned ${ago(p.last_scan_at)}` : "Not scanned yet") : "Folder missing"),
      p.vulnerable_deps ? h("div", { style: "color:var(--medium)" }, plural(p.vulnerable_deps, "vulnerable dependency", "vulnerable dependencies")) : null));
}

// ---------- add project ----------

async function startFolder() {
  // Open the picker next to the project you added most recently, since new ones usually live alongside it.
  const latest = [...state.status.projects].sort((a, b) => b.id - a.id)[0];
  if (!latest) return "";
  const cut = Math.max(latest.path.lastIndexOf("\\"), latest.path.lastIndexOf("/"));
  return cut > 0 ? latest.path.slice(0, cut) : "";
}

async function renderAdd(path, view) {
  $("#app").replaceChildren(spinner("Reading folders"));
  let data;
  try {
    data = await api("GET", `/api/browse?path=${encodeURIComponent(path)}`);
  } catch (e) {
    if (view !== state.view) return;
    toast(e.message);
    if (path) return renderAdd("", view);
    throw e;
  }
  if (view !== state.view) return;
  const pathInput = h("input", { type: "text", class: "field grow", value: data.path, placeholder: "C:\\Users\\you\\Projects\\my-app", "aria-label": "Folder path" });
  const go = () => renderAdd(pathInput.value.trim(), state.view);
  pathInput.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });

  const add = async (folder) => {
    if (folder === data.path && !data.project) {
      const hint = data.projects_inside
        ? `It holds ${plural(data.projects_inside, "project")} of its own, so "Add every project inside" is probably what you want.`
        : "It has no package.json, pyproject.toml, Cargo.toml or similar.";
      if (!confirm(`This folder doesn't look like a single project. ${hint}\n\nAdd it as one project anyway?`)) return;
    }
    const res = await api("POST", "/api/projects", { path: folder });
    toast("Project added");
    location.hash = `#/project/${res.id}`;
  };
  const discover = async () => {
    const res = await api("POST", "/api/discover", { path: data.path });
    toast(res.added ? `Added ${plural(res.added, "project")}` : "No projects found directly inside this folder");
    if (res.added) location.hash = "#/";
  };

  const rows = data.dirs.map((d) => h("div", { class: "folder-row" },
    h("span", { "aria-hidden": "true" }, "📁"),
    h("button", { class: "name", onclick: () => renderAdd(d.path, state.view) }, d.name),
    d.project ? h("span", { class: "chip accent" }, "looks like a project") : null,
    d.project ? h("button", { class: "btn small", onclick: () => add(d.path) }, "Add") : null));

  $("#app").replaceChildren(h("div", { class: "stack" },
    h("a", { href: "#/" }, "← Your projects"),
    h("h1", null, "Add a project"),
    h("p", { class: "muted" }, "Choose the folder that contains your project's package.json, pyproject.toml or similar. LadPock only reads files."),
    h("div", { class: "card stack" },
      h("div", { class: "row" }, pathInput, h("button", { class: "btn", onclick: go }, "Go")),
      h("div", { class: "row" },
        data.parent !== null ? h("button", { class: "btn small", onclick: () => renderAdd(data.parent, state.view) }, "↑ Up") : null,
        // Make the likely choice the primary button: this folder if it's a project, otherwise its projects.
        data.path ? h("button", { class: `btn small${data.project ? " primary" : ""}`, onclick: () => add(data.path) }, "Add this folder") : null,
        data.path && data.projects_inside ? h("button", { class: `btn small${data.project ? "" : " primary"}`, onclick: discover },
          `Add every project inside (${data.projects_inside})`) : null)),
    h("div", { class: "card flush list" }, rows.length ? rows : h("p", { class: "faint", style: "padding:16px 20px" }, "No sub-folders here."))));
}

// ---------- project ----------

async function renderProject(id, tab, view) {
  $("#app").replaceChildren(spinner("Loading project"));
  const data = await api("GET", `/api/projects/${id}`);
  if (view !== state.view) return;
  const p = data.project;
  const scan = data.scan;
  const summary = scan ? scan.summary : {};
  const coverage = summary.coverage || { deep: [], generic: [] };

  const header = h("div", { class: "header-grid" },
    h("div", { class: "stack" },
      h("a", { href: "#/" }, "← Your projects"),
      h("h1", null, p.name),
      h("div", { class: "faint mono" }, p.path),
      p.stack.length ? h("div", { class: "row" }, p.stack.map((s) => h("span", { class: "chip" }, s))) : null,
      scan ? h("p", { class: "faint" },
        `Deep checks: ${coverage.deep.join(", ") || "none"}`,
        coverage.generic.length ? ` · Generic only: ${coverage.generic.join(", ")}` : "") : null),
    h("div", { class: "row", style: "align-items:center" },
      gradeEl(scan ? scan.grade : null, true),
      h("div", null,
        h("div", { style: "font-size:20px;font-weight:700" }, scan ? `${scan.score}/100` : "Not scanned"),
        h("div", { class: "faint" }, scan ? `Scanned ${ago(scan.finished_at)} · ${scan.profile}` : "Run a scan to get a grade"))));

  const scanPanel = scanCard(p, data.job);
  const parts = [header, scanPanel];
  if (!scan) {
    parts.push(h("div", { class: "card empty" }, h("h2", null, "No scan yet"), h("p", { class: "muted" }, "Pick a profile above and press Run scan.")));
  } else {
    const deps = data.findings.filter((f) => f.check_id === "LP-DEP-001").length;
    const humanDone = data.human.filter((i) => i.checked_at).length;
    const isTauri = p.stack.includes("Tauri");
    const isNext = p.stack.includes("Next.js");
    const entryLabel = isTauri && isNext ? "Routes & commands" : isTauri ? "Commands" : "Routes";
    const tabs = [["findings", `Findings (${data.findings.length})`], ["routes", entryLabel], ["deps", `Dependencies (${deps})`],
      ["human", `Needs a human (${humanDone}/${data.human.length})`], ["history", "History"]];
    parts.push(h("nav", { class: "tabs", "aria-label": "Project sections" }, tabs.map(([key, label]) =>
      h("a", { href: `#/project/${id}/${key}`, "aria-current": key === tab ? "page" : null }, label))));
    const content = h("div", { class: "stack" });
    parts.push(content);
    if (tab === "routes") drawRoutes(content, id, view);
    else if (tab === "deps") drawDeps(content, id, view);
    else if (tab === "human") drawHuman(content, id, data.human);
    else if (tab === "history") drawHistory(content, data.history);
    else drawFindings(content, id, data, summary);
  }
  parts.push(h("div", { class: "row", style: "justify-content:flex-end" },
    h("button", { class: "btn small danger", onclick: async () => {
      if (!confirm(`Remove ${p.name} from LadPock? Your files aren't touched; only LadPock's scan history is deleted.`)) return;
      await api("DELETE", `/api/projects/${id}`);
      toast("Removed");
      location.hash = "#/";
    } }, "Remove from LadPock")));
  $("#app").replaceChildren(h("div", { class: "stack" }, parts));
  if (data.job) watchJob(data.job, id);
}

function scanCard(p, runningJob) {
  let profile = "standard";
  const seg = h("div", { class: "segmented", role: "group", "aria-label": "Scan profile" });
  const desc = h("p", { class: "faint" }, PROFILES[profile]);
  for (const name of Object.keys(PROFILES)) {
    seg.append(h("button", { type: "button", "aria-pressed": name === profile ? "true" : "false", onclick: (ev) => {
      profile = name;
      seg.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === ev.target)));
      desc.textContent = PROFILES[name];
    } }, name[0].toUpperCase() + name.slice(1)));
  }
  const external = h("input", { type: "checkbox", id: "opt-external", checked: true });
  const historyOpt = h("input", { type: "checkbox", id: "opt-history" });
  const offline = h("input", { type: "checkbox", id: "opt-offline" });
  const option = (input, label, help) => h("label", { class: "option", for: input.id }, input,
    h("span", null, h("span", null, label), h("br"), h("span", { class: "faint" }, help)));

  const runBtn = h("button", { class: "btn primary", disabled: !p.exists || null, onclick: async () => {
    runBtn.setAttribute("aria-busy", "true");
    try {
      const res = await api("POST", `/api/projects/${p.id}/scan`, {
        profile, external: external.checked, history: historyOpt.checked, offline: offline.checked });
      watchJob(res.job, p.id);
    } catch (e) {
      runBtn.removeAttribute("aria-busy");
      toast(e.message);
    }
  } }, "Run scan");

  return h("section", { class: "card", "aria-label": "Scan" },
    h("div", { class: "scan-grid" },
      h("div", { class: "stack" },
        h("div", { class: "row spread" }, h("h2", null, "Scan"), seg),
        desc,
        h("div", null,
          option(external, "Use installed scanners", "Gitleaks, OSV-Scanner and Opengrep, if they're installed."),
          option(historyOpt, "Search git history for secrets", "Slower. Needs Gitleaks."),
          option(offline, "Offline", "Skip the network and use the last vulnerability data LadPock downloaded.")),
        h("div", { class: "row" }, runBtn, !p.exists ? h("span", { class: "faint" }, "This folder no longer exists.") : null),
        h("div", { id: "scan-progress" })),
      h("div", { class: "stack" },
        h("h3", null, "AI review"),
        h("div", { class: "soon" }, h("span", { class: "chip" }, "Coming soon"), h("span", null, "Local AI, overnight. Free, and your code never leaves this computer.")),
        h("div", { class: "soon" }, h("span", { class: "chip" }, "Coming soon"), h("span", null, "External AI with your own API key, for a second opinion on serious findings.")),
        h("p", { class: "faint" }, "Until then, use “Copy fix prompt” to hand findings to Claude Code or your AI assistant."))));
}

function watchJob(jobId, projectId) {
  const box = $("#scan-progress");
  const btn = document.querySelector(".scan-grid .btn.primary");
  if (btn) btn.setAttribute("aria-busy", "true");
  const view = state.view;
  const tick = async () => {
    if (view !== state.view) return clearInterval(state.poll);
    let job;
    try { job = await api("GET", `/api/jobs/${jobId}`); } catch (e) { clearInterval(state.poll); return; }
    if (box) box.replaceChildren(h("div", { class: "row" }, job.status === "running" ? h("span", { class: "spinner" }) : null,
      job.status === "running" ? "Scanning…" : job.status === "done" ? "Done" : "Scan failed"),
      h("div", { class: "log", style: "margin-top:8px" }, job.log.join("\n") || "Starting…"));
    if (job.status === "running") return;
    clearInterval(state.poll);
    if (job.status === "done") {
      toast(`Scan finished: grade ${job.result.grade}, ${plural(job.result.findings, "finding")}`);
      renderProject(projectId, currentRoute().tab, state.view);
    } else {
      if (btn) btn.removeAttribute("aria-busy");
      toast(job.error || "Scan failed");
    }
  };
  clearInterval(state.poll);
  state.poll = setInterval(tick, 1000);
  tick();
}

// ---------- findings ----------

function drawFindings(container, projectId, data, summary) {
  const findings = data.findings;
  const cats = summary.categories || [];
  container.append(h("div", { class: "scorecard" }, cats.map((c) => h("div", { class: "score-tile" },
    h("span", { class: "label" }, c.name), gradeEl(c.grade)))));

  const scanners = (summary.scanners || []).map((s) => !s.available ? `${s.name} not installed` : s.ran ? `${s.name} ran` : `${s.name} failed`);
  const info = [`Built-in: ${summary.checks_run ?? "?"} checks`, ...scanners, `${summary.dependencies ?? 0} dependencies checked`];
  container.append(h("p", { class: "faint" }, info.join(" · ")));
  if (summary.suppressed) {
    container.append(h("p", { class: "faint", style: "color:var(--medium)" },
      `${plural(summary.suppressed, "finding")} hidden by 'accept risk' or ladpock-ignore comments. Check any you didn't add yourself.`));
  }
  if ((summary.errors || []).length) {
    container.append(h("details", { class: "faint" }, h("summary", null, plural(summary.errors.length, "warning")),
      h("ul", null, summary.errors.map((e) => h("li", null, e)))));
  }
  if (!findings.length) {
    container.append(h("div", { class: "card empty" }, h("h2", null, "No issues found"),
      h("p", { class: "muted" }, "Nice. Work through the 'Needs a human' tab too, because some things no scanner can check.")));
    return;
  }

  const active = new Set(SEVERITIES);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  const search = h("input", { type: "search", placeholder: "Search findings, files or check IDs", "aria-label": "Search findings" });
  const category = h("select", { "aria-label": "Category" }, h("option", { value: "" }, "All categories"),
    Object.entries(data.categories).filter(([key]) => findings.some((f) => f.category === key)).map(([key, name]) => h("option", { value: key }, name)));
  const list = h("div", { class: "card flush" });
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    const shown = findings.filter((f) => active.has(f.severity) && (!category.value || f.category === category.value)
      && (!q || [f.title, f.file, f.check_id, f.message, f.snippet].some((v) => (v || "").toLowerCase().includes(q))));
    const groups = SEVERITIES.map((sev) => [sev, shown.filter((f) => f.severity === sev)]).filter(([, items]) => items.length);
    list.replaceChildren(...(groups.length ? groups.flatMap(([sev, items]) => [
      h("div", { class: "group-head" }, `${sev} (${items.length})`), ...items.map((f) => findingEl(f, projectId))])
      : [h("p", { class: "faint", style: "padding:16px 20px" }, "Nothing matches these filters.")]));
  };
  const filters = SEVERITIES.filter((s) => counts[s]).map((sev) => h("button", { class: `filter sev-${sev}`, "aria-pressed": "true", onclick: (ev) => {
    active.has(sev) ? active.delete(sev) : active.add(sev);
    ev.currentTarget.setAttribute("aria-pressed", String(active.has(sev)));
    draw();
  } }, `${sev} ${counts[sev]}`));
  search.addEventListener("input", draw);
  category.addEventListener("change", draw);
  const copyAll = h("button", { class: "btn", onclick: async () => {
    const res = await api("GET", `/api/projects/${projectId}/fix-prompt`);
    await copy(res.prompt);
    toast("Fix prompt copied. Paste it into Claude Code or your AI assistant.");
  } }, "Copy fix prompt for all");
  container.append(h("div", { class: "toolbar" }, filters, search, category, copyAll), list);
  draw();
}

function findingEl(f, projectId) {
  const actions = h("div", { class: "row" });
  const fixBtn = h("button", { class: "btn small", onclick: async () => {
    const res = await api("GET", `/api/projects/${projectId}/fix-prompt?ref=${encodeURIComponent(f.ref)}`);
    await copy(res.prompt);
    toast("Fix prompt copied");
  } }, "Copy fix prompt");
  const acceptBtn = h("button", { class: "btn small", onclick: () => {
    const reason = h("input", { type: "text", class: "field", placeholder: "Why is this acceptable? (required)", "aria-label": "Reason" });
    const days = h("select", { class: "field", "aria-label": "Hide for" },
      h("option", { value: "30" }, "30 days"), h("option", { value: "90", selected: true }, "90 days"),
      h("option", { value: "365" }, "1 year"), h("option", { value: "0" }, "Forever"));
    const err = h("span", { class: "faint", style: "color:var(--high)" });
    reason.addEventListener("input", () => { err.textContent = ""; });
    actions.replaceChildren(h("div", { class: "form-inline grow" }, reason, days,
      h("button", { class: "btn small primary", onclick: async () => {
        if (!reason.value.trim()) { err.textContent = "Add a reason first"; reason.focus(); return; }
        try {
          await api("POST", `/api/projects/${projectId}/suppress`, { ref: f.ref, reason: reason.value.trim(), days: Number(days.value) });
          details.remove();
          toast("Accepted. It'll be hidden from future scans.");
        } catch (e) { err.textContent = e.message; }
      } }, "Save"),
      h("button", { class: "btn small", onclick: () => actions.replaceChildren(fixBtn, acceptBtn) }, "Cancel"), err));
    reason.focus();
  } }, "Accept risk…");
  actions.append(fixBtn, acceptBtn);

  const details = h("details", { class: "finding" },
    h("summary", null, sevPill(f.severity), h("span", { class: "title" }, f.title),
      f.file ? h("span", { class: "mono faint" }, f.line ? `${f.file}:${f.line}` : f.file) : null),
    h("div", { class: "body" },
      f.snippet ? h("div", { class: "snippet" }, f.snippet) : null,
      h("p", null, h("strong", null, "Why it matters: "), f.message),
      f.fix ? h("p", null, h("strong", null, "How to fix: "), f.fix) : null,
      h("p", { class: "faint" }, [f.check_id, `confidence ${f.confidence}`, f.source !== "ladpock" ? `via ${f.source}` : null, ...(f.cwe || []), `ref ${f.ref}`].filter(Boolean).join(" · ")),
      actions));
  return details;
}

// ---------- routes / deps / human / history ----------

async function drawRoutes(container, id, view) {
  container.append(spinner("Mapping routes"));
  let data;
  try { data = await api("GET", `/api/projects/${id}/routes`); } catch (e) { container.replaceChildren(h("p", { class: "muted" }, e.message)); return; }
  if (view !== state.view) return;
  if (!data.routes.length && !data.commands.length) {
    container.replaceChildren(h("div", { class: "card empty" }, h("h2", null, "No routes or commands found"),
      h("p", { class: "muted" }, "This view currently understands Next.js (App Router, Pages API and server actions) and Tauri commands. More frameworks are planned.")));
    return;
  }
  const cell = (value) => h("td", { class: value === "no" || value === "none" ? "cell-no" : value === "yes" || value === "sig" || value === "rls" || value === "dir" ? "cell-yes" : value === "mw" || value === "ext" ? "cell-mid" : "faint" }, value);
  container.replaceChildren();
  if (data.commands.length) container.append(...commandsTable(data.commands, cell));
  if (!data.routes.length) return;
  container.append(
    h("h2", null, "Routes"),
    h("div", { class: "card flush table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Method", "Path", "Auth", "Owner check", "Validation", "Rate limit", "Gaps"].map((t) => h("th", null, t)))),
      h("tbody", null, data.routes.map((r) => h("tr", null,
        h("td", { class: "mono" }, r.method), h("td", { class: "mono", title: `${r.file}:${r.line}` }, r.path),
        cell(r.auth), cell(r.owner), cell(r.validation), cell(r.rate_limit),
        h("td", { style: r.gaps.length ? "color:var(--medium)" : "" }, r.gaps.join(", ") || "–")))))),
    h("p", { class: "faint" }, "Auth: yes = checked in the handler, mw = only in middleware, sig = webhook signature. Owner: rls = relies on Supabase Row Level Security. This is read from your current code and is heuristic: treat “no” as “go and look”."));
}

function commandsTable(commands, cell) {
  const yesNo = (flag) => h("td", { class: flag ? "cell-mid" : "faint" }, flag ? "yes" : "no");
  return [
    h("h2", null, "Tauri commands"),
    h("p", { class: "muted" }, "Everything the web page inside your app can ask the Rust side to do. If script in the page is ever compromised, this is what it can reach."),
    h("div", { class: "card flush table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Command", "Page input", "Files", "Path check", "Runs programs", "Network", "Gaps"].map((t) => h("th", null, t)))),
      h("tbody", null, commands.map((c) => h("tr", null,
        h("td", { class: "mono", title: `${c.file}:${c.line}` }, c.name, c.registered ? null : h("span", { class: "faint" }, " (unregistered)")),
        h("td", { class: "mono faint" }, c.inputs.join(", ") || "–"),
        h("td", { class: c.file_access === "none" ? "faint" : "" }, c.file_access),
        cell(c.path_check), yesNo(c.runs_programs), yesNo(c.network),
        h("td", { style: c.gaps.length ? "color:var(--medium)" : "" }, c.gaps.join(", ") || "–")))))),
    h("p", { class: "faint" }, "Path check: dir = confirms the path is inside an allowed folder, ext = only checks the file type, none = uses whatever it's given. Heuristic: hover a command to see where it's defined."),
  ];
}

async function drawDeps(container, id, view) {
  container.append(spinner("Loading advisories"));
  const data = await api("GET", `/api/projects/${id}/advisories`);
  if (view !== state.view) return;
  if (!data.advisories.length) {
    container.replaceChildren(h("div", { class: "card empty" }, h("h2", null, "No known vulnerable dependencies"),
      h("p", { class: "muted" }, "Based on your lockfiles and the latest OSV data. Projects without a lockfile can't be checked precisely.")));
    return;
  }
  const byPkg = new Map();
  for (const a of data.advisories) {
    const key = `${a.package}@${a.version}`;
    if (!byPkg.has(key)) byPkg.set(key, []);
    byPkg.get(key).push(a);
  }
  const fixedOf = (items) => items.map((a) => a.fixed).filter(Boolean).sort((x, y) => x.localeCompare(y, undefined, { numeric: true })).pop();
  container.replaceChildren(h("div", { class: "card flush list" }, [...byPkg.entries()].map(([key, items]) => {
    const worst = SEVERITIES.find((s) => items.some((a) => a.severity === s));
    const fixed = fixedOf(items);
    return h("details", { class: "finding" },
      h("summary", null, sevPill(worst), h("span", { class: "title mono" }, key),
        items.some((a) => a.kev) ? h("span", { class: "pill kev" }, "actively exploited") : null,
        h("span", { class: "faint" }, plural(items.length, "advisory", "advisories")),
        fixed ? h("span", { class: "faint" }, `upgrade to ${fixed}+`) : null),
      h("div", { class: "body" }, h("table", null, h("tbody", null, items.map((a) => h("tr", null,
        h("td", null, sevPill(a.severity)),
        h("td", { class: "mono" }, a.cves[0] || a.id),
        h("td", null, a.summary, a.kev ? h("span", { class: "pill kev", style: "margin-left:6px" }, "exploited") : null),
        h("td", { class: "faint" }, a.fixed ? `fixed in ${a.fixed}` : "no fix listed"),
        h("td", { class: "faint" }, a.epss != null ? `EPSS ${Math.round(a.epss * 100)}%` : "")))))));
  })), h("p", { class: "faint" }, "EPSS is the estimated chance of exploitation in the next 30 days. “Actively exploited” comes from CISA's KEV catalog."));
}

function drawHuman(container, id, items) {
  container.append(h("p", { class: "muted" }, "Things no scanner can check. Tick them off as you confirm them; LadPock remembers."),
    h("div", { class: "card flush list" }, items.map((item) => {
      const box = h("input", { type: "checkbox", id: `h-${item.id}`, checked: !!item.checked_at || null });
      box.addEventListener("change", async () => {
        try { await api("POST", `/api/projects/${id}/human`, { item: item.id, checked: box.checked }); }
        catch (e) { box.checked = !box.checked; toast(e.message); }
      });
      return h("label", { class: "check-item", for: box.id }, box,
        h("span", null, item.text, item.checked_at ? h("span", { class: "faint" }, `  ·  confirmed ${ago(item.checked_at)}`) : null));
    })));
}

function drawHistory(container, history) {
  container.append(h("div", { class: "card flush table-wrap" }, h("table", null,
    h("thead", null, h("tr", null, ["When", "Profile", "Grade", "Score", ""].map((t) => h("th", null, t)))),
    h("tbody", null, history.map((s) => h("tr", null,
      h("td", null, new Date(s.started_at).toLocaleString()), h("td", null, s.profile), h("td", null, gradeEl(s.grade)),
      h("td", null, `${s.score}/100`), h("td", { style: "width:35%" }, h("div", { class: "bar" }, h("span", { style: `width:${s.score}%` })))))))));
}

// ---------- start ----------

state.token = readToken();
if (!state.token) showLocked();
else {
  window.addEventListener("hashchange", route);
  route();
}
