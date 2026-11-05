"use strict";

// Everything shown here can come from scanned code, so the DOM is only ever
// built with textContent (see h()). Never use innerHTML with data.

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PROFILE_INFO = {
  quick: { label: "Quick", time: "Seconds", best: "A fast check before you commit or deploy",
    looks: "Leaked keys and passwords, committed .env files, and known vulnerabilities in your dependencies." },
  standard: { label: "Standard", time: "Usually under a minute", best: "Everyday use (the default)",
    looks: "Everything in Quick, plus every code check: sign-in, access control, routes and commands, injection, payments, config and AI code smells, and a check that your packages really exist." },
  full: { label: "Full", time: "Longer on big repositories", best: "Before a release, or weekly",
    looks: "Everything in Standard, plus a search of git history for secrets that were committed and later deleted (needs Gitleaks)." },
};
const memory = {};
const state = { token: null, status: null, refreshing: false, refreshed: false, poll: null, view: 0, dismissed: new Set() };

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
  const parts = state.status.feeds.map((f) => {
    const text = f.error ? "update failed" : f.updated ? `updated ${ago(f.updated)}` : (f.note || "not checked yet");
    const warn = f.error || (!f.updated && !f.note);
    return h("a", { class: "feed", href: "#/help/data", title: `${f.about || ""}${f.error ? `\n${f.error}` : ""}` },
      h("span", { class: `dot${warn ? " warn" : f.updated ? "" : " idle"}` }), `${f.name} ${text}`);
  });
  el.replaceChildren(...parts, h("button", { class: "btn small", title: "Download the latest vulnerability data now", onclick: refreshFeeds }, "Refresh"));
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
  const project = hash.match(/^\/project\/(\d+)(?:\/(\w+))?(?:\/([\w-]+))?/);
  if (project) return { name: "project", id: Number(project[1]), tab: project[2] || "findings", sub: project[3] || null };
  if (hash.startsWith("/add")) return { name: "add" };
  const help = hash.match(/^\/help(?:\/([\w-]+))?/);
  if (help) return { name: "help", section: help[1] || null };
  if (hash.startsWith("/scanners")) return { name: "scanners" };
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
    if (r.name === "project") await renderProject(r.id, r.tab, view, r.sub);
    else if (r.name === "add") await renderAdd(await startFolder(), view);
    else if (r.name === "help") renderHelp(r.section);
    else if (r.name === "scanners") await renderScanners(view);
    else await renderHome(view);
  } catch (e) {
    if (e.status === 401) return;
    $("#app").replaceChildren(h("div", { class: "card empty" }, h("h2", null, "Something went wrong"), h("p", { class: "muted" }, e.message),
      h("a", { class: "btn", href: "#/" }, "Back to your projects")));
  }
}

function helpLink(section, text) {
  return h("a", { class: "help-inline", href: `#/help/${section}` }, text || "What's this?");
}

// ---------- background tasks: what's running, what finished ----------

const jobs = { list: [], seen: new Map(), timer: null, started: false, open: false };
const STOPPABLE = new Set(["ai", "full", "full-all"]);

async function pollJobs() {
  clearTimeout(jobs.timer);
  let data;
  try { data = await api("GET", "/api/jobs"); } catch (e) { jobs.timer = setTimeout(pollJobs, 10000); return; }
  const first = !jobs.started;
  jobs.started = true;
  for (const j of data.jobs) {
    const before = jobs.seen.get(j.id);
    jobs.seen.set(j.id, j.status);
    // Announce jobs that finished since the last look (including ones that started and finished in between).
    if (!first && j.status !== "running" && (before === "running" || before === undefined)) jobFinished(j);
  }
  jobs.list = data.jobs;
  const running = data.jobs.filter((j) => j.status === "running");
  document.title = running.length ? "● Running · LadPock" : "LadPock";
  drawActivity();
  drawJobBanner();
  if (currentRoute().name === "home") drawHomeBadges();
  jobs.timer = setTimeout(pollJobs, running.length ? 1000 : 6000);
}

async function startTask(path, body) {
  try {
    await api("POST", path, body || {});
    pollJobs();
    return true;
  } catch (e) {
    toast(e.message);
    return false;
  }
}

function jobProgress(j) {
  const n = Math.max(1, j.steps.length);
  const pct = j.status === "running" ? Math.min(99, Math.round(100 * (j.step + (j.fraction || 0)) / n)) : 100;
  const stepName = j.steps[j.step] || "Starting";
  const within = j.fraction != null ? ` (${Math.round(j.fraction * 100)}%)` : "";
  return { pct, label: `Step ${Math.min(j.step + 1, n)} of ${n}: ${stepName}${within}` };
}

function progressBar(pct) {
  return h("div", { class: "bar", role: "progressbar", "aria-valuenow": pct, "aria-valuemin": 0, "aria-valuemax": 100 },
    h("span", { style: `width:${pct}%` }));
}

function stopButton(j) {
  if (!STOPPABLE.has(j.kind) && !j.steps.some((step) => step.endsWith("AI review"))) return null;
  if (j.stopping) return h("span", { class: "faint" }, "Stopping after the current step…");
  return h("button", { class: "btn small", onclick: async (ev) => {
    ev.preventDefault();
    ev.currentTarget.textContent = "Stopping…";
    await api("POST", `/api/jobs/${j.id}/stop`);
    pollJobs();
  } }, "Stop");
}

function finishMessage(j) {
  if (j.status === "error") return `${j.title} failed: ${j.error}`;
  const r = j.result || {};
  if (j.kind === "full-all") {
    const grades = (r.projects || []).map((p) => `${p.name} ${p.grade}`).join(", ");
    return `${j.title} finished${grades ? `: ${grades}` : ""}`;
  }
  if (j.kind === "benchmark") return `${j.title} finished`;
  const bits = [];
  if (r.grade) bits.push(`grade ${r.grade}`);
  if (r.findings != null) bits.push(plural(r.findings, "finding"));
  if (r.leads != null) bits.push(plural(r.leads, "new AI lead"));
  if (r.ai === "unavailable") bits.push("AI review skipped (no local model)");
  if (r.online_leads != null) bits.push(plural(r.online_leads, "new Claude lead"));
  if (r.online_cost != null) bits.push(`online AI cost about $${r.online_cost.toFixed(2)}`);
  if (r.online_ai === "budget") bits.push("online AI stopped at your monthly budget");
  if (r.online_ai === "not set up") bits.push("online AI skipped (not set up yet)");
  if (r.online_ai === "unavailable" || r.online_ai === "error") bits.push("online AI review failed (see the task log)");
  if (r.status === "stopped" || r.ai === "stopped") bits.push("stopped early; the next run continues from there");
  if (r.status === "paused") bits.push(r.message || "paused");
  return `${j.title} finished${bits.length ? ": " + bits.join(", ") : ""}`;
}

function jobFinished(j) {
  toast(finishMessage(j));
  const r = currentRoute();
  if (r.name === "project" && (j.project_id === r.id || j.kind === "full-all")) renderProject(r.id, r.tab, state.view, r.sub);
  else if (r.name === "scanners" && j.kind === "install") renderScanners(state.view);
  else if (r.name === "home") renderHome(state.view);
}

function jobLink(j) {
  return j.project_id ? h("a", { href: `#/project/${j.project_id}` }, j.title) : h("strong", null, j.title);
}

function drawActivity() {
  const el = $("#activity");
  if (!el) return;
  const running = jobs.list.filter((j) => j.status === "running");
  const finished = jobs.list.filter((j) => j.status !== "running" && j.finished_at);
  const recent = finished.filter((j) => Date.now() - new Date(j.finished_at).getTime() < 15 * 60e3);
  let summary;
  if (running.length === 1) summary = [h("span", { class: "spinner small" }), `${running[0].title} · ${jobProgress(running[0]).pct}%`];
  else if (running.length > 1) summary = [h("span", { class: "spinner small" }), `${running.length} tasks running`];
  else if (recent.length) summary = [h("span", { class: `dot${recent[0].status === "error" ? " err" : ""}` }),
    `${recent[0].status === "error" ? "Failed" : "Finished"} ${ago(recent[0].finished_at)}: ${recent[0].title}`];
  else summary = [h("span", { class: "dot idle" }), "Nothing running"];
  const button = h("button", { class: "activity-btn", "aria-expanded": String(jobs.open), "aria-label": "Tasks",
    onclick: (ev) => { ev.stopPropagation(); jobs.open = !jobs.open; drawActivity(); } }, summary);
  el.replaceChildren(...[button, jobs.open ? activityPanel(running, finished.slice(0, 8)) : null].filter(Boolean));
}

function activityPanel(running, finished) {
  return h("div", { class: "activity-panel", onclick: (ev) => ev.stopPropagation() },
    h("h3", null, running.length ? "Running now" : "Nothing running right now"),
    running.map((j) => {
      const p = jobProgress(j);
      return h("div", { class: "activity-item" },
        h("div", { class: "row spread" }, jobLink(j), stopButton(j)),
        h("div", { class: "faint" }, `${p.label} · started ${ago(j.started_at)}`), progressBar(p.pct),
        j.log.length ? h("div", { class: "faint mono log-line" }, j.log[j.log.length - 1]) : null);
    }),
    finished.length ? h("h3", null, "Recently finished") : null,
    finished.map((j) => h("div", { class: "activity-item" },
      h("div", { class: "row spread" }, jobLink(j), h("span", { class: "faint" }, ago(j.finished_at))),
      h("div", { class: j.status === "error" ? "err-text" : "faint" }, finishMessage(j)))),
    h("p", { class: "faint" }, "Tasks keep running if you move to another page. Closing the terminal that runs `ladpock ui` stops them. ",
      helpLink("running", "More about tasks")));
}

document.addEventListener("click", () => {
  if (jobs.open) { jobs.open = false; drawActivity(); }
});

function drawJobBanner() {
  const el = $("#job-banner");
  const r = currentRoute();
  if (!el || (r.name !== "project" && r.name !== "scanners")) return;
  const mine = r.name === "scanners" ? jobs.list.filter((j) => j.kind === "install")
    : jobs.list.filter((j) => j.project_id === r.id || j.kind === "full-all");
  const running = mine.find((j) => j.status === "running");
  setRunButtonsBusy(Boolean(running));
  if (running) {
    const p = jobProgress(running);
    el.replaceChildren(h("section", { class: "status-banner running", role: "status" },
      h("div", { class: "row spread" }, h("div", { class: "row" }, h("span", { class: "spinner" }), h("strong", null, `Running: ${running.title}`)),
        stopButton(running)),
      h("div", { class: "faint" }, `${p.label} · started ${ago(running.started_at)}`), progressBar(p.pct),
      running.log.length ? h("div", { class: "faint mono log-line" }, running.log[running.log.length - 1]) : null,
      h("p", { class: "faint" }, "You can leave this page; progress also shows in the top bar.")));
    return;
  }
  const last = mine.find((j) => j.finished_at && Date.now() - new Date(j.finished_at).getTime() < 30 * 60e3 && !state.dismissed.has(j.id));
  if (!last) { el.replaceChildren(); return; }
  el.replaceChildren(h("section", { class: `status-banner ${last.status === "error" ? "failed" : "done"}`, role: "status" },
    h("div", { class: "row spread" },
      h("strong", null, `${last.status === "error" ? "✗" : "✓"} ${finishMessage(last)}`),
      h("button", { class: "btn small", onclick: () => { state.dismissed.add(last.id); drawJobBanner(); } }, "Dismiss")),
    h("div", { class: "faint" }, `Finished ${ago(last.finished_at)}. The results below are up to date.`)));
}

function setRunButtonsBusy(busy) {
  document.querySelectorAll("[data-run]").forEach((b) => {
    b.disabled = busy;
    b.textContent = busy ? "Running…" : b.dataset.label;
  });
}

function runButton(label, onclick, primary) {
  return h("button", { class: `btn${primary ? " primary" : ""}`, "data-run": "", "data-label": label, onclick }, label);
}

// ---------- home ----------

async function renderHome(view) {
  if (!state.status) $("#app").replaceChildren(spinner("Loading your projects"));
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
  const checkAll = projects.length ? runButton("Check all projects", async () => {
    const ok = confirm(`Run a full check on all ${projects.length} projects, one after another?\n\n`
      + "Each gets every scan check, then the local AI review if a model is installed. This can take a while; "
      + "you can keep using your computer, watch progress in the top bar, and stop it at any time.");
    if (ok) startTask("/api/full-check", { ai: true });
  }) : null;
  const head = h("div", { class: "section-title" },
    h("h1", null, "Your projects"),
    h("div", { class: "row" }, checkAll, h("a", { class: "btn primary", href: "#/add" }, "+ Add project")));
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
    h("p", { class: "faint" }, "A good grade means no obvious problems were found, not that a project is guaranteed secure. ",
      helpLink("grades", "How grades work"))));
  drawHomeBadges();
}

function drawHomeBadges() {
  const running = jobs.list.filter((j) => j.status === "running");
  document.querySelectorAll(".job-slot").forEach((slot) => {
    const id = Number(slot.dataset.project);
    const job = running.find((j) => j.project_id === id);
    const all = running.find((j) => j.kind === "full-all");
    if (job) slot.replaceChildren(h("span", { class: "chip accent" }, h("span", { class: "spinner small" }), ` ${job.title.split(" of ")[0]} · ${jobProgress(job).pct}%`));
    else if (all && (all.steps[all.step] || "").startsWith(`${slot.dataset.name}:`)) slot.replaceChildren(h("span", { class: "chip accent" }, h("span", { class: "spinner small" }), " Checking now"));
    else slot.replaceChildren();
  });
}

function newBanner(s) {
  const affected = new Set(s.new.map((a) => a.project)).size;
  const exploited = s.new.filter((a) => a.kev).length;
  return h("section", { class: "banner", "aria-labelledby": "new-adv" },
    h("div", { class: "row spread" },
      h("h2", { id: "new-adv" }, `${plural(s.new.length, "new advisory", "new advisories")} ${s.new.length === 1 ? "affects" : "affect"} ${plural(affected, "project")} since you last checked`),
      h("button", { class: "btn small", onclick: async (ev) => { await api("POST", "/api/ack"); ev.target.closest(".banner").remove(); toast("Marked as seen"); } }, "Mark as seen")),
    h("p", { class: "faint" }, "Newly published vulnerabilities in packages your projects use, found by re-checking your lockfiles against today's data. ", helpLink("data")),
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
      h("div", { class: "job-slot", "data-project": p.id, "data-name": p.name }),
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

async function renderProject(id, tab, view, sub) {
  if (!document.querySelector(".project-page")) $("#app").replaceChildren(spinner("Loading project"));
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
        coverage.generic.length ? ` · Generic only: ${coverage.generic.join(", ")}` : "", " ", helpLink("coverage")) : null),
    scan ? h("a", { class: "grade-link", href: `#/project/${id}/grade`, title: "Why this grade, and how to reach A+" },
      gradeEl(scan.grade, true),
      h("div", null,
        h("div", { style: "font-size:20px;font-weight:700" }, `${scan.score}/100`),
        h("div", { class: "faint" }, `Last scanned ${ago(scan.finished_at)} (${scan.profile})`),
        h("span", { class: "help-inline" }, scan.grade === "A+" ? "Why this grade?" : "Why not A+? How to improve →")))
      : h("div", { class: "row", style: "align-items:center" }, gradeEl(null, true),
        h("div", null, h("div", { style: "font-size:20px;font-weight:700" }, "Not scanned"),
          h("div", { class: "faint" }, "Scan to get a grade"), helpLink("grades", "How grades work"))));

  const parts = [header, h("div", { id: "job-banner" }), scanPanel(p, data), aiSettings(p, data.ai)];
  if (!scan) {
    parts.push(h("div", { class: "card empty" }, h("h2", null, "No results yet"),
      h("p", { class: "muted" }, "Choose what to run above, then press Scan.")));
  } else {
    const deps = data.findings.filter((f) => f.check_id === "LP-DEP-001").length;
    const humanDone = data.human.filter((i) => i.checked_at).length;
    const isTauri = p.stack.includes("Tauri");
    const isNext = p.stack.includes("Next.js");
    const entryLabel = isTauri && isNext ? "Routes & commands" : isTauri ? "Commands" : "Routes";
    const leads = data.ai.leads.filter((l) => l.status !== "dismissed").length;
    const tabs = [["findings", `Findings (${data.findings.length}${leads ? ` + ${leads} AI` : ""})`],
      ["grade", scan.grade === "A+" ? "Why this grade" : "Why not A+"], ["routes", entryLabel],
      ["deps", `Dependencies (${deps})`], ["human", `Needs a human (${humanDone}/${data.human.length})`], ["history", "History"]];
    parts.push(h("nav", { class: "tabs", "aria-label": "Project sections" }, tabs.map(([key, label]) =>
      h("a", { href: `#/project/${id}/${key}`, "aria-current": key === tab ? "page" : null }, label))));
    const content = h("div", { class: "stack" });
    parts.push(content);
    if (tab === "routes") drawRoutes(content, id, view);
    else if (tab === "deps") drawDeps(content, id, view);
    else if (tab === "human") drawHuman(content, id, data.human);
    else if (tab === "history") drawHistory(content, data.history);
    else if (tab === "grade") drawGrade(content, id, data, sub);
    else drawFindings(content, id, data, summary);
  }
  parts.push(h("div", { class: "row", style: "justify-content:flex-end" },
    h("button", { class: "btn small danger", onclick: async () => {
      if (!confirm(`Remove ${p.name} from LadPock? Your files aren't touched; only LadPock's scan history is deleted.`)) return;
      await api("DELETE", `/api/projects/${id}`);
      toast("Removed");
      location.hash = "#/";
    } }, "Remove from LadPock")));
  $("#app").replaceChildren(h("div", { class: "stack project-page" }, parts));
  drawJobBanner();
  const focus = tab === "grade" && sub && document.getElementById(`cat-${sub}`);
  if (focus) focus.scrollIntoView({ block: "center" });
}

// ---------- scan panel: every option is a toggle, then one Scan button ----------

const DEFAULT_OPTIONS = { profile: "standard", online: true, scanners: true, history: false, local_ai: false, online_ai: false,
  live: false, live_writes: false };
const OPTION_KEYS = Object.keys(DEFAULT_OPTIONS);
const PRESETS = [
  ["Everything free", "Full scan, live vulnerability data, installed scanners, git history and the local AI review.",
    { profile: "full", online: true, scanners: true, history: true, local_ai: true, online_ai: false }],
  ["Offline", "Nothing leaves this computer. Uses the vulnerability data LadPock last downloaded.",
    { profile: "full", online: false, scanners: true, history: true, local_ai: true, online_ai: false }],
  ["Quick", "Seconds: leaked secrets and vulnerable dependencies only.",
    { profile: "quick", online: true, scanners: false, history: false, local_ai: false, online_ai: false }],
  ["Deepest (paid)", "Everything free, plus Claude reviewing your code online, billed to your Anthropic account.",
    { profile: "full", online: true, scanners: true, history: true, local_ai: true, online_ai: true }],
];

function savedOptions(projectId) {
  try {
    const saved = JSON.parse(load(`ladpock-scan-${projectId}`) || "null");
    if (saved && typeof saved === "object") return { ...DEFAULT_OPTIONS, ...saved };
  } catch (e) { /* use the default */ }
  return { ...DEFAULT_OPTIONS };
}

function money(n) { return `$${Number(n || 0).toFixed(2)}`; }

function openAiSettings() {
  const box = document.getElementById("ai-settings");
  if (!box) return;
  box.open = true;
  box.scrollIntoView({ block: "start", behavior: "smooth" });
}

function scanPanel(p, data) {
  const opts = savedOptions(p.id);
  const env = { scanners: null, missing: [], ai: null, online: null };  // filled in as each status loads
  const presets = h("div", { class: "presets", role: "group", "aria-label": "Presets" });
  const depth = h("div", { class: "segmented", role: "group", "aria-label": "How deep" });
  const depthText = h("p", { class: "faint" });
  const toggles = h("div", { class: "toggle-list" });
  const summary = h("div", { class: "scan-summary" });
  const go = runButton("Scan", () => start(), true);
  go.classList.add("big");

  const blocked = (key) => {
    const quick = opts.profile === "quick";
    if (key === "scanners" && quick) return "Quick scans skip installed scanners. Choose Standard or Full.";
    if (key === "history") {
      if (quick) return "Quick scans skip git history. Choose Standard or Full.";
      if (!opts.scanners) return "Needs Installed scanners on.";
      if (env.scanners && !env.scanners.includes("gitleaks")) return "Needs Gitleaks. Install it on the Scanners page.";
    }
    if (key === "local_ai" && env.ai && !env.ai.available) return "Ollama isn't running on this computer, so there's no local model to use.";
    if (key === "online_ai") {
      if (!opts.online) return "Needs free online data on (it can't run offline).";
      const o = env.online;
      if (!o) return null;
      if (o.never) return "This project is set to never be sent online.";
      if (!o.sdk_installed) return "Needs Anthropic's Python SDK: python -m pip install anthropic";
      if (!o.enabled) return "Not set up yet. Allow it in AI settings.";
      if (!(o.key.stored || o.key.env)) return "Add your Anthropic API key in AI settings.";
    }
    if (key === "online_tools") return "Not available yet.";
    if (key === "live_writes" && !opts.live) return "Turn on live checks first.";
    return null;
  };
  let liveUrl = load(`ladpock-live-${p.id}`) || "http://localhost:3000";
  // Test-account logins stay in this page's memory only: never saved, and gone when you leave the page.
  const accounts = { a: "", b: "", own: "", open: false };
  const effective = () => Object.fromEntries(OPTION_KEYS.map((k) => [k, k === "profile" ? opts.profile : Boolean(opts[k]) && !blocked(k)]));
  const tag = (text, kind) => h("span", { class: `tag ${kind}` }, text);

  const row = (key, label, tags, help) => {
    const reason = blocked(key);
    const input = h("input", { type: "checkbox", class: "switch", role: "switch", id: `opt-${key}`,
      checked: (opts[key] && !reason) || null, disabled: reason ? true : null });
    input.addEventListener("change", () => { opts[key] = input.checked; draw(); });
    const needsSettings = reason && (key === "local_ai" || key === "online_ai") && !reason.startsWith("Needs free");
    return h("div", { class: `toggle-row${reason ? " disabled" : ""}` }, input,
      h("div", { class: "grow" },
        h("label", { for: input.id, class: "row" }, h("strong", null, label), tags),
        h("div", { class: "faint" }, help),
        reason ? h("div", { class: "reason" }, reason, needsSettings
          ? h("button", { class: "btn link", onclick: openAiSettings }, "Open AI settings") : null) : null));
  };

  const scannerHelp = () => {
    if (!env.scanners) return "Gitleaks, OSV-Scanner and Opengrep, if they're installed.";
    return [env.scanners.length ? `Uses ${env.scanners.join(", ")}. ` : "None installed yet. ",
      env.missing.length ? h("a", { href: "#/scanners" }, `Install ${env.missing.join(", ")} (free)`) : ""];
  };
  const localHelp = () => {
    const base = "A model on this computer reads your routes, commands and code for logic bugs. After the first run only changed code is re-read.";
    return env.ai && env.ai.available ? `${base} Model: ${env.ai.model}.` : base;
  };
  const onlineHelp = () => {
    const base = "Claude reads the same parts with secrets masked, and double-checks the local model's leads. Billed to your own Anthropic account and stops at your monthly budget.";
    const o = env.online;
    if (!o || o.never) return base;
    const todo = o.units + (o.leads || 0);
    return [base, h("br"), todo
      ? `${plural(todo, "part")} to send now (unchanged code isn't re-sent): about ${money(o.cost)}. ${money(o.left)} of ${money(o.budget)} left this month.`
        + (o.cost > o.left ? " That's more than is left, so it reviews the most important parts first and stops at the budget; the next month (or a bigger budget) continues from there." : "")
      : "Nothing has changed since its last review, so this would cost nothing."];
  };

  const liveHelp = () => {
    const base = "Calls your app running on this computer without logging in, to confirm which endpoints really answer, and "
      + "checks security headers, CORS, exposed files like .env and sign-in rate limits. Only ever talks to localhost.";
    if (!opts.live) return base;
    const field = h("input", { type: "url", class: "field", value: liveUrl, "aria-label": "Address of your running app",
      placeholder: "http://localhost:3000", style: "max-width:260px;margin-top:6px" });
    field.addEventListener("input", () => { liveUrl = field.value.trim(); store(`ladpock-live-${p.id}`, liveUrl); });
    const writes = h("input", { type: "checkbox", id: "opt-live_writes", checked: opts.live_writes || null });
    writes.addEventListener("change", () => { opts.live_writes = writes.checked; drawSummary(effective()); });
    return [base, h("div", { class: "form-inline" }, h("span", null, "App address"), field),
      h("label", { class: "option", for: writes.id, style: "border:none;padding:4px 0" }, writes,
        h("span", null, "Also call routes that change data (POST, PUT, DELETE)", h("br"),
          h("span", { class: "faint" }, "Uses placeholder IDs and empty bodies. Only do this against a development database."))),
      accountsBlock()];
  };
  const accountsBlock = () => {
    const secret = (key, label) => {
      const input = h("input", { type: "password", class: "field grow", value: accounts[key], autocomplete: "off", "aria-label": label,
        placeholder: "Cookie: session=...  or  Bearer ..." });
      input.addEventListener("input", () => { accounts[key] = input.value; drawSummary(effective()); });
      return h("div", { class: "form-inline" }, h("span", null, label), input);
    };
    const own = h("textarea", { class: "field", rows: "2", "aria-label": "Account A's records", style: "width:100%;margin-top:6px",
      placeholder: "/api/orders/123" });
    own.value = accounts.own;
    own.addEventListener("input", () => { accounts.own = own.value; });
    const box = h("details", { class: "compare", open: accounts.open || null, style: "margin-top:6px" },
      h("summary", null, "Also test whether one account can read another's data"),
      h("p", { class: "faint", style: "margin-top:6px" }, "Sign in to your app as two ordinary test accounts, each with some data of its own. "
        + "In your browser's developer tools (Network tab, any request to your app) copy the Cookie or Authorization header for each. "
        + "LadPock lists account A's records, then tries to open them as account B. It only reads, and these values are only kept on this page."),
      secret("a", "Account A"), secret("b", "Account B"),
      h("p", { class: "faint", style: "margin-top:6px" }, "Optional: addresses of account A's own records, one per line, if there's no list endpoint to find them from."),
      own);
    box.addEventListener("toggle", () => { accounts.open = box.open; });
    return box;
  };

  const drawSummary = (eff) => {
    const profile = data.profiles[eff.profile];
    const will = [`${PROFILE_INFO[eff.profile].label} scan: ${profile.checks} built-in checks that apply to this project`,
      eff.online ? "Live vulnerability data for your dependencies" : "Saved vulnerability data (offline)"];
    if (eff.online && profile.registry) will.push("Check your packages really exist on npm and PyPI");
    if (eff.scanners) will.push(env.scanners ? (env.scanners.length ? `Run ${env.scanners.join(", ")}` : "Installed scanners (none installed yet)") : "Installed scanners");
    if (eff.history) will.push("Search git history for deleted secrets");
    if (eff.local_ai) will.push("Local AI review");
    if (eff.online_ai) will.push("Paid online AI review with Claude");
    if (eff.live) will.push(`Live checks against ${liveUrl}${eff.live_writes ? ", including routes that change data" : ""}`);
    if (eff.live && accounts.a.trim() && accounts.b.trim()) will.push("Try to open account A's records as account B");
    const leaves = [];
    if (eff.online) leaves.push("Package names and versions, to OSV.dev, npm and PyPI. CVE IDs, to EPSS.");
    if (eff.online_ai) leaves.push("Your code with secrets masked, to Anthropic.");
    const cost = eff.online_ai && env.online ? `About ${money(Math.min(env.online.cost, env.online.left))} on your Anthropic account, never more than your budget allows.` : "Free.";
    const time = [PROFILE_INFO[eff.profile].time];
    if (eff.local_ai) time.push("plus the local AI review: minutes, longer the first time");
    if (eff.online_ai) time.push("plus a few seconds per part for the online review");
    if (eff.live) time.push("plus up to a minute of live checks");
    summary.replaceChildren(
      h("div", null, h("h3", null, "This scan will"), h("ul", null, will.map((w) => h("li", null, w)))),
      h("div", null, h("h3", null, "What leaves your computer"),
        leaves.length ? h("ul", null, leaves.map((w) => h("li", null, w))) : h("p", null, "Nothing. This scan stays on this computer."),
        h("p", { class: "faint" }, "Your code is never run.")),
      h("div", null, h("h3", null, "Cost and time"), h("p", null, cost), h("p", { class: "faint" }, `${time.join(", ")}.`)));
  };

  const draw = () => {
    const focused = document.activeElement && document.activeElement.id;
    presets.replaceChildren(...PRESETS.map(([label, about, values]) => {
      const pressed = Object.keys(values).every((k) => values[k] === opts[k]);
      return h("button", { type: "button", class: "preset", "aria-pressed": pressed ? "true" : "false", title: about,
        onclick: () => { Object.assign(opts, values); draw(); } }, h("strong", null, label), h("span", { class: "faint" }, about));
    }));
    depth.replaceChildren(...Object.keys(PROFILE_INFO).map((name) => h("button", { type: "button",
      "aria-pressed": name === opts.profile ? "true" : "false", onclick: () => { opts.profile = name; draw(); } }, PROFILE_INFO[name].label)));
    depthText.textContent = `${PROFILE_INFO[opts.profile].looks} ${data.profiles[opts.profile].checks} checks on this project. ${PROFILE_INFO[opts.profile].time}.`;
    toggles.replaceChildren(
      row("online", "Free online vulnerability data", [tag("Free", "free"), tag("online", "where")],
        "Checks the exact versions in your lockfiles against OSV.dev, CISA's actively-exploited list and EPSS. Off means an offline scan."),
      row("scanners", "Installed scanners", [tag("Free", "free"), tag("this computer", "where")], scannerHelp()),
      row("history", "Search git history for secrets", [tag("Free", "free"), tag("this computer", "where")],
        "Finds keys that were committed and later deleted: they're still in history. Slower."),
      row("local_ai", "Local AI review", [tag("Free", "free"), tag("this computer", "where")], localHelp()),
      row("online_ai", "Paid online AI review (Claude)", [tag("Paid", "paid"), tag("sends code", "where")], onlineHelp()),
      row("live", "Live checks against your running app", [tag("Free", "free"), tag("this computer", "where")], liveHelp()),
      row("online_tools", "Paid online scanners", [tag("Paid", "paid"), tag("online", "where")],
        "Commercial services such as Snyk or Socket, using your own account."));
    drawSummary(effective());
    if (focused && document.getElementById(focused) == null) return;
    if (focused && focused.startsWith("opt-")) document.getElementById(focused).focus();
  };

  const start = () => {
    const eff = effective();
    store(`ladpock-scan-${p.id}`, JSON.stringify(opts));
    if (eff.online_ai && env.online && env.online.units + (env.online.leads || 0) > 0) {
      const o = env.online;
      const ok = confirm(`Send ${plural(o.units + (o.leads || 0), "part")} of ${p.name} to Anthropic for the Claude review?\n\n`
        + `Secrets are masked first. Estimated cost about ${money(o.cost)}. You have ${money(o.left)} of your ${money(o.budget)} monthly `
        + "budget left, and the review stops before going over it.");
      if (!ok) return;
    }
    const liveFields = eff.live ? { live_url: liveUrl, live_user_a: accounts.a || undefined, live_user_b: accounts.b || undefined,
      live_own_urls: accounts.own.split("\n").map((u) => u.trim()).filter(Boolean) } : {};
    startTask(`/api/projects/${p.id}/run`, { ...eff, ...liveFields });
  };

  api("GET", "/api/scanners").then((s) => {
    env.scanners = s.tools.filter((t) => t.installed).map((t) => t.name);
    env.missing = s.tools.filter((t) => !t.installed && t.supported).map((t) => t.name);
    draw();
  }).catch(() => {});
  api("GET", "/api/ai").then((info) => { env.ai = info; draw(); }).catch((e) => { env.ai = { available: false, error: e.message }; draw(); });
  api("GET", `/api/projects/${p.id}/online/plan`).then((info) => { env.online = info; draw(); }).catch(() => {});
  draw();

  return h("section", { class: "card scan-panel", "aria-labelledby": "scan-title" },
    h("div", { class: "row spread" }, h("h2", { id: "scan-title" }, "Scan this project"), helpLink("options", "What does each option do?")),
    h("div", { class: "stack" },
      h("div", null, h("h3", { class: "eyebrow" }, "Start from a preset"), presets),
      h("div", null, h("div", { class: "row spread" }, h("h3", { class: "eyebrow" }, "How deep"), depth), depthText, profileComparison(data.profiles)),
      h("div", null, h("h3", { class: "eyebrow" }, "What to include"), toggles),
      summary,
      h("div", { class: "scan-go" }, !p.exists ? h("span", { class: "faint" }, "This folder no longer exists.") : null,
        h("span", { class: "faint" }, "You can leave this page while it runs."), go)));
}

function profileComparison(profiles) {
  const names = Object.keys(PROFILE_INFO);
  const yes = (v) => (v ? "Yes" : "No");
  const rows = [
    ["Checks on this project", (n) => `${profiles[n].checks}`],
    ["What it looks at", (n) => PROFILE_INFO[n].looks],
    ["Installed scanners", (n) => yes(profiles[n].scanners)],
    ["Live vulnerability data", () => "Yes (unless Offline)"],
    ["Checks packages really exist", (n) => yes(profiles[n].registry)],
    ["Git history secrets", (n) => (profiles[n].history ? "Yes, with Gitleaks" : "No")],
    ["Typical time", (n) => PROFILE_INFO[n].time],
    ["Best for", (n) => PROFILE_INFO[n].best],
  ];
  return h("details", { class: "compare" },
    h("summary", null, "What's the difference between Quick, Standard and Full?"),
    h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, ""), names.map((n) => h("th", null, PROFILE_INFO[n].label)))),
      h("tbody", null, rows.map(([label, value]) => h("tr", null, h("th", { scope: "row" }, label), names.map((n) => h("td", null, value(n)))))))),
    h("p", { class: "faint" }, "None of them run your code. The Everything free preset is Full plus the local AI review."));
}

// ---------- local AI ----------

function aiSettings(p, ai) {
  const local = h("div", { class: "stack" }, h("h3", null, "Local AI review"), h("div", { class: "faint" }, h("span", { class: "spinner small" }), " Looking for a local model…"));
  const online = h("div", { class: "stack" }, h("h3", null, "Paid online AI review"), h("div", { class: "faint" }, h("span", { class: "spinner small" }), " Loading…"));
  loadAi(local, p, ai);
  loadOnline(online, p, ai);
  return h("details", { class: "card ai-settings", id: "ai-settings", open: load("ladpock-ai-open") === "1" || null,
    ontoggle: (ev) => store("ladpock-ai-open", ev.currentTarget.open ? "1" : "0") },
    h("summary", null, h("h2", null, "AI settings"),
      h("span", { class: "faint" }, "Local model, nightly reviews, and the paid online review")),
    h("div", { class: "scan-grid", style: "margin-top:12px" }, local, online));
}

async function loadOnline(box, p, ai) {
  let info;
  try { info = await api("GET", "/api/online"); } catch (e) { box.replaceChildren(h("h3", null, "Paid online AI review"), h("p", { class: "faint" }, e.message)); return; }
  const redraw = (next) => { info = next; draw(); };
  const draw = () => {
    const parts = [h("h3", null, "Paid online AI review"),
      h("p", { class: "faint" }, `Claude (${info.model}) reads the same parts as the local review, with secrets masked, and double-checks the local model's leads. `
        + "It's billed to your own Anthropic account. Like local AI results, its leads never change the grade. ", helpLink("online-ai"))];
    if (!info.sdk_installed) {
      parts.push(h("div", { class: "callout" }, h("p", null, "First install Anthropic's Python SDK. It's optional, so LadPock itself stays dependency-free:"),
        h("div", { class: "snippet" }, "python -m pip install anthropic"), h("p", { class: "faint" }, "Then restart ladpock ui.")));
    }
    const enabled = h("input", { type: "checkbox", class: "switch", role: "switch", id: "online-enabled", checked: info.enabled || null });
    enabled.addEventListener("change", async () => {
      try {
        redraw(await api("POST", "/api/online/settings", { enabled: enabled.checked }));
        toast(enabled.checked ? "Online AI review allowed. Turn it on in the scan panel when you want it." : "Online AI review turned off");
      } catch (e) { enabled.checked = !enabled.checked; toast(e.message); }
    });
    parts.push(h("div", { class: "toggle-row bare" }, enabled, h("div", { class: "grow" },
      h("label", { for: enabled.id }, h("strong", null, "Allow sending code to Anthropic")),
      h("div", { class: "faint" }, "Nothing is sent until you also switch on the paid online AI review for a scan. Secrets are masked first."))));

    const key = info.key;
    if (key.stored) {
      parts.push(h("div", { class: "row" }, h("span", null, "API key ", h("span", { class: "mono" }, key.masked)),
        h("span", { class: "faint" }, "saved in Windows Credential Manager"),
        h("button", { class: "btn small", onclick: async () => {
          if (!confirm("Remove the saved API key from Windows Credential Manager?")) return;
          redraw(await api("DELETE", "/api/online/key"));
          toast("Key removed");
        } }, "Remove")));
    } else if (key.env) {
      parts.push(h("p", { class: "faint" }, "Using the key in your ANTHROPIC_API_KEY environment variable."));
    } else if (key.can_store) {
      const input = h("input", { type: "password", class: "field grow", placeholder: "sk-ant-…", autocomplete: "off", "aria-label": "Anthropic API key" });
      parts.push(h("div", { class: "form-inline" }, input, h("button", { class: "btn small", onclick: async () => {
        try { redraw(await api("POST", "/api/online/key", { key: input.value })); toast("Key saved in Windows Credential Manager"); }
        catch (e) { toast(e.message); }
      } }, "Save key")),
      h("p", { class: "faint" }, "Create a key at console.anthropic.com. It's stored in Windows Credential Manager, never in LadPock's files, and only its last four characters are ever shown."));
    } else {
      parts.push(h("p", { class: "faint" }, "Set ANTHROPIC_API_KEY in the terminal you start ladpock ui from."));
    }

    const budget = h("input", { type: "number", class: "field", min: "0", max: "1000", step: "1", value: String(info.budget), "aria-label": "Monthly budget in US dollars", style: "max-width:110px" });
    const used = info.budget ? Math.min(100, Math.round(100 * info.spent / info.budget)) : 100;
    parts.push(h("div", { class: "stack" },
      h("div", { class: "form-inline" }, h("span", null, "Monthly budget $"), budget, h("button", { class: "btn small", onclick: async () => {
        try { redraw(await api("POST", "/api/online/settings", { budget: Number(budget.value) })); toast("Budget saved"); } catch (e) { toast(e.message); }
      } }, "Save")),
      h("div", { class: "faint" }, `Spent this month: ${money(info.spent)} of ${money(info.budget)}. That's LadPock's estimate; your Anthropic console has the exact bill.`),
      progressBar(used)));

    const labels = { low: "Low: cheapest", medium: "Medium: balanced (default)", high: "High: most thorough, roughly twice the cost" };
    const effort = h("select", { class: "field", "aria-label": "Effort", style: "max-width:280px" },
      info.efforts.map((e) => h("option", { value: e, selected: e === info.effort || null }, labels[e] || e)));
    effort.addEventListener("change", async () => { try { redraw(await api("POST", "/api/online/settings", { effort: effort.value })); } catch (e) { toast(e.message); } });
    parts.push(h("label", { class: "row" }, h("span", { class: "faint" }, "Effort"), effort));

    const never = h("input", { type: "checkbox", id: "online-never", checked: ai.never_online || null });
    never.addEventListener("change", async () => {
      await api("POST", `/api/projects/${p.id}/online/never`, { never: never.checked });
      toast(never.checked ? `${p.name} will never be sent online` : `${p.name} can be sent to the online review`);
      const r = currentRoute();
      renderProject(p.id, r.tab, state.view, r.sub);
    });
    parts.push(h("label", { class: "option", for: never.id }, never, h("span", null, "Never send this project online", h("br"),
      h("span", { class: "faint" }, "For client work or anything under an NDA. Overrides the scan panel."))));

    const last = ai.last_online_run;
    parts.push(last ? h("p", { class: "faint" }, `Last online review ${ago(last.finished_at || last.started_at)}: ${plural(last.done, "part")} read, `
      + `${plural(last.leads, "new lead")}. ${last.message || ""}`) : h("p", { class: "faint" }, "No online review yet."));
    box.replaceChildren(...parts);
  };
  draw();
}

async function loadAi(box, p, ai) {
  let info;
  try { info = await api("GET", "/api/ai"); } catch (e) { info = { available: false, error: e.message }; }
  const title = h("h3", null, "Local AI review");
  if (!info.available) {
    box.replaceChildren(title,
      h("p", { class: "muted" }, "Reads your routes, commands and code with a model running on this computer, to find logic bugs pattern checks can't. Free, and your code never leaves your machine."),
      h("p", { class: "faint" }, "Needs Ollama (ollama.com) running with a model installed, for example: ollama pull qwen2.5-coder:14b"),
      h("p", { class: "faint" }, info.error || ""), helpLink("ai", "How the AI review works"));
    return;
  }
  const select = h("select", { class: "field", "aria-label": "Model" }, info.models.map((m) =>
    h("option", { value: m.name, selected: m.name === info.model || null }, `${m.name} · ${m.size_gb} GB${m.fits_gpu ? "" : " (bigger than GPU: slower)"}`)));
  select.addEventListener("change", async () => {
    try { await api("POST", "/api/ai/settings", { model: select.value }); toast(`Using ${select.value}`); } catch (e) { toast(e.message); }
  });
  const think = h("input", { type: "checkbox", id: "ai-think", checked: info.think || null });
  think.addEventListener("change", async () => { await api("POST", "/api/ai/settings", { think: think.checked }); });
  const nightly = h("input", { type: "checkbox", id: "ai-nightly", checked: ai.nightly || null });
  nightly.addEventListener("change", async () => {
    await api("POST", `/api/projects/${p.id}/ai/nightly`, { enabled: nightly.checked });
    toast(nightly.checked ? "Included in the nightly review" : "Removed from the nightly review");
  });
  const estimate = h("span", { class: "faint" });
  const runBtn = runButton("Review now", () => startTask(`/api/projects/${p.id}/ai/run`, {}));
  const estimateBtn = h("button", { class: "btn small", onclick: async () => {
    estimateBtn.setAttribute("aria-busy", "true");
    estimate.textContent = "Loading the model and timing a sample…";
    try {
      const res = await api("POST", "/api/ai/benchmark", { project_id: p.id });
      pollJobs();
      const result = await waitForJob(res.job);
      const mins = Math.max(1, Math.round((result.estimate_seconds || 0) / 60));
      estimate.textContent = result.todo
        ? `${result.todo} of ${result.parts} parts need reviewing: about ${mins} minute${mins === 1 ? "" : "s"} on this computer.`
        : `Nothing has changed since the last review (${result.parts} parts), so a review would finish almost instantly.`;
    } catch (e) { estimate.textContent = e.message; }
    estimateBtn.removeAttribute("aria-busy");
  } }, "Estimate time");

  const last = ai.last_run;
  const lastLine = last ? h("p", { class: "faint" },
    `Last review ${ago(last.finished_at || last.started_at)}: ${last.done} parts read (${last.cached} unchanged), ${plural(last.leads, "new lead")}. `
    + `Filtered out ${last.dropped} quoting code that doesn't exist and ${last.rejected || 0} that failed a second look.`,
    last.message ? ` ${last.message}` : "")
    : h("p", { class: "faint" }, "Not reviewed yet. The first review reads everything; later ones only re-read what changed.");

  box.replaceChildren(title,
    h("p", { class: "faint" }, "Runs on this computer. Results are leads to check, not findings: they never change the grade. ", helpLink("ai")),
    h("label", { class: "row" }, h("span", { class: "faint" }, "Model"), select),
    h("label", { class: "option", for: think.id }, think, h("span", null, "Let the model think first", h("br"), h("span", { class: "faint" }, "Slower, sometimes catches more."))),
    h("div", { class: "row" }, runBtn, estimateBtn), estimate, lastLine,
    h("label", { class: "option", for: nightly.id }, nightly, h("span", null, "Include in the nightly review")),
    scheduleBlock(info.schedule || {}));
  drawJobBanner();  // the buttons just drawn should reflect a task that's already running
}

function scheduleBlock(schedule) {
  const box = h("div", { class: "stack" });
  const draw = (s) => {
    if (s.supported === false) {
      box.replaceChildren(h("p", { class: "faint" }, "Nightly scheduling is built in on Windows. Elsewhere, run `ladpock ai review --all` from cron."));
    } else if (s.scheduled) {
      box.replaceChildren(h("div", { class: "row" }, h("span", { class: "faint" }, `Nightly review is on. Next run: ${s.next_run || "unknown"}`),
        h("button", { class: "btn small", onclick: async () => draw(await api("DELETE", "/api/ai/schedule")) }, "Turn off")));
    } else {
      const at = h("input", { type: "time", class: "field", value: "01:00", "aria-label": "Start time" });
      const until = h("input", { type: "time", class: "field", value: "07:00", "aria-label": "Stop time" });
      const wake = h("input", { type: "checkbox", id: "ai-wake" });
      const setUp = h("button", { class: "btn small", onclick: () => {
        box.replaceChildren(h("div", { class: "form-inline" }, "Start", at, "stop by", until),
          h("label", { class: "option", for: wake.id }, wake, h("span", null, "Wake the computer from sleep", h("br"),
            h("span", { class: "faint" }, "Needs wake timers allowed in Windows power settings."))),
          h("div", { class: "row" },
            h("button", { class: "btn small primary", onclick: async () => {
              if (!confirm(`Create a Windows scheduled task, for your account only, that reviews the projects you've included every night from ${at.value} until ${until.value}, only when plugged in?`)) return;
              try { draw(await api("POST", "/api/ai/schedule", { at: at.value, until: until.value, wake: wake.checked })); toast("Nightly review scheduled"); }
              catch (e) { toast(e.message); }
            } }, "Create schedule"),
            h("button", { class: "btn small", onclick: () => draw(s) }, "Cancel")));
      } }, "Set up nightly review…");
      box.replaceChildren(h("div", { class: "row" }, h("span", { class: "faint" }, "Nightly review isn't scheduled."), setUp));
    }
  };
  draw(schedule);
  return box;
}

async function waitForJob(jobId) {
  for (;;) {
    const job = await api("GET", `/api/jobs/${jobId}`);
    if (job.status === "done") return job.result;
    if (job.status === "error") throw new Error(job.error || "Failed");
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

function leadsSection(projectId, leads) {
  if (!leads.length) return null;
  const open = leads.filter((l) => l.status !== "dismissed");
  const dismissed = leads.filter((l) => l.status === "dismissed");
  const list = h("div", { class: "card flush" },
    h("div", { class: "group-head" }, `AI leads (${open.length})`),
    open.map((l) => leadEl(projectId, l)),
    dismissed.length ? h("details", null, h("summary", { class: "faint", style: "padding:10px 20px;cursor:pointer" }, `${dismissed.length} dismissed`),
      dismissed.map((l) => leadEl(projectId, l))) : null);
  return h("div", { class: "stack" }, list,
    h("p", { class: "faint" }, "Found by an AI review (local, or Claude online) and checked against your code: the quoted line exists. They're not verified and never change the grade. Confirm the real ones to include them in the fix prompt; dismissed leads stay dismissed."));
}

function leadEl(projectId, l) {
  const setStatus = async (status) => {
    await api("POST", `/api/projects/${projectId}/ai/leads/${l.id}`, { status });
    toast(status === "confirmed" ? "Confirmed. It's now included in the fix prompt." : status === "dismissed" ? "Dismissed" : "Reopened");
    renderProject(projectId, "findings", state.view);
  };
  const who = (l.model || "").startsWith("claude") ? "Claude" : "AI";
  const second = { confirmed: "looks real", doubtful: "probably not a real problem", unsure: "can't tell" }[l.online_verdict];
  return h("details", { class: "finding" },
    h("summary", null, sevPill(l.severity), h("span", { class: "chip accent" }, l.status === "confirmed" ? `${who} · confirmed` : `${who} lead`),
      second ? h("span", { class: `chip${l.online_verdict === "confirmed" ? " accent" : ""}` }, `Claude: ${second}`) : null,
      h("span", { class: "title" }, l.title), h("span", { class: "mono faint" }, `${l.file}:${l.line}`)),
    h("div", { class: "body" },
      h("div", { class: "snippet" }, l.quote),
      h("p", null, h("strong", null, "Why it might matter: "), l.explanation),
      l.fix ? h("p", null, h("strong", null, "Suggested fix: "), l.fix) : null,
      second ? h("p", { class: "faint" }, h("strong", null, "Claude's second opinion: "), second, l.online_reason ? ` (${l.online_reason})` : "") : null,
      h("p", { class: "faint" }, `${l.category} · ${l.model}`),
      h("div", { class: "row" },
        l.status !== "confirmed" ? h("button", { class: "btn small", onclick: () => setStatus("confirmed") }, "Confirm") : null,
        l.status !== "dismissed" ? h("button", { class: "btn small", onclick: () => setStatus("dismissed") }, "Dismiss") : null,
        l.status !== "new" ? h("button", { class: "btn small", onclick: () => setStatus("new") }, "Reopen") : null,
        h("button", { class: "btn small", onclick: async () => {
          const res = await api("GET", `/api/projects/${projectId}/fix-prompt?lead=${l.id}`);
          await copy(res.prompt);
          toast("Fix prompt copied");
        } }, "Copy fix prompt"))));
}

// ---------- findings ----------

function drawFindings(container, projectId, data, summary) {
  const findings = data.findings;
  const cats = summary.categories || [];
  container.append(h("div", { class: "scorecard" }, cats.map((c) => h("a", { class: "score-tile", href: `#/project/${projectId}/grade/${c.key}`,
    title: c.grade === "A+" ? `${c.name}: no open findings` : `Why ${c.name} is ${c.grade}, and how to fix it` },
    h("span", { class: "label" }, c.name), gradeEl(c.grade)))),
    h("p", { class: "faint" }, "Click any grade to see where the points went and how to reach A+."));
  if (summary.changes) container.append(changesCard(summary.changes, data.scan));
  if (summary.live && !summary.live.error) container.append(liveCard(summary.live));
  const newRefs = new Set((summary.changes && summary.changes.new) || []);

  const scanners = (summary.scanners || []).map((s) => !s.available ? `${s.name} not installed` : s.ran ? `${s.name} ran` : `${s.name} failed`);
  const info = [`Built-in: ${summary.checks_run ?? "?"} checks`, ...scanners, `${summary.dependencies ?? 0} dependencies checked`];
  container.append(h("div", { class: "row spread" }, h("p", { class: "faint" }, info.join(" · ")), reportButton(projectId)));
  if (summary.suppressed) {
    container.append(h("p", { class: "faint", style: "color:var(--medium)" },
      `${plural(summary.suppressed, "finding")} hidden by 'accept risk', ladpock-ignore comments or ladpock.toml. Check any you didn't add yourself.`));
  }
  if ((summary.errors || []).length) {
    container.append(h("details", { class: "faint" }, h("summary", null, plural(summary.errors.length, "warning")),
      h("ul", null, summary.errors.map((e) => h("li", null, e)))));
  }
  const leads = leadsSection(projectId, data.ai.leads);
  if (leads) container.append(leads);
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
      h("div", { class: "group-head" }, `${sev} (${items.length})`), ...items.map((f) => findingEl(f, projectId, data.ai.verdicts[f.ref], newRefs.has(f.ref)))])
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

function reportButton(projectId) {
  return h("button", { class: "btn small", title: "A one-page summary you can keep, print or send. Secrets are masked.", onclick: async () => {
    const res = await api("GET", `/api/projects/${projectId}/report`);
    const url = URL.createObjectURL(new Blob([res.html], { type: "text/html" }));
    const link = h("a", { href: url, download: res.filename });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    toast(`Report ready: ${res.filename}. Keep it private, as it includes code snippets.`);
  } }, "Download report");
}

function liveCard(live) {
  const accounts = live.accounts;
  const notes = live.notes || [];
  return h("section", { class: "card changes", "aria-label": "Live checks" },
    h("div", { class: "row" }, h("strong", null, "Live checks"), h("span", { class: "faint mono" }, live.url)),
    h("p", null, `${plural(live.requests, "request")}, ${plural(live.routes, "route")} called · `,
      h("span", { class: live.confirmed ? "cell-no" : "cell-yes" }, `${plural(live.confirmed, "problem")} confirmed`)),
    accounts ? h("p", null, `Two accounts: ${plural(accounts.records_checked, "record")} tried as the other account · `,
      h("span", { class: accounts.exposed ? "cell-no" : "faint" }, `${accounts.exposed} opened`), " · ",
      h("span", { class: accounts.protected ? "cell-yes" : "faint" }, `${accounts.protected} refused`),
      accounts.admin_exposed ? h("span", { class: "cell-no" }, ` · ${plural(accounts.admin_exposed, "admin endpoint")} open to ordinary accounts`) : null)
      : h("p", { class: "faint" }, "Called without logging in. Add two test accounts in the scan panel to test whether one user can read another's data."),
    notes.length ? h("ul", { class: "fixed-list faint" }, notes.map((note) => h("li", null, note))) : null);
}

function changesCard(c, scan) {
  const delta = scan.score - (c.previous_score || 0);
  const fixed = c.fixed || [];
  const where = (f) => (f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "");
  return h("section", { class: "card changes", "aria-label": "Since the last scan" },
    h("div", { class: "row spread" },
      h("div", { class: "row" }, h("strong", null, "Since the last scan"), h("span", { class: "faint" }, ago(c.previous_at))),
      h("div", { class: "row" }, gradeEl(c.previous_grade), h("span", { class: "arrow" }, "→"), gradeEl(scan.grade),
        h("span", { class: delta > 0 ? "cell-yes" : delta < 0 ? "cell-no" : "faint" }, `${delta > 0 ? "+" : ""}${delta} points`))),
    h("p", null, h("span", { class: c.fixed_count ? "cell-yes" : "faint" }, `${plural(c.fixed_count, "finding")} fixed`), " · ",
      h("span", { class: c.new.length ? "cell-mid" : "faint" }, `${c.new.length} new`),
      c.new.length ? h("span", { class: "faint" }, " (marked New below)") : null),
    c.same_profile ? null : h("p", { class: "faint" }, `The previous scan was ${c.previous_profile}, so some differences come from `
      + "running a different set of checks, not from code changes."),
    fixed.length ? h("details", null, h("summary", { class: "faint", style: "cursor:pointer" }, "What was fixed"),
      h("ul", { class: "fixed-list" }, fixed.map((f) => h("li", null, sevPill(f.severity), " ", f.title, " ",
        h("span", { class: "mono faint" }, where(f)))))) : null);
}

function findingEl(f, projectId, verdict, isNew) {
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
    h("summary", null, sevPill(f.severity), isNew ? h("span", { class: "chip accent" }, "New") : null,
      f.source === "live" || (f.extra && f.extra.live === "confirmed") ? h("span", { class: "chip", title: "Seen on your running app, not just in the code" }, "Confirmed live") : null,
      f.extra && f.extra.live === "refused" ? h("span", { class: "chip", title: "The code looked unprotected, but your running app refused the request" }, "Refused live") : null,
      h("span", { class: "title" }, f.title),
      f.file ? h("span", { class: "mono faint" }, f.line ? `${f.file}:${f.line}` : f.file) : null),
    h("div", { class: "body" },
      f.snippet ? h("div", { class: "snippet" }, f.snippet) : null,
      h("p", null, h("strong", null, "Why it matters: "), f.message),
      f.fix ? h("p", null, h("strong", null, "How to fix: "), f.fix) : null,
      verdict ? h("p", { class: "faint" }, h("strong", null, (verdict.model || "").startsWith("claude") ? "Claude's second opinion: " : "Local AI second opinion: "),
        { real: "likely real", false_alarm: "likely a false alarm", unsure: "can't tell" }[verdict.verdict] || verdict.verdict,
        ` (${verdict.reason}) Advisory only; it doesn't change the grade.`) : null,
      h("p", { class: "faint" }, [f.check_id, `confidence ${f.confidence}`, f.source !== "ladpock" ? `via ${f.source}` : null, ...(f.cwe || []), `ref ${f.ref}`].filter(Boolean).join(" · ")),
      actions));
  return details;
}

// ---------- why this grade ----------

const WEIGHT_TEXT = "Critical findings take 40 points off their category, high 20, medium 8 and low 2. Low-confidence findings count half.";

function drawGrade(container, id, data, focus) {
  const a = data.assessment;
  if (!a) { container.append(h("p", { class: "muted" }, "Scan this project first.")); return; }
  const byRef = new Map(data.findings.map((f) => [f.ref, f]));
  const where = (d) => (d.file ? `${d.file}${d.line ? `:${d.line}` : ""}` : "");
  const promptButton = (refs, label) => h("button", { class: "btn small", onclick: async () => {
    const query = refs.slice(0, 25).map((r) => `ref=${encodeURIComponent(r)}`).join("&");
    const res = await api("GET", `/api/projects/${id}/fix-prompt?${query}`);
    await copy(res.prompt);
    toast("Fix prompt copied. Paste it into Claude Code or your AI assistant.");
  } }, label);

  // 1. the answer, in a sentence or two
  const below = a.categories.filter((c) => c.score < 97).sort((x, y) => x.score - y.score);
  const reasons = [];
  if (a.perfect) reasons.push("Nothing is open. Every category is at 100.");
  else {
    if (a.cap) reasons.push(h("li", null, `Your categories average ${a.average}/100, but ${a.cap.unconfirmed ? "an unconfirmed" : "an open"} ${a.cap.severity} finding limits the overall score to `
      + `${a.cap.limit} until it's fixed. An average would hide it: one real problem barely moves it.`));
    else reasons.push(h("li", null, `Your overall score is the average of ${plural(a.categories.length, "category", "categories")}: ${a.average}/100.`));
    if (below.length) reasons.push(h("li", null, "Categories below A+: ", below.map((c, i) => [i ? ", " : "",
      h("a", { href: `#/project/${id}/grade/${c.key}` }, `${c.name} ${c.grade} (${c.score})`)])));
    const counts = data.scan.summary.counts || {};
    const open = SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`);
    if (open.length) reasons.push(h("li", null, `Open findings: ${open.join(", ")}. ${WEIGHT_TEXT}`));
  }
  container.append(h("section", { class: "card grade-hero" },
    h("div", { class: "row" }, gradeEl(a.grade, true), h("div", { class: "grow" },
      h("h2", null, a.perfect ? "Top marks: nothing open" : `Why ${a.grade} and not A+`),
      h("div", { class: "faint" }, `${a.score}/100`))),
    a.perfect ? h("p", null, reasons[0]) : h("ul", { class: "reasons" }, reasons)));

  // 2. the path to A+, most serious first, with the grade after each step
  if (a.plan.length) {
    let before = { score: a.score, grade: a.grade };
    container.append(h("section", { class: "card flush" },
      h("div", { class: "group-head" }, "Your path to A+"),
      a.plan.map((step, i) => {
        const items = step.refs.map((r) => byRef.get(r)).filter(Boolean);
        const from = before;
        before = step;
        return h("div", { class: "plan-step" },
          h("span", { class: "num" }, String(i + 1)),
          h("div", { class: "grow" },
            h("div", { class: "row" }, h("strong", null, `Fix ${plural(step.count, `${step.severity} finding`)}`),
              h("span", { class: "faint" }, `${from.grade} (${from.score})`), h("span", { class: "arrow" }, "→"), gradeEl(step.grade),
              h("span", { class: "faint" }, `${step.score}/100`)),
            h("ul", null, items.slice(0, 8).map((f) => h("li", null, h("span", null, f.title), " ", h("span", { class: "mono faint" }, where(f))))),
            items.length > 8 ? h("p", { class: "faint" }, `…and ${items.length - 8} more`) : null),
          promptButton(step.refs, `Copy fix prompt${step.count > 25 ? " (first 25)" : ""}`));
      }),
      h("p", { class: "faint", style: "padding:12px 20px" }, "Grades after each step assume the earlier steps are done. "
        + "Accepting a risk also removes a finding, but only do that for deliberate choices.")));
  }

  // 3. where every point went
  container.append(h("h2", null, "Where the points went"),
    h("div", { class: "card flush" }, a.categories.map((c) => {
      const worst = c.deductions.length ? c.deductions[0].severity : null;
      const floor = c.floored ? (c.deductions.some((d) => d.severity === "medium") ? 70 : 83) : null;
      return h("details", { class: `finding cat-detail${focus === c.key ? " focus" : ""}`, id: `cat-${c.key}`, open: (focus === c.key || (!focus && c.score < 97)) || null },
        h("summary", null, gradeEl(c.grade), h("span", { class: "title" }, c.name), h("span", { class: "faint" }, `${c.score}/100`),
          c.deductions.length ? h("span", { class: "faint" }, plural(c.deductions.length, "finding")) : h("span", { class: "cell-yes" }, "nothing open")),
        h("div", { class: "body" },
          c.deductions.length ? [
            h("p", { class: "faint" }, `Starts at 100. ${c.deductions.length > 1 ? "These take" : "This takes"} ${c.deductions.reduce((s, d) => s + d.points, 0)} points off`
              + (floor ? `, but a category whose worst finding is ${worst} can't drop below ${floor}, so it stays at ${c.score}.` : ".")),
            h("div", { class: "table-wrap" }, h("table", null, h("tbody", null, c.deductions.map((d) => h("tr", null,
              h("td", { class: "points" }, `−${d.points}`), h("td", null, sevPill(d.severity)),
              h("td", null, d.title, d.confidence === "low" ? h("span", { class: "faint" }, " (low confidence: counts half)") : null),
              h("td", { class: "mono faint" }, where(d))))))),
            h("div", { class: "row" }, promptButton(c.deductions.map((d) => d.ref), `Copy fix prompt for ${c.name}`),
              h("a", { class: "btn small", href: `#/project/${id}/findings` }, "See these findings")),
          ] : h("p", { class: "muted" }, "No open findings in this category. That means none of LadPock's checks matched, not that it's guaranteed safe.")));
    })));

  // 4. how complete the assessment itself was
  if (a.gaps.length) {
    container.append(h("h2", null, "Make the assessment more complete"),
      h("p", { class: "muted" }, "A grade is only as good as what was checked. These would let LadPock see more:"),
      h("div", { class: "card flush list" }, a.gaps.map((g) => h("div", { class: "gap-row" },
        h("div", { class: "grow" }, h("strong", null, g.title), h("p", { class: "faint" }, g.detail)),
        g.href ? h("a", { class: "btn small", href: g.href }, g.fix) : h("span", { class: "faint" }, g.fix)))));
  }

  // 5. how it's worked out, and what it leaves out
  const leads = data.ai.leads.filter((l) => l.status === "new").length;
  container.append(h("section", { class: "card stack" },
    h("h3", null, "How the grade is worked out"),
    h("ul", null,
      h("li", null, `Each category starts at 100. ${WEIGHT_TEXT}`),
      h("li", null, "Small issues alone can't sink a category: with only medium findings it stays at 70 (C-) or above, with only low ones at 83 (B) or above."),
      h("li", null, "The overall score is the average of the categories, limited while anything is open: 59 (F) with a critical finding, 79 (C+) with a high one, 89 (B+) with a medium one and 96 (A) with a low one. A low-confidence finding limits it one step less. A+ means nothing is open."),
      h("li", null, "A+ is 97 or more, A 93, B 83, C 73, D 63; below 60 is F.")),
    h("p", { class: "faint" }, leads ? `${plural(leads, "AI lead")} ${leads === 1 ? "is" : "are"} waiting for you on the Findings tab. AI leads never change the grade, so confirm or dismiss them yourself. ` : "",
      "Some protections can't be seen in code at all, so work through the Needs a human tab too. ", helpLink("grades", "More about grades"))));
}

// ---------- routes / deps / human / history ----------

async function drawRoutes(container, id, view) {
  container.append(spinner("Mapping routes"));
  let data;
  try { data = await api("GET", `/api/projects/${id}/routes`); } catch (e) { container.replaceChildren(h("p", { class: "muted" }, e.message)); return; }
  if (view !== state.view) return;
  if (!data.routes.length && !data.commands.length) {
    container.replaceChildren(h("div", { class: "card empty" }, h("h2", null, "No routes or commands found"),
      h("p", { class: "muted" }, "This view understands Next.js, SvelteKit, Remix, Nuxt, Astro, Express, Fastify, Hono, Koa, NestJS, FastAPI, Flask, Django, Spring, Go, Rails, Laravel, ASP.NET, tRPC, Convex, GraphQL, Firebase Functions, Supabase Edge Functions, Vercel, Netlify, Cloudflare, AWS Lambda, Rust (Axum, Actix, Rocket), Elysia, Hapi, Sinatra, Symfony, Ktor, JAX-RS and Micronaut routes, and Tauri commands.")));
    return;
  }
  const cell = (value) => h("td", { class: value === "no" || value === "none" ? "cell-no" : value === "yes" || value === "sig" || value === "rls" || value === "dir" ? "cell-yes" : value === "mw" || value === "ext" ? "cell-mid" : "faint" }, value);
  container.replaceChildren();
  if (data.commands.length) container.append(...commandsTable(data.commands, cell));
  if (!data.routes.length) return;
  const withGaps = data.routes.filter((r) => r.gaps.length).length;
  const kinds = [...new Set(data.routes.map((r) => r.kind))].sort();
  let onlyGaps = false;
  const search = h("input", { type: "search", placeholder: "Search paths or files", "aria-label": "Search routes" });
  const kind = kinds.length > 1 ? h("select", { "aria-label": "Kind of route" }, h("option", { value: "" }, "All kinds"), kinds.map((k) => h("option", { value: k }, k))) : null;
  const toggle = withGaps ? h("button", { class: "filter", "aria-pressed": "false", onclick: () => {
    onlyGaps = !onlyGaps;
    toggle.setAttribute("aria-pressed", String(onlyGaps));
    draw();
  } }, `Only the ${withGaps} with gaps`) : null;
  const body = h("tbody");
  const count = h("p", { class: "faint" });
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    const shown = data.routes.filter((r) => (!onlyGaps || r.gaps.length) && (!kind || !kind.value || r.kind === kind.value)
      && (!q || `${r.method} ${r.path} ${r.file}`.toLowerCase().includes(q)));
    count.textContent = `${plural(data.routes.length, "endpoint")}, ${withGaps} with gaps.` + (shown.length < data.routes.length ? ` Showing ${shown.length}.` : "");
    body.replaceChildren(...(shown.length ? shown.map((r) => h("tr", null,
      h("td", { class: "mono" }, r.method),
      h("td", null, h("div", { class: "mono" }, r.path), h("div", { class: "mono faint small-print" }, `${r.file}:${r.line}`, kinds.length > 1 ? ` · ${r.kind}` : "")),
      cell(r.auth), cell(r.owner), cell(r.validation), cell(r.rate_limit),
      h("td", { style: r.gaps.length ? "color:var(--medium)" : "" }, r.gaps.join(", ") || "–", r.notes && r.notes.length ? h("div", { class: "faint small-print" }, r.notes.join(", ")) : null)))
      : [h("tr", null, h("td", { colspan: "7", class: "faint" }, "Nothing matches these filters."))]));
  };
  search.addEventListener("input", draw);
  if (kind) kind.addEventListener("change", draw);
  draw();
  container.append(
    h("h2", null, "Routes"),
    count,
    h("div", { class: "toolbar" }, toggle, search, kind),
    h("div", { class: "card flush table-wrap", style: "margin-top:10px" }, h("table", null,
      h("thead", null, h("tr", null, ["Method", "Path", "Auth", "Owner check", "Validation", "Rate limit", "Gaps"].map((t) => h("th", null, t)))),
      body)),
    h("p", { class: "faint" }, "Auth: yes = checked in the handler, mw = only in middleware or a gateway in front of it, sig = webhook signature. Owner: rls = relies on Supabase Row Level Security. This is read from your current code and is heuristic: treat “no” as “go and look”."));
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
        h("span", null, item.text, item.checked_at ? h("span", { class: "faint" }, `  ·  confirmed ${ago(item.checked_at)}`) : null,
          item.evidence ? h("div", { class: "faint small-print" }, item.evidence) : null));
    })));
}

function drawHistory(container, history) {
  container.append(h("div", { class: "card flush table-wrap" }, h("table", null,
    h("thead", null, h("tr", null, ["When", "Profile", "Grade", "Score", ""].map((t) => h("th", null, t)))),
    h("tbody", null, history.map((s) => h("tr", null,
      h("td", null, new Date(s.started_at).toLocaleString()), h("td", null, s.profile), h("td", null, gradeEl(s.grade)),
      h("td", null, `${s.score}/100`), h("td", { style: "width:35%" }, h("div", { class: "bar" }, h("span", { style: `width:${s.score}%` })))))))));
}

// ---------- optional scanners ----------

async function renderScanners(view) {
  if (!document.querySelector(".scanners-page")) $("#app").replaceChildren(spinner("Checking installed scanners"));
  const data = await api("GET", "/api/scanners");
  if (view !== state.view) return;
  const mb = (bytes) => `${(bytes / 1e6).toFixed(1)} MB`;
  const installable = data.tools.filter((t) => t.supported && !(t.installed && (!t.managed || t.up_to_date)));
  const install = (tools) => {
    const lines = tools.map((t) => `• ${t.file} (${mb(t.download_size)}) from github.com/${t.repo}, ${t.license} licence`);
    const total = tools.reduce((sum, t) => sum + t.download_size, 0);
    if (!confirm(`Download and install?\n\n${lines.join("\n")}\n\nTotal ${mb(total)}. Each file is checked against the SHA-256 `
      + "built into LadPock before it's installed; anything that doesn't match is deleted.")) return;
    startTask("/api/scanners/install", { names: tools.map((t) => t.name) });
  };
  const card = (t) => {
    let state_, action = null;
    if (!t.supported) state_ = h("span", { class: "faint" }, "No pinned build for this computer");
    else if (t.installed && !t.managed) state_ = h("span", { class: "cell-yes" }, `Installed (${t.installed_version || "found"} at ${t.path})`);
    else if (t.installed && t.up_to_date) state_ = h("span", { class: "cell-yes" }, `Installed by LadPock (${t.installed_version || t.version})`);
    else if (t.installed) state_ = h("span", { class: "cell-mid" }, `Installed by LadPock, ${t.version} available`);
    else state_ = h("span", { class: "faint" }, "Not installed");
    if (t.supported && !(t.installed && (!t.managed || t.up_to_date))) {
      action = runButton(t.installed ? "Update" : "Install", () => install([t]));
    } else if (t.managed) {
      action = h("button", { class: "btn small", onclick: async () => {
        if (!confirm(`Remove ${t.name} from LadPock's folder?`)) return;
        await api("POST", "/api/scanners/remove", { name: t.name });
        toast(`Removed ${t.name}`);
        renderScanners(state.view);
      } }, "Remove");
    }
    return h("div", { class: "folder-row", style: "align-items:flex-start" },
      h("div", { class: "grow" },
        h("div", { class: "row" }, h("strong", null, t.name), h("span", { class: "chip" }, `v${t.version}`),
          h("span", { class: "faint" }, `${t.license} · released ${t.released}${t.download_size ? ` · ${mb(t.download_size)}` : ""}`)),
        h("p", { class: "muted", style: "margin-top:4px" }, t.adds),
        h("div", { style: "margin-top:4px" }, state_)),
      action);
  };
  $("#app").replaceChildren(h("div", { class: "stack scanners-page" },
    h("a", { href: "#/" }, "← Your projects"),
    h("div", { class: "section-title" }, h("h1", null, "Optional scanners"),
      installable.length ? runButton(`Install ${installable.length === data.tools.length ? "all" : "missing"} (${mb(installable.reduce((s, t) => s + t.download_size, 0))})`,
        () => install(installable), true) : null),
    h("p", { class: "muted" }, "LadPock works on its own. These free, open-source tools add coverage, and every scan uses them automatically once installed. ",
      helpLink("scanners", "How installing works")),
    h("div", { id: "job-banner" }),
    h("div", { class: "card flush list" }, data.tools.map(card)),
    h("p", { class: "faint" }, `Installed into ${data.bin_dir}. Nothing is added to your PATH or run with administrator rights. `
      + "Versions are pinned inside LadPock and only change when LadPock itself is updated.")));
  drawJobBanner();
}

// ---------- help ----------

const HELP = [
  ["start", "How LadPock works", [
    "LadPock reads your project's files (it never runs them) and looks for the security mistakes AI-written code tends to make. It does four kinds of checking:",
    ["Built-in checks: patterns and structure, such as admin keys in browser code, routes that never check who's calling, Supabase tables without Row Level Security, or Tauri commands that write wherever the page says.",
      "Installed scanners, if you have them: Gitleaks for secrets (including git history), OSV-Scanner and Opengrep.",
      "Your dependencies, checked against live vulnerability databases every time.",
      "Optionally, an AI review that reads your code for logic bugs patterns can't see: a free local model, or Claude online with your own API key."],
    "Everything it finds becomes a finding with a severity and a confidence. Findings are grouped into categories, and each category gets a grade.",
  ]],
  ["running", "Running tasks", [
    "Scans, full checks and AI reviews run in the background. While one is running you'll see:",
    ["a spinner and percentage in the top bar (click it for details)",
      "a blue “Running” banner on the project's page, with the current step and a Stop button where stopping is possible",
      "“● Running” in the browser tab title"],
    "When it finishes, a message pops up, the banner turns green (or red if it failed), and the page refreshes with the new results. Tasks keep going if you switch pages, but stop if you close the terminal running `ladpock ui`.",
    "Only one task runs per project at a time, and only one task can use the local AI model at a time. LadPock tells you if you need to wait.",
  ]],
  ["profiles", "Quick, Standard, Full, and the full check", [
    "Quick looks for leaked keys and passwords, committed .env files, and known vulnerabilities in your dependencies. It takes seconds. Use it before a commit or deploy.",
    "Standard runs every built-in check that applies to your project: sign-in, access control, routes and Tauri commands, injection, payments, config, AI code smells and supply chain. It also uses any installed scanners, and checks that the packages you depend on really exist on npm or PyPI (AI assistants sometimes invent names). It's the default for everyday use.",
    "Full is Standard plus a search of your git history for secrets that were committed and later deleted. That needs Gitleaks installed. Use it before a release, or weekly.",
    "The Everything free preset is Full followed by the local AI review: everything LadPock can do for free. Check all projects on the home page does that for every project, one after another.",
    "None of these run your code, install packages or execute build scripts.",
  ]],
  ["grades", "How grades work", [
    "Each category starts at 100. Open findings take points off: 40 for critical, 20 for high, 8 for medium and 2 for low. Findings LadPock is less sure about (low confidence) count half.",
    "A pile of small issues can't fail a category on its own. Only critical or high findings can take it below C-, and only medium ones below B.",
    "The overall grade is the average of the categories, limited by the worst finding that's still open: at most F (59) with a critical finding, C+ (79) with a high one, B+ (89) with a medium one and A (96) with a low one. A low-confidence finding limits it one step less, because it may not be a real problem. So A+ means nothing is open, and a leaked key can't hide behind tidy code.",
    "Roughly: A means no obvious problems found, B means a few things to tidy, C means real issues worth fixing soon, and D or F means something serious is open. A good grade isn't a guarantee: LadPock can't see your business logic, your dashboards or your production settings.",
    "Click a project's grade, or any category grade, to see exactly where the points went, the grade you'd reach after each round of fixes, a fix prompt for each step, and what would make the assessment itself more complete.",
  ]],
  ["options", "Scan options", [
    "The scan panel lets you choose exactly what runs and what leaves your computer, then press Scan. Presets set the toggles for you:",
    ["Everything free: a Full scan, live vulnerability data, installed scanners, git history and the local AI review.",
      "Offline: the same, but nothing leaves your computer. Vulnerability data comes from LadPock's last download.",
      "Quick: leaked secrets and vulnerable dependencies, in seconds.",
      "Deepest (paid): everything free plus the paid online AI review."],
    "The toggles:",
    ["Free online vulnerability data: your exact dependency versions checked against OSV.dev, CISA's actively-exploited list and EPSS, plus a check that your packages exist on npm and PyPI. Sends package names and versions, never code.",
      "Installed scanners: Gitleaks, OSV-Scanner and Opengrep, if installed. Free, and they run on this computer.",
      "Search git history: finds secrets that were committed and later deleted. Needs Gitleaks.",
      "Local AI review: a model on this computer reads your code for logic bugs. Free and private, but needs Ollama.",
      "Paid online AI review: Claude reads your code with secrets masked. Billed to your own Anthropic account, within a monthly budget you set.",
      "Live checks against your running app: LadPock calls your app on this computer (never anywhere else) without logging in, to confirm which endpoints really answer, and checks headers, cookies, CORS, exposed files like .env and .git, error pages and sign-in rate limits. Requests that change data are only sent if you also tick that option, so use a development database for it. For the most realistic results, run a production build locally. It also sends a few harmless probes: a marker to see if it comes back as raw HTML, a stray quote to see if it breaks a database query, and a made-up address in redirect parameters. With two test accounts it tries to open one account's records as the other, which only reads, and flags admin endpoints that answer ordinary accounts and private answers marked cacheable.",
      "Paid online scanners: commercial services with your own account. Not available yet."],
    "A greyed-out toggle says why it can't be used right now, for example a missing scanner or no API key. Your choices are remembered for each project.",
  ]],
  ["online-ai", "The paid online AI review", [
    "Claude, Anthropic's model, reviews your code the same way the local model does: routes and commands first, then a second opinion on serious findings, then the rest of the code. It also double-checks the local model's open leads. It's a stronger reviewer than most models that fit on a home computer.",
    "To set it up, open AI settings on a project page:",
    ["install Anthropic's Python SDK: python -m pip install anthropic",
      "allow sending code to Anthropic",
      "paste an API key from console.anthropic.com (it's stored in Windows Credential Manager, not in LadPock's files), or set ANTHROPIC_API_KEY",
      "set a monthly budget (5 dollars by default)"],
    "Then switch on Paid online AI review in the scan panel. Before anything is sent, LadPock shows how many parts it will send and roughly what it will cost.",
    "What's sent: the same parts of your code the local model reads, with secrets masked first. Nothing is sent for a project marked Never send this project online.",
    "Costs: billed by Anthropic to your account. LadPock records an estimate of every call and stops before a run would go over your monthly budget. Unchanged code isn't sent again, so later runs only pay for what changed.",
    "Results are leads, like the local review's: they never change the grade, and quoted code must exist in your project before you see a lead.",
  ]],
  ["severity", "Severity and confidence", [
    "Severity is how bad it would be if the problem is real. Critical means someone could take over accounts, data or money now. High means a serious hole. Medium means a weakness worth fixing. Low means hardening.",
    "Confidence is how sure LadPock is that it's real. High means the pattern is unambiguous, for example a live key in the code. Medium means it's probably real. Low means it's a heuristic that needs a human look, for example “this route doesn't seem to check ownership”.",
  ]],
  ["coverage", "Deep checks and generic checks", [
    "Some stacks have dedicated packs that understand how the framework works: Next.js, React, Supabase, Firebase and Stripe; SvelteKit, Remix, Nuxt and Astro; Express, Fastify, Hono, Koa and NestJS; FastAPI, Flask and Django; Spring, Go, Rails, Laravel and ASP.NET; tRPC, Convex, GraphQL and serverless functions; AI features; Tauri and Electron; Android, iOS, React Native and Flutter; and Docker, Kubernetes, Terraform and GitHub Actions.",
    "Go, PHP, Ruby, Java/Kotlin, C# and Rust get language-specific versions of the injection, crypto and config checks. Everything else gets the generic checks: secrets, dependencies, injection patterns, config and AI code smells.",
    "Each project page lists which stacks got deep checks, so you know how thorough a scan was.",
  ]],
  ["ai", "The local AI review", [
    "A model running on this computer through Ollama reads the parts of your project most likely to hide logic bugs. It starts with routes and Tauri commands (along with what the static checks found), then gives a second opinion on medium-and-above findings, then reads the rest of your code. Nothing is sent anywhere, and secrets are masked before the model sees anything.",
    "What it reports are leads, not findings. Before you see a lead it has to pass four filters:",
    ["it must quote a real line of code that exists in your project, and not a comment",
      "the model takes a second look and confirms the claim against the code",
      "it mustn't repeat something the scanner already reported",
      "it's capped at high severity"],
    "Leads never change your grade and can't hide a scanner finding. Confirm the real ones, which puts them in the fix prompt, and dismiss the rest. Dismissed leads stay dismissed. Even after filtering, expect some leads to be wrong, because the model can't see everything.",
    "The first review reads everything. Later reviews only re-read code that changed. Stopping is safe at any time; the next run continues from where it stopped.",
    "The nightly review is a Windows scheduled task for your account. It runs only when plugged in, at low priority, and stops at the time you choose.",
  ]],
  ["data", "Vulnerability data", [
    "Every time you open LadPock or run a scan, it refreshes three sources:",
    ["OSV.dev: known vulnerabilities for npm, PyPI, crates.io, Go and more, matched against the exact versions in your lockfiles.",
      "CISA KEV: the US government's list of vulnerabilities attackers are actively using. Anything on it is treated as critical.",
      "EPSS: the estimated chance a vulnerability will be exploited in the next 30 days."],
    "Dependency versions are read from npm, PyPI, Cargo, Go, Composer, RubyGems, NuGet, Maven/Gradle, pub (Flutter), Swift Package Manager and Hex lockfiles and manifests, without running any package manager.",
    "Because LadPock remembers each project's dependency list, it can tell you when a new vulnerability affects a project you haven't touched. That's the red banner on the home page.",
    "What's sent: package names and versions (to OSV.dev and the npm and PyPI registries) and CVE IDs (to EPSS). Never your code. There's no telemetry.",
  ]],
  ["scanners", "Optional scanners and how they're installed", [
    "Gitleaks (more secret patterns, plus git history in Full scans), OSV-Scanner (more lockfile types) and Opengrep (data-flow rules that follow user input to SQL, shell commands and outgoing requests) add coverage on top of LadPock's own checks.",
    "Installing from the Scanners page is safe by design:",
    ["the exact version and the SHA-256 of every file are built into LadPock, from releases at least two weeks old",
      "files come over HTTPS from each project's official GitHub release",
      "a download that doesn't match the pinned SHA-256 is deleted and nothing is installed, which defeats tampered or replaced releases",
      "only the expected program is taken from an archive, and it goes into LadPock's own folder, not your PATH"],
    "Versions only change when LadPock is updated, in a reviewed change. If you installed a scanner yourself, LadPock uses yours and leaves it alone.",
  ]],
  ["routes", "Routes and commands", [
    "The Routes tab lists every API route: Next.js handlers and server actions; SvelteKit, Remix, Nuxt and Astro endpoints and form actions; Express, Fastify, Hono and Koa routes; NestJS controllers; FastAPI, Flask and Django views; Spring, Go, Rails, Laravel and ASP.NET routes; and backends with no server of your own: tRPC procedures, Convex functions, GraphQL resolvers, Firebase and Supabase functions, and Vercel, Netlify, Cloudflare and AWS Lambda functions. For each one it shows whether the handler checks who's calling (Auth), whether it checks the record belongs to them (Owner), whether input is validated, and whether there's a rate limit.",
    "For Tauri, the Commands tab lists every command the app's web page can call. For each one it shows what input it takes from the page, whether it reads or writes files, whether it checks a path is inside an allowed folder, and whether it starts programs.",
    "Both are heuristic. Read “no” as “go and look”.",
  ]],
  ["accept", "Accepting a risk", [
    "If a finding is a deliberate choice, use Accept risk… on it. You give a reason and an expiry (90 days by default), and it's hidden from future scans until then.",
    "You can also add a `ladpock-ignore` comment on the line. Hidden findings are always counted on the results page, so you'll notice if anything (including an AI assistant) quietly hides one.",
  ]],
  ["human", "Needs a human", [
    "Some of the most important protections can't be seen in code: two-factor login on your accounts, tested backups, spending limits on paid APIs, and trying to open another user's data while logged in as someone else. The checklist reminds you to verify these, and remembers what you've ticked.",
  ]],
  ["limits", "What LadPock can't do", [
    "It finds common, recognisable mistakes. It doesn't understand your business rules, can't see settings in your hosting or database dashboards, and doesn't test the running app. Use it alongside the Needs a human checklist, and get a person to review anything handling payments or sensitive data before launch.",
  ]],
];

function renderHelp(section) {
  const blocks = HELP.map(([id, title, body]) => h("section", { id: `help-${id}`, class: "help-section" },
    h("h2", null, title),
    body.map((part) => Array.isArray(part) ? h("ul", null, part.map((li) => h("li", null, li))) : h("p", null, part))));
  $("#app").replaceChildren(h("div", { class: "stack help" },
    h("a", { href: "#/" }, "← Your projects"),
    h("h1", null, "Help"),
    h("nav", { class: "help-toc", "aria-label": "Help topics" }, HELP.map(([id, title]) => h("a", { href: `#/help/${id}` }, title))),
    blocks));
  const target = section && document.getElementById(`help-${section}`);
  if (target) target.scrollIntoView({ block: "start" });
  else window.scrollTo(0, 0);
}

// ---------- start ----------

// LadPock makes a new link each time it starts. Opening it in a tab that's already here only changes the hash, so nothing
// reloads by itself, and the page would carry on with the old token and the old code.
window.addEventListener("hashchange", () => {
  if (/token=/.test(location.hash)) {
    readToken();
    location.reload();
  }
});

state.token = readToken();
if (!state.token) showLocked();
else {
  window.addEventListener("hashchange", route);
  route();
  pollJobs();
}
