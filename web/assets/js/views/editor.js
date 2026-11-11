import { api } from "../api.js";
import { mappings } from "../mappings.js";
import { trackState } from "../router.js";
import { state } from "../state.js";
import { store } from "../store.js";
import { $, $$, copyText, debounce, download, esc, forging, icons, levelBadge, openDrawer, plural, toast } from "../ui.js";

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

export async function editorView(root, route) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Editor</div>
          <h1>Write a rule and watch it convert</h1>
          <p>Checks, ATT&amp;CK mapping and the query for any platform update as you type.</p>
        </div>
      </div>
      <div class="editor">
        <div class="card editor__main">
          <div class="editor__bar">
            <input class="input editor__name" id="edName" aria-label="File name" spellcheck="false">
            <select class="select" id="edTemplate" aria-label="New from template">
              <option value="">New from template</option>
              ${Object.entries(TEMPLATES).map(([k, t]) => `<option value="${k}">${esc(t.label)}</option>`).join("")}
            </select>
            <button class="btn btn--sm" type="button" id="edOpen">${icons.folder} Open</button>
            <button class="btn btn--sm" type="button" id="edDownload">${icons.download} Download</button>
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
  const draft = readJson(DRAFT_KEY);
  const fromRoute = route.file ? rules.find((r) => r.name === route.file) : null;
  if (fromRoute) {
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

  function renderChecks(analysis) {
    const items = analysis?.rules || [];
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
          </div>
          ${r.error ? `<div class="notice notice--bad">${esc(r.error)}</div>` : ""}
          ${(r.issues || []).map((i) => `<div class="notice notice--warn">${severityBadge(i.severity)} <span>${esc(i.message)}</span></div>`).join("")}
          ${!r.error && !(r.issues || []).length ? '<div class="notice notice--ok">No findings</div>' : ""}
          ${r.logsource ? `<div class="editor__meta"><span>Log source</span><span class="mono">${esc([r.logsource.product, r.logsource.category, r.logsource.service].filter(Boolean).join(" / ") || "none")}</span></div>` : ""}
        </div>`
      )
      .join("");
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
    if (!text.value.trim()) {
      renderChecks(null);
      renderAttack(null);
      $("#edQueryOut", root).innerHTML = "";
      return;
    }
    try {
      const analysis = await api.analyze([current]);
      if (seq !== current.seq) return;
      renderChecks(analysis);
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
  });

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
        document.querySelector("#drawer [data-close]")?.click();
        paintGutter();
        refresh();
      });
    });
  });

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
  return {
    destroy() {
      saveDraft();
    },
  };
}
