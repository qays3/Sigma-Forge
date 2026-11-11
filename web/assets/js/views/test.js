import { api } from "../api.js";
import { mappingOptions, mappings } from "../mappings.js";
import { trackState } from "../router.js";
import { state } from "../state.js";
import { $, $$, copyText, debounce, emptyState, esc, forging, icons, levelBadge, logo, openDrawer, plural, skeleton, toast } from "../ui.js";

const MODES = [
  ["auto", "Match log source when known", "Events with a known Windows channel only hit rules for that log source. Other events are tested against every rule."],
  ["strict", "Always match log source", "A rule only sees events whose product, service and category match its logsource."],
  ["off", "Ignore log source", "Every rule runs against every event. Good for logs with custom fields."],
];

let files = [];
let lastResult = null;

function size(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function pretty(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

export async function testView(root, route) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Test</div>
          <h1>Run your rules on real logs</h1>
          <p>Drop EVTX, JSON or JSON lines files. Sigma Forge loads them into SQLite and runs every rule to show which ones fire and on what.</p>
        </div>
      </div>
      <div class="grid grid--side test">
        <div class="test__side">
          <div class="card">
            <div class="card__body">
              <label class="dropzone" id="logDrop" for="logInput">
                ${logo(56, "dropzone__logo")}
                <span class="dropzone__title">Drop log files here</span>
                <span class="dropzone__text">.evtx, .json, .jsonl, .ndjson up to 64 MB</span>
                <input class="hidden-input" type="file" id="logInput" multiple accept=".evtx,.json,.jsonl,.ndjson,.log,.txt">
              </label>
              <div class="dropzone__actions">
                <button class="btn btn--sm" type="button" id="sampleLogs">${icons.spark} Load sample logs</button>
                <button class="btn btn--sm btn--ghost" type="button" id="clearLogs">${icons.trash} Clear</button>
              </div>
              <ul class="list test__files" id="logList"></ul>
            </div>
          </div>
          <div class="card mt-4">
            <div class="card__body">
              <label class="field">
                <span class="field__label">Log source matching</span>
                <select class="select" id="testMode">${MODES.map(([k, label]) => `<option value="${k}">${esc(label)}</option>`).join("")}</select>
                <span class="field__hint" id="modeHint"></span>
              </label>
              <label class="field">
                <span class="field__label">Field mapping</span>
                <select class="select" id="testMap"></select>
              </label>
              <div class="row">
                <button class="btn" type="button" id="testRules">${icons.file} Rules <span class="badge badge--accent" id="testRuleCount"></span></button>
                <div class="spacer"></div>
                <button class="btn btn--primary" type="button" id="runTest">${icons.play} Run test</button>
              </div>
            </div>
          </div>
        </div>
        <div id="testOut"></div>
      </div>
    </section>`;

  const rules = await state.rules();
  let selected = new Set(rules.map((r) => r.id));

  const out = $("#testOut", root);
  const modeSel = $("#testMode", root);
  modeSel.value = route.mode || "auto";
  const showHint = () => ($("#modeHint", root).textContent = MODES.find((m) => m[0] === modeSel.value)?.[2] || "");
  showHint();
  modeSel.addEventListener("change", () => {
    showHint();
    trackState({ mode: modeSel.value });
  });
  $("#testMap", root).innerHTML = mappingOptions(mappings.activeId());

  function paintFiles() {
    $("#logList", root).innerHTML = files
      .map((f, i) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(f.name)}</div><div class="list__meta">${esc(size(f.size))}</div></div><button class="icon-btn" type="button" data-drop="${i}" aria-label="Remove ${esc(f.name)}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg></button></li>`)
      .join("");
    $("#runTest", root).disabled = !files.length || !rules.length;
  }

  function paintCount() {
    $("#testRuleCount", root).textContent = `${selected.size} / ${rules.length}`;
  }

  function addFiles(list) {
    const incoming = Array.from(list || []);
    incoming.forEach((f) => {
      files = files.filter((x) => x.name !== f.name);
      files.push(f);
    });
    paintFiles();
  }

  const drop = $("#logDrop", root);
  ["dragenter", "dragover"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.add("is-over");
    })
  );
  ["dragleave", "drop"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.remove("is-over");
    })
  );
  drop.addEventListener("drop", (e) => addFiles(e.dataTransfer.files));
  $("#logInput", root).addEventListener("change", (e) => {
    addFiles(e.target.files);
    e.target.value = "";
  });
  $("#logList", root).addEventListener("click", (e) => {
    const btn = e.target.closest("[data-drop]");
    if (!btn) return;
    files.splice(Number(btn.dataset.drop), 1);
    paintFiles();
  });
  $("#clearLogs", root).addEventListener("click", () => {
    files = [];
    paintFiles();
  });
  $("#sampleLogs", root).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const { logs } = await api.sampleLogs();
      addFiles(logs.map((l) => new File([l.content], l.name, { type: "application/json" })));
      toast(`Loaded ${plural(logs.length, "sample log file")}`, "ok");
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });

  $("#testRules", root).addEventListener("click", () => {
    const body = `
      <div class="row">
        <input class="input toolbar__grow" type="search" id="trFilter" placeholder="Filter files" aria-label="Filter files">
        <button class="btn btn--sm" type="button" id="trAll">All</button>
        <button class="btn btn--sm" type="button" id="trNone">None</button>
      </div>
      <div id="trChecks" class="mt-4"></div>`;
    openDrawer("Rules to test", body, (panel) => {
      const draw = (f = "") => {
        $("#trChecks", panel).innerHTML = rules
          .filter((r) => !f || r.name.toLowerCase().includes(f.toLowerCase()))
          .map((r) => `<label class="check"><input type="checkbox" data-id="${esc(r.id)}" ${selected.has(r.id) ? "checked" : ""}> <span>${esc(r.name)}</span></label>`)
          .join("");
      };
      draw();
      panel.addEventListener("change", (e) => {
        const box = e.target.closest("[data-id]");
        if (!box) return;
        if (box.checked) selected.add(box.dataset.id);
        else selected.delete(box.dataset.id);
        paintCount();
      });
      $("#trFilter", panel).addEventListener("input", debounce((e) => draw(e.target.value), 120));
      $("#trAll", panel).addEventListener("click", () => {
        selected = new Set(rules.map((r) => r.id));
        draw($("#trFilter", panel).value);
        paintCount();
      });
      $("#trNone", panel).addEventListener("click", () => {
        selected = new Set();
        draw($("#trFilter", panel).value);
        paintCount();
      });
    });
  });

  function statusBadge(r) {
    if (r.status === "failed" || r.status === "error") return '<span class="badge badge--bad">error</span>';
    if (r.status === "skipped") return '<span class="badge">skipped</span>';
    if (r.hits) return `<span class="badge badge--ok">${esc(plural(r.hits, r.kind === "correlation" ? "alert" : "hit"))}</span>`;
    return '<span class="badge badge--warn">silent</span>';
  }

  function groupOf(r) {
    if (r.status === "failed" || r.status === "error") return "errors";
    if (r.status === "skipped") return "skipped";
    return r.hits ? "hits" : "silent";
  }

  function render(res) {
    const s = res.summary;
    const groups = { all: res.results.length, hits: 0, silent: 0, errors: 0, skipped: 0 };
    res.results.forEach((r) => (groups[groupOf(r)] += 1));
    const maxSource = Math.max(1, ...res.logsources.map((l) => l.events));
    out.innerHTML = `
      <div class="stats">
        <div class="stat"><div class="stat__label">Events</div><div class="stat__value stat__value--accent">${s.events}</div><div class="stat__hint">${esc(plural(s.files, "file"))} · ${esc(plural(res.fields, "field"))}</div></div>
        <div class="stat"><div class="stat__label">Rules that fired</div><div class="stat__value stat__value--ok">${s.matched_rules}</div><div class="stat__hint">of ${s.tested} tested</div></div>
        <div class="stat"><div class="stat__label">Events hit</div><div class="stat__value">${s.matched_events}</div><div class="stat__hint">${s.unmatched_events} with no hit</div></div>
        <div class="stat"><div class="stat__label">Errors</div><div class="stat__value ${s.errors ? "stat__value--bad" : ""}">${s.errors}</div><div class="stat__hint">ran in ${s.seconds}s</div></div>
      </div>
      <div class="card">
        <div class="card__head"><span class="card__title">Log sources found</span><span class="card__sub">mode ${esc(res.mode)}</span></div>
        <div class="card__body"><div class="bars">${res.logsources
          .map((l) => `<div class="bar"><span class="bar__label">${esc(l.name)}</span><span class="bar__track"><span class="bar__fill" data-width="${Math.round((l.events / maxSource) * 100)}"></span></span><span class="bar__value">${l.events}</span></div>`)
          .join("")}</div></div>
      </div>
      <div class="toolbar mt-4">
        <div class="tabs tabs--inline" id="testTabs">
          ${[["all", "All"], ["hits", "Fired"], ["silent", "Silent"], ["errors", "Errors"], ["skipped", "Skipped"]].map(([k, label]) => `<button class="tab ${k === "all" ? "is-active" : ""}" type="button" data-filter="${k}" ${groups[k] || k === "all" ? "" : "disabled"}>${label} <span class="tab__count">${groups[k]}</span></button>`).join("")}
        </div>
        <input class="input toolbar__grow" type="search" id="testFilter" placeholder="Filter rules" aria-label="Filter rules">
      </div>
      <div class="card">
        <ul class="list" id="testList">${res.results
          .map(
            (r, i) => `<li class="list__item test__row" data-group="${groupOf(r)}" data-title="${esc(r.title.toLowerCase())}">
              <div class="list__main">
                <div class="list__title">${esc(r.title)}</div>
                <div class="list__meta">${esc(r.key)}${r.logsource ? ` · ${esc(r.logsource)}` : ""}${r.message ? ` · ${esc(r.message)}` : ""}</div>
              </div>
              ${levelBadge(r.level)}
              ${statusBadge(r)}
              <button class="btn btn--sm" type="button" data-show="${i}">Details</button>
            </li>`
          )
          .join("")}</ul>
      </div>`;
    out.querySelectorAll(".bar__fill").forEach((el) => el.style.setProperty("width", `${el.dataset.width}%`));
    const applyFilter = () => {
      const tab = $("#testTabs .tab.is-active", out)?.dataset.filter || "all";
      const q = $("#testFilter", out).value.trim().toLowerCase();
      $$(".test__row", out).forEach((row) => {
        row.hidden = (tab !== "all" && row.dataset.group !== tab) || (q && !row.dataset.title.includes(q));
      });
    };
    $("#testTabs", out).addEventListener("click", (e) => {
      const tab = e.target.closest("[data-filter]");
      if (!tab || tab.disabled) return;
      $$("#testTabs .tab", out).forEach((t) => t.classList.toggle("is-active", t === tab));
      applyFilter();
    });
    $("#testFilter", out).addEventListener("input", debounce(applyFilter, 120));
  }

  function showDetails(r) {
    const samples = r.samples || [];
    const alerts = r.alerts || [];
    const body = `
      <dl class="meta">
        <dt>Status</dt><dd>${statusBadge(r)}</dd>
        <dt>File</dt><dd class="mono">${esc(r.key)}</dd>
        <dt>Log source</dt><dd>${esc(r.logsource || "not filtered")}</dd>
        ${r.kind === "correlation" ? `<dt>Events used</dt><dd>${r.events || 0}</dd>` : ""}
      </dl>
      ${r.message ? `<div class="card"><div class="notice notice--bad">${esc(r.message)}</div></div>` : ""}
      ${(r.warnings || []).length ? `<div class="card mt-4">${r.warnings.map((w) => `<div class="notice notice--warn">${esc(w)}</div>`).join("")}</div>` : ""}
      ${alerts.length ? `<h3 class="section-title">Alerts</h3>${alerts.map((a) => `<div class="card"><pre class="code">${esc(pretty(a))}</pre></div>`).join("")}` : ""}
      ${samples.length ? `<h3 class="section-title">Matching events${r.hits > samples.length ? ` (first ${samples.length} of ${r.events || r.hits})` : ""}</h3>${samples.map((s) => `<div class="card test__event"><div class="card__head"><span class="card__sub">${esc(s.source)} · ${esc([s.logsource.product, s.logsource.service, s.logsource.category].filter(Boolean).join(" / ") || "unknown source")}</span></div><pre class="code">${esc(pretty(s.event))}</pre></div>`).join("")}` : r.status === "ok" ? '<p class="muted">No event matched this rule.</p>' : ""}
      ${r.query ? `<h3 class="section-title">SQLite query</h3><div class="card"><pre class="code">${esc(r.query)}</pre><div class="row test__copy"><button class="btn btn--sm" type="button" id="copyQuery">${icons.copy} Copy query</button></div></div>` : ""}`;
    openDrawer(r.title, body, (panel) => {
      $("#copyQuery", panel)?.addEventListener("click", () => copyText(r.query, "Query copied"));
    });
  }

  out.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-show]");
    if (btn && lastResult) showDetails(lastResult.results[Number(btn.dataset.show)]);
  });

  async function run() {
    const chosen = rules.filter((r) => selected.has(r.id));
    if (!chosen.length) {
      toast("Select at least one rule", "bad");
      return;
    }
    if (!files.length) {
      toast("Add a log file first", "bad");
      return;
    }
    const btn = $("#runTest", root);
    btn.disabled = true;
    out.innerHTML = `${forging(`Testing ${plural(chosen.length, "rule")} on ${plural(files.length, "file")}`)}${skeleton.stats(4)}${skeleton.rows(8)}`;
    try {
      const profile = mappings.get($("#testMap", root).value);
      lastResult = await api.test(chosen, files, modeSel.value, profile?.map || {});
      render(lastResult);
    } catch (err) {
      out.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    } finally {
      btn.disabled = !files.length;
    }
  }

  $("#runTest", root).addEventListener("click", run);

  paintFiles();
  paintCount();
  if (!rules.length) {
    out.innerHTML = `<div class="card">${emptyState("No rules yet", "Add Sigma rules in the workspace, then come back to test them.", '<a class="btn btn--primary" href="/" data-link>Go to workspace</a>')}</div>`;
  } else if (lastResult) {
    render(lastResult);
  } else {
    out.innerHTML = `<div class="card">${emptyState("Add logs to start", "Drop EVTX or JSON files on the left, or load the sample logs, then press Run test.")}</div>`;
  }
  return null;
}
