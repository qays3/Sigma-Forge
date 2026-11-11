import { api } from "../api.js";
import { state } from "../state.js";
import { $, $$, copyText, debounce, download, emptyState, esc, forging, icons, levelBadge, openDrawer, plural, skeleton, toast } from "../ui.js";

const PREF_KEY = "sigma-forge-convert";
const EXT = { spl: "spl", spl2: "spl2", lucene: "txt", esql: "esql", eql: "eql", kql: "kql", xml: "xml", yaml: "yml", ppl: "ppl", logscale: "txt", s1ql: "txt", powerquery: "txt", xql: "xql", udm: "txt", cbc: "txt", aql: "aql", lpql: "txt", netwitness: "txt", json: "json", python: "py", tql: "txt", logql: "logql", quickwit: "txt", sql: "sql", surrealql: "surql" };
const FORMAT_EXT = { savedsearches: "conf", kibana_ndjson: "ndjson", siem_rule_ndjson: "ndjson", siem_rule: "json", dsl_lucene: "json", eqlapi: "json", dashboards_ndjson: "ndjson", monitor_rule: "json", module: "spl2", yara_l: "yaral", zircolite: "json", ruler: "yml", grafana_alerting: "json", sdyaml: "yml", pantherflow: "txt", python: "py", cse_rule: "json", clickdetect: "yml", json: "json", data_model: "spl" };

function loadPrefs() {
  try {
    return JSON.parse(localStorage.getItem(PREF_KEY)) || {};
  } catch {
    return {};
  }
}

function savePrefs(prefs) {
  try {
    localStorage.setItem(PREF_KEY, JSON.stringify(prefs));
  } catch {
    return;
  }
}

function fileExt(target, format) {
  return FORMAT_EXT[format] || EXT[target.language] || "txt";
}

export async function convertView(root, route) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Convert</div>
          <h1>Turn Sigma into queries</h1>
          <p>Pick one of 31 target platforms and Sigma Forge converts every rule into its query language.</p>
        </div>
      </div>
      <div id="controls">${skeleton.card(3)}</div>
      <div class="mt-5" id="output">${forging("Loading targets")}${skeleton.blocks(3)}</div>
    </section>`;

  let rules;
  let targets;
  try {
    [rules, targets] = await Promise.all([state.rules(), state.targets()]);
  } catch (err) {
    $("#controls", root).innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    $("#output", root).innerHTML = "";
    return null;
  }

  if (!rules.length) {
    $("#controls", root).innerHTML = "";
    $("#output", root).outerHTML = `<div class="card">${emptyState("No rules to convert", "Add Sigma rules in the workspace first.", '<a class="btn btn--primary" href="/" data-link>Go to workspace</a>')}</div>`;
    return null;
  }

  const prefs = loadPrefs();
  let targetId = route.target || prefs.target || "splunk";
  if (!targets.some((t) => t.id === targetId && t.available)) targetId = targets.find((t) => t.available)?.id;
  const preselect = route.file;
  let selected = new Set(preselect ? rules.filter((r) => r.name === preselect).map((r) => r.id) : rules.map((r) => r.id));
  let lastResult = null;

  const families = [...new Set(targets.map((t) => t.family))];
  $("#controls", root).innerHTML = `
    <div class="card convert-bar">
      <div class="convert-bar__targets" role="radiogroup" aria-label="Target">
        ${families
          .map(
            (fam) => `<div class="tgroup"><span class="tgroup__name">${esc(fam)}</span><div class="tgroup__items">${targets
              .filter((t) => t.family === fam)
              .map((t) => `<button class="pill" type="button" role="radio" data-target="${esc(t.id)}" title="${esc(t.available ? t.description : "Backend or pipeline not installed")}" ${t.available ? "" : "disabled"}>${esc(t.name)}</button>`)
              .join("")}</div></div>`
          )
          .join("")}
      </div>
      <div class="convert-bar__info" id="targetInfo"></div>
      <div class="convert-bar__row">
        <label class="inline-field">
          <span class="field__label">Format</span>
          <select class="select" id="formatSelect"></select>
        </label>
        <div class="convert-bar__wazuh" id="wazuhOptions" hidden>
          <label class="inline-field">
            <span class="field__label">First id</span>
            <input class="input input--sm" type="number" id="wazuhStart" min="1" max="999999" value="${esc(prefs.wazuhStart || 100100)}" title="Custom Wazuh rules should use 100000 and up">
          </label>
          <label class="check mb-0" title="Wazuh eventchannel fields keep escaped backslashes"><input type="checkbox" id="wazuhDouble" ${prefs.wazuhDouble === false ? "" : "checked"}> <span>Double backslashes</span></label>
          <label class="check mb-0" title="Add if_group sysmon or windows"><input type="checkbox" id="wazuhParent" ${prefs.wazuhParent === false ? "" : "checked"}> <span>Parent group</span></label>
        </div>
        <div class="spacer"></div>
        <button class="btn" type="button" id="pickRules">${icons.file} Rules <span class="badge badge--accent" id="selCount"></span></button>
        <button class="btn btn--primary" type="button" id="runConvert">${icons.play} Convert</button>
      </div>
    </div>`;

  const formatSelect = $("#formatSelect", root);
  const currentTarget = () => targets.find((t) => t.id === targetId);

  function renderTargets() {
    $$(".pill", root).forEach((b) => {
      const on = b.dataset.target === targetId;
      b.classList.toggle("is-active", on);
      b.setAttribute("aria-checked", String(on));
    });
    const t = currentTarget();
    const formats = Object.entries(t?.formats || {});
    const wanted = prefs.formats?.[targetId] || (t?.id === "splunk_cim" ? "data_model" : "default");
    formatSelect.innerHTML = formats.map(([k, label]) => `<option value="${esc(k)}" ${k === wanted ? "selected" : ""}>${esc(k)}: ${esc(label)}</option>`).join("");
    $("#wazuhOptions", root).hidden = targetId !== "wazuh";
    if (t) {
      const engine = t.backend === "sigma-forge-wazuh" ? "Sigma Forge backend" : `pySigma backend ${t.backend}`;
      const pipes = t.pipelines.length ? ` · pipelines ${t.pipelines.join(", ")}` : "";
      $("#targetInfo", root).innerHTML = `<span class="badge badge--accent">${esc(t.language)}</span><span class="convert-bar__desc">${esc(t.description)}</span><span class="convert-bar__meta">${esc(engine + pipes)}</span>`;
    }
  }

  function updateCount() {
    $("#selCount", root).textContent = `${selected.size} / ${rules.length}`;
    const drawerCount = document.getElementById("drawerSelCount");
    if (drawerCount) drawerCount.textContent = `${selected.size} of ${rules.length} selected`;
  }

  function renderChecks(filter = "") {
    const box = document.getElementById("ruleChecks");
    if (box) {
      const f = filter.toLowerCase();
      box.innerHTML = rules
        .filter((r) => !f || r.name.toLowerCase().includes(f))
        .map((r) => `<label class="check"><input type="checkbox" data-id="${esc(r.id)}" ${selected.has(r.id) ? "checked" : ""}> <span title="${esc(r.name)}">${esc(r.name)}</span></label>`)
        .join("");
    }
    updateCount();
  }

  function openRulePicker() {
    const body = `
      <div class="row">
        <input class="input toolbar__grow" type="search" id="ruleFilter" placeholder="Filter files" aria-label="Filter files">
        <button class="btn btn--sm" type="button" id="selAll">Select all</button>
        <button class="btn btn--sm" type="button" id="selNone">Select none</button>
      </div>
      <p class="muted" id="drawerSelCount"></p>
      <div id="ruleChecks"></div>
      <div class="row mt-4"><button class="btn btn--primary" type="button" id="pickDone">${icons.play} Convert selected</button></div>`;
    openDrawer("Choose rules", body, (panel) => {
      renderChecks();
      $("#ruleChecks", panel).addEventListener("change", (e) => {
        const box = e.target.closest("[data-id]");
        if (!box) return;
        if (box.checked) selected.add(box.dataset.id);
        else selected.delete(box.dataset.id);
        updateCount();
      });
      $("#ruleFilter", panel).addEventListener("input", debounce((e) => renderChecks(e.target.value), 120));
      $("#selAll", panel).addEventListener("click", () => {
        selected = new Set(rules.map((r) => r.id));
        renderChecks($("#ruleFilter", panel).value);
      });
      $("#selNone", panel).addEventListener("click", () => {
        selected = new Set();
        renderChecks($("#ruleFilter", panel).value);
      });
      $("#pickDone", panel).addEventListener("click", () => {
        document.querySelector("#drawer [data-close]")?.click();
        run();
      });
    });
  }

  function persist() {
    prefs.target = targetId;
    prefs.formats = { ...(prefs.formats || {}), [targetId]: formatSelect.value };
    prefs.wazuhStart = Number($("#wazuhStart", root).value) || 100100;
    prefs.wazuhDouble = $("#wazuhDouble", root).checked;
    prefs.wazuhParent = $("#wazuhParent", root).checked;
    savePrefs(prefs);
  }

  root.addEventListener("click", (e) => {
    const t = e.target.closest("[data-target]");
    if (t && !t.disabled) {
      targetId = t.dataset.target;
      renderTargets();
      persist();
      run();
    }
  });
  formatSelect.addEventListener("change", () => {
    persist();
    run();
  });
  $("#pickRules", root).addEventListener("click", openRulePicker);

  function renderResult(result) {
    const t = currentTarget();
    const ext = fileExt(t, result.format);
    const s = result.summary;
    const cards = result.results
      .map((r, i) => {
        const body = r.queries.length ? r.queries.map((q) => `<pre class="code">${esc(q)}</pre>`).join("") : "";
        const warn = (r.warnings || []).map((w) => `<div class="notice notice--warn">${esc(w)}</div>`).join("");
        const err = r.error ? `<div class="notice notice--bad">${esc(r.error)}</div>` : "";
        return `<article class="card result">
          <div class="result__head">
            <div class="result__title" title="${esc(r.title)}">${esc(r.title)}<div class="result__file">${esc(r.key)}</div></div>
            ${levelBadge(r.level)}
            ${r.kind === "correlation" ? '<span class="badge badge--accent">correlation</span>' : ""}
            ${r.error ? '<span class="badge badge--bad">failed</span>' : r.queries.length ? '<span class="badge badge--ok">ok</span>' : '<span class="badge badge--warn">skipped</span>'}
            ${r.queries.length ? `<button class="btn btn--sm" type="button" data-copy="${i}">${icons.copy} Copy</button>` : ""}
          </div>
          ${body}${err}${warn}
        </article>`;
      })
      .join("");
    $("#output", root).innerHTML = `
      <div class="stats">
        <div class="stat"><div class="stat__label">Target</div><div class="stat__value stat__value--accent stat__value--sm">${esc(result.target.name)}</div><div class="stat__hint">format ${esc(result.format)}</div></div>
        <div class="stat"><div class="stat__label">Converted</div><div class="stat__value stat__value--ok">${s.converted}</div><div class="stat__hint">of ${plural(s.total, "rule")}</div></div>
        <div class="stat"><div class="stat__label">Skipped</div><div class="stat__value ${s.skipped ? "stat__value--warn" : ""}">${s.skipped || 0}</div><div class="stat__hint">used by correlations</div></div>
        <div class="stat"><div class="stat__label">Failed</div><div class="stat__value ${s.failed ? "stat__value--bad" : ""}">${s.failed}</div><div class="stat__hint">see the reasons below</div></div>
      </div>
      ${(result.notes || []).length ? `<div class="card result">${result.notes.map((n) => `<div class="notice notice--info">${esc(n)}</div>`).join("")}</div>` : ""}
      <div class="toolbar">
        <div class="toolbar__grow muted">${result.bundle_error ? `Bundle failed: ${esc(result.bundle_error)}` : "Each card shows one Sigma rule. The bundle holds every converted rule in one file."}</div>
        <button class="btn btn--sm" type="button" id="copyBundle" ${result.bundle ? "" : "disabled"}>${icons.copy} Copy bundle</button>
        <button class="btn btn--sm btn--primary" type="button" id="dlBundle" ${result.bundle ? "" : "disabled"}>${icons.download} Download .${esc(ext)}</button>
      </div>
      ${cards}`;
    $("#copyBundle", root)?.addEventListener("click", () => copyText(result.bundle, "Bundle copied"));
    $("#dlBundle", root)?.addEventListener("click", () => download(`sigma-forge_${result.target.id}.${ext}`, result.bundle));
  }

  $("#output", root).addEventListener("click", (e) => {
    const btn = e.target.closest("[data-copy]");
    if (!btn || !lastResult) return;
    copyText(lastResult.results[Number(btn.dataset.copy)].queries.join("\n\n"));
  });

  async function run() {
    const chosen = rules.filter((r) => selected.has(r.id));
    if (!chosen.length) {
      toast("Select at least one rule", "bad");
      return;
    }
    persist();
    const btn = $("#runConvert", root);
    btn.disabled = true;
    $("#output", root).innerHTML = `${forging(`Forging ${plural(chosen.length, "file")} into ${currentTarget()?.name || "queries"}`)}${skeleton.stats(3)}${skeleton.blocks(3)}`;
    try {
      const options = {
        wazuh_rule_id_start: Number($("#wazuhStart", root).value) || 100100,
        wazuh_double_backslash: $("#wazuhDouble", root).checked,
        wazuh_parent_group: $("#wazuhParent", root).checked,
      };
      lastResult = await api.convert(chosen, targetId, formatSelect.value, options);
      renderResult(lastResult);
    } catch (err) {
      $("#output", root).innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    } finally {
      btn.disabled = false;
    }
  }

  $("#runConvert", root).addEventListener("click", run);
  renderTargets();
  renderChecks();
  run();
  return null;
}
