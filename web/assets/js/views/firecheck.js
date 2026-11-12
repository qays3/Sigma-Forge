import { api } from "../api.js";
import { mappingOptions, mappings } from "../mappings.js";
import { fileChips, readJson, writeJson } from "../shared.js";
import { state } from "../state.js";
import { $, $$, copyText, emptyState, esc, forging, icons, levelBadge, logo, openDrawer, plural, toast } from "../ui.js";

const KEY = "sigma-forge-firecheck";
const CONVERT_KEY = "sigma-forge-convert";
const VERDICT = {
  fires: ["Fires", "ok", "The converted query found every event the Sigma rule matched."],
  partial: ["Partly", "warn", "The query found some of the events the Sigma rule matched."],
  silent: ["Silent", "bad", "The Sigma rule matched these events, but the converted query found nothing on the platform."],
  hidden: ["Hidden", "warn", "Wazuh picked another rule for the same events."],
  extra: ["Extra hits", "warn", "The query fired on events the Sigma rule did not match."],
  error: ["Error", "bad", "The platform rejected the query or it could not be converted."],
  untested: ["No events", "", "None of the replayed events should fire this rule."],
  hits: ["Hits", "ok", "The query found events in your live data."],
  no_data: ["Nothing", "", "The query found nothing in the time range."],
  skipped: ["Skipped", "", "Used only inside a correlation rule, so it has no query of its own."],
};
const PLATFORM_TARGETS = {
  splunk: [["splunk", "Splunk SPL"], ["splunk_cim", "Splunk CIM"]],
  elastic: [["elastic_lucene", "Lucene (Kibana)"], ["elastic_esql", "ES|QL"], ["elastic_eql", "EQL"]],
  opensearch: [["opensearch_lucene", "Lucene"]],
  wazuh: [["wazuh", "Wazuh rules"]],
};
let files = [];
let last = null;

function connFields(p, s) {
  const v = (k, d = "") => esc(s[k] ?? d);
  const tls = `<label class="check mb-0"><input type="checkbox" data-k="verify_tls" ${s.verify_tls === false ? "" : "checked"}> Check the TLS certificate</label>`;
  if (p === "splunk") {
    return `
      <div class="fc__grid">
        <label class="field"><span class="field__label">REST API URL</span><input class="input mono" data-k="url" value="${v("url")}" placeholder="https://splunk.lab:8089"></label>
        <label class="field"><span class="field__label">Index</span><input class="input mono" data-k="index" value="${v("index", "main")}"></label>
        <label class="field"><span class="field__label">User</span><input class="input" data-k="username" value="${v("username")}" autocomplete="off"></label>
        <label class="field"><span class="field__label">Password or token</span><input class="input" data-k="password" type="password" autocomplete="off" data-secret></label>
        <label class="field" data-replay><span class="field__label">HEC URL</span><input class="input mono" data-k="hec_url" value="${v("hec_url")}" placeholder="https://splunk.lab:8088"></label>
        <label class="field" data-replay><span class="field__label">HEC token</span><input class="input mono" data-k="hec_token" type="password" autocomplete="off" data-secret></label>
        <label class="field"><span class="field__label">Windows source in your Splunk</span><select class="select" data-k="splunk_windows_source">
          <option value="" ${!s.splunk_windows_source ? "selected" : ""}>WinEventLog (pySigma default)</option>
          <option value="xml" ${s.splunk_windows_source === "xml" ? "selected" : ""}>XmlWinEventLog</option>
          <option value="none" ${s.splunk_windows_source === "none" ? "selected" : ""}>Do not filter on source</option>
        </select></label>
        <label class="field" data-replay><span class="field__label">Sourcetype for JSON logs</span><input class="input mono" data-k="sourcetype" value="${v("sourcetype", "_json")}"></label>
      </div>
      <div class="row">${tls}<label class="check mb-0" data-replay title="Send .evtx records as XML, the way the Splunk add on for Windows does"><input type="checkbox" data-k="windows_xml" ${s.windows_xml === false ? "" : "checked"}> Send EVTX as XmlWinEventLog</label></div>`;
  }
  if (p === "elastic" || p === "opensearch") {
    return `
      <div class="fc__grid">
        <label class="field"><span class="field__label">URL</span><input class="input mono" data-k="url" value="${v("url")}" placeholder="https://elastic.lab:9200"></label>
        <label class="field"><span class="field__label">API key, or leave empty</span><input class="input mono" data-k="token" type="password" autocomplete="off" data-secret></label>
        <label class="field"><span class="field__label">User</span><input class="input" data-k="username" value="${v("username")}" autocomplete="off"></label>
        <label class="field"><span class="field__label">Password</span><input class="input" data-k="password" type="password" autocomplete="off" data-secret></label>
        <label class="field" data-replay><span class="field__label">Index for replayed events</span><input class="input mono" data-k="index" value="${v("index", "sigma-forge-firecheck")}"></label>
        <label class="field" data-replay><span class="field__label">Ingest pipeline (optional)</span><input class="input mono" data-k="pipeline" value="${v("pipeline")}" placeholder="the pipeline your agents use"></label>
        <label class="field" data-live><span class="field__label">Indices with your live data</span><input class="input mono" data-k="live_index" value="${v("live_index", "logs-*,winlogbeat-*")}"></label>
      </div>
      <div class="row">${tls}</div>`;
  }
  return `
    <div class="fc__grid">
      <label class="field"><span class="field__label">API URL</span><input class="input mono" data-k="url" value="${v("url")}" placeholder="https://wazuh.lab:55000"></label>
      <label class="field"><span class="field__label">API user</span><input class="input" data-k="username" value="${v("username", "wazuh")}" autocomplete="off"></label>
      <label class="field"><span class="field__label">API password</span><input class="input" data-k="password" type="password" autocomplete="off" data-secret></label>
      <label class="field"><span class="field__label">Windows log format</span><input class="input mono" data-k="log_format" value="${v("log_format", "eventchannel")}"></label>
    </div>
    <div class="row">${tls}</div>
    <p class="muted">Deploy the Wazuh rules to the manager first (Convert, Deploy). Events go through logtest, so nothing lands in your alerts.</p>`;
}

export async function fireCheckView(root) {
  const prefs = readJson(KEY, { platform: "splunk", mode: "replay", settings: {} });
  let platform = prefs.platform || "splunk";
  let mode = prefs.mode || "replay";
  const all = prefs.settings || {};
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Fire check</div>
          <h1>Prove your rules fire on the real platform</h1>
          <p>A rule can convert cleanly and still match nothing because the platform names fields differently. Fire check replays your logs into the platform, runs every converted query there, and compares the hits with what the Sigma rule matched. Silent rules come with the missing fields and the fix.</p>
        </div>
      </div>
      <div class="card setup fc__setup">
        <div class="setup__main">
          <div class="field__label">1. Platform</div>
          <div class="seg" id="fcPlat">${Object.entries({ splunk: "Splunk", elastic: "Elasticsearch", opensearch: "OpenSearch", wazuh: "Wazuh" }).map(([k, l]) => `<button class="seg__btn ${k === platform ? "is-active" : ""}" type="button" data-p="${k}">${l}</button>`).join("")}</div>
          <div id="fcConn" class="mt-4"></div>
          <div class="field__label mt-4">2. Events</div>
          <div class="seg" id="fcMode"><button class="seg__btn" type="button" data-m="replay">Replay my logs</button><button class="seg__btn" type="button" data-m="live">Live data already there</button></div>
          <div id="fcReplay" class="mt-4">
            <label class="dropzone dropzone--row" for="fcInput">
              ${logo(40, "dropzone__logo")}
              <span class="dropzone__body"><span class="dropzone__title">Drop logs that look like production</span><span class="dropzone__text">.evtx, .json, .jsonl or a .zip, up to 64 MB. They are sent to the platform with a run tag.</span></span>
              <input class="hidden-input" type="file" id="fcInput" multiple accept=".evtx,.json,.jsonl,.ndjson,.zip">
            </label>
            <div class="setup__actions"><label class="check mb-0"><input type="checkbox" id="fcSample"> Add the sample attack chain logs</label></div>
            <ul class="filechips" id="fcFiles"></ul>
          </div>
          <div id="fcLive" class="mt-4" hidden>
            <label class="inline-field"><span class="field__label">Look back</span><select class="select" id="fcHours">${[[1, "1 hour"], [24, "24 hours"], [168, "7 days"], [720, "30 days"]].map(([h, l]) => `<option value="${h}" ${h === (prefs.hours || 24) ? "selected" : ""}>${l}</option>`).join("")}</select></label>
            <p class="muted">Runs every converted query on the data already in the platform and checks every field exists. Nothing is sent.</p>
          </div>
        </div>
        <div class="setup__side">
          <label class="field"><span class="field__label">Query language</span><select class="select" id="fcTarget"></select></label>
          <label class="field"><span class="field__label">Field mapping</span><select class="select" id="fcMap">${mappingOptions(mappings.activeId())}</select></label>
          <div class="fc__how">
            <div class="field__label">What you get</div>
            <ol>
              <li>Each rule: fires, partly, silent or error.</li>
              <li>For silent rules: fields the platform does not have and where the value really is.</li>
              <li>A fix for the rules (mapping profile) or for the platform (field aliases).</li>
            </ol>
          </div>
          <div class="setup__run">
            <button class="btn" type="button" id="fcRules">${icons.file} Rules <span class="badge badge--accent" id="fcCount"></span></button>
            <button class="btn btn--primary" type="button" id="fcRun">${icons.play} Run fire check</button>
          </div>
        </div>
      </div>
      <div id="fcOut" class="mt-5"></div>
    </section>`;

  const rules = await state.rules();
  let selected = new Set(rules.map((r) => r.id));
  const out = $("#fcOut", root);
  $("#fcCount", root).textContent = `${selected.size} / ${rules.length}`;

  const readConn = () => {
    const s = {};
    $$("#fcConn [data-k]", root).forEach((el) => {
      s[el.dataset.k] = el.type === "checkbox" ? el.checked : el.value.trim();
    });
    return s;
  };
  const save = () => {
    const s = readConn();
    const keep = {};
    Object.entries(s).forEach(([k, v]) => {
      if (!["password", "token", "hec_token"].includes(k)) keep[k] = v;
    });
    all[platform] = keep;
    writeJson(KEY, { platform, mode, hours: Number($("#fcHours", root).value), settings: all, target: { ...(prefs.target || {}), [platform]: $("#fcTarget", root).value } });
  };
  const paint = () => {
    $$("#fcPlat [data-p]", root).forEach((b) => b.classList.toggle("is-active", b.dataset.p === platform));
    if (platform === "wazuh") mode = "replay";
    $$("#fcMode [data-m]", root).forEach((b) => {
      b.classList.toggle("is-active", b.dataset.m === mode);
      b.disabled = platform === "wazuh" && b.dataset.m === "live";
    });
    $("#fcConn", root).innerHTML = connFields(platform, all[platform] || {});
    $$("#fcConn [data-replay]", root).forEach((el) => (el.hidden = mode !== "replay"));
    $$("#fcConn [data-live]", root).forEach((el) => (el.hidden = mode !== "live"));
    $("#fcReplay", root).hidden = mode !== "replay";
    $("#fcLive", root).hidden = mode !== "live";
    const want = (prefs.target || {})[platform];
    $("#fcTarget", root).innerHTML = PLATFORM_TARGETS[platform].map(([k, l]) => `<option value="${k}" ${k === want ? "selected" : ""}>${esc(l)}</option>`).join("");
  };
  paint();
  $("#fcPlat", root).addEventListener("click", (e) => {
    const b = e.target.closest("[data-p]");
    if (!b) return;
    save();
    platform = b.dataset.p;
    paint();
  });
  $("#fcMode", root).addEventListener("click", (e) => {
    const b = e.target.closest("[data-m]");
    if (!b || b.disabled) return;
    save();
    mode = b.dataset.m;
    paint();
  });
  const addFiles = (list) => {
    Array.from(list || []).forEach((f) => {
      files = files.filter((x) => x.name !== f.name);
      files.push(f);
    });
    $("#fcFiles", root).innerHTML = fileChips(files);
  };
  addFiles([]);
  $("#fcInput", root).addEventListener("change", (e) => addFiles(e.target.files));
  const zone = $("#fcReplay .dropzone", root);
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("is-over");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("is-over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("is-over");
    addFiles(e.dataTransfer.files);
  });
  $("#fcFiles", root).addEventListener("click", (e) => {
    const b = e.target.closest("[data-drop]");
    if (!b) return;
    files.splice(Number(b.dataset.drop), 1);
    addFiles([]);
  });
  $("#fcRules", root).addEventListener("click", () => {
    openDrawer("Rules to check", `<div class="row"><button class="btn btn--sm" type="button" id="frAll">All</button><button class="btn btn--sm" type="button" id="frNone">None</button><input class="input toolbar__grow" type="search" id="frQ" placeholder="Filter"></div><div class="case__pick mt-4" id="frList">${rules.map((r) => `<label class="check" data-t="${esc(r.name.toLowerCase())}"><input type="checkbox" data-rid="${esc(r.id)}" ${selected.has(r.id) ? "checked" : ""}> <span class="mono">${esc(r.name)}</span></label>`).join("")}</div>`, (panel) => {
      const sync = () => ($("#fcCount", root).textContent = `${selected.size} / ${rules.length}`);
      panel.addEventListener("change", (e) => {
        const b = e.target.closest("[data-rid]");
        if (!b) return;
        if (b.checked) selected.add(b.dataset.rid);
        else selected.delete(b.dataset.rid);
        sync();
      });
      $("#frAll", panel).addEventListener("click", () => {
        selected = new Set(rules.map((r) => r.id));
        $$("[data-rid]", panel).forEach((b) => (b.checked = true));
        sync();
      });
      $("#frNone", panel).addEventListener("click", () => {
        selected = new Set();
        $$("[data-rid]", panel).forEach((b) => (b.checked = false));
        sync();
      });
      $("#frQ", panel).addEventListener("input", (e) => {
        const q = e.target.value.trim().toLowerCase();
        $$("[data-t]", panel).forEach((l) => (l.hidden = q && !l.dataset.t.includes(q)));
      });
    });
  });

  const run = async (override = {}) => {
    const chosen = rules.filter((r) => selected.has(r.id));
    if (!chosen.length) {
      toast("Pick at least one rule", "bad");
      return;
    }
    const sample = $("#fcSample", root).checked;
    if (mode === "replay" && !files.length && !sample) {
      toast("Add log files, or tick the sample logs", "bad");
      return;
    }
    save();
    const settings = { ...readConn(), ...(override.settings || {}) };
    const map = override.mapping || mappings.get($("#fcMap", root).value)?.map || {};
    $("#fcRun", root).disabled = true;
    out.innerHTML = `<div class="card"><div class="card__body">${forging("Starting the fire check")}<div class="fc__progress"><div class="fc__stage" id="fcStage">Starting</div><div class="meter"><span class="meter__fill" id="fcBar"></span></div></div></div></div>`;
    try {
      const { id } = await api.fire.start(chosen, { platform, target: $("#fcTarget", root).value, mode, hours: $("#fcHours", root).value, settings, field_mapping: map, sample: sample ? "1" : "" }, mode === "replay" ? files : []);
      for (;;) {
        await new Promise((r) => setTimeout(r, 1200));
        const s = await api.fire.status(id);
        if (!document.body.contains(out)) return;
        if (s.status === "running") {
          $("#fcStage", root).textContent = s.total ? `${s.stage}: ${s.done} of ${s.total}` : s.stage;
          $("#fcBar", root).style.setProperty("width", `${s.total ? Math.round((s.done * 100) / s.total) : 8}%`);
          continue;
        }
        if (s.status === "error") throw new Error(s.error);
        last = { res: s.result, settings, map };
        render();
        break;
      }
    } catch (err) {
      out.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    } finally {
      $("#fcRun", root).disabled = false;
    }
  };
  $("#fcRun", root).addEventListener("click", () => run());

  function render() {
    const res = last.res;
    const c = res.counts || {};
    const silent = (c.silent || 0) + (c.partial || 0);
    const isTested = (r) => (r.expected || 0) > 0 || ["error", "extra"].includes(r.verdict);
    const tested = res.results.filter(isTested).length;
    const fixes = [];
    if (res.source_fix) fixes.push(`<div class="fc__fix"><div><div class="list__title">The converted queries filter on the wrong Windows source</div><div class="muted">Your data uses ${res.source_fix === "xml" ? "XmlWinEventLog" : "another source"}, the Splunk pipeline asks for WinEventLog.</div></div><button class="btn btn--sm btn--primary" type="button" data-fix="source">Use ${res.source_fix === "xml" ? "XmlWinEventLog" : "no source filter"} and run again</button></div>`);
    if (Object.keys(res.mapping || {}).length) fixes.push(`<div class="fc__fix"><div><div class="list__title">Fix the rules: a field mapping</div><div class="muted">${esc(Object.entries(res.mapping).slice(0, 4).map(([a, b]) => `${a} to ${b}`).join(", "))}${Object.keys(res.mapping).length > 4 ? "..." : ""}</div></div><button class="btn btn--sm btn--primary" type="button" data-fix="mapping">Save mapping and run again</button></div>`);
    if (res.alias_config) fixes.push(`<div class="fc__fix fc__fix--code"><div><div class="list__title">Or fix the platform: ${res.platform === "splunk" ? "field aliases in props.conf" : "field aliases in the index mapping"}</div><div class="muted">${res.platform === "splunk" ? "Add these to props.conf of your add on, then run again." : "PUT this to <index>/_mapping, then run again."}</div></div><button class="btn btn--sm" type="button" data-fix="alias">${icons.copy} Copy</button></div><pre class="code">${esc(res.alias_config)}</pre>`);
    out.innerHTML = `
      <div class="stats">
        <div class="stat"><div class="stat__label">Fire score</div><div class="stat__value ${res.score === 100 ? "stat__value--ok" : res.score === null ? "" : "stat__value--warn"}">${res.score === null ? "none" : `${res.score}%`}</div><div class="stat__hint">${res.mode === "replay" ? `${res.fired} of ${res.should_fire} rules that should fire` : "live data"}</div></div>
        <div class="stat"><div class="stat__label">Silent</div><div class="stat__value ${silent ? "stat__value--bad" : "stat__value--ok"}">${silent}</div><div class="stat__hint">${c.error || 0} errors</div></div>
        <div class="stat"><div class="stat__label">Events</div><div class="stat__value stat__value--accent">${res.events || 0}</div><div class="stat__hint">${res.indexed != null ? `${res.indexed} searchable` : esc(res.platform_name)}</div></div>
        <div class="stat"><div class="stat__label">Fields seen</div><div class="stat__value">${res.fields_seen}</div><div class="stat__hint">on ${esc(res.platform_name)}</div></div>
      </div>
      ${fixes.length ? `<div class="card"><div class="card__head"><span class="card__title">How to fix the silent rules</span></div><div class="card__body fc__fixes">${fixes.join("")}</div></div>` : silent ? "" : res.mode === "replay" && res.should_fire ? '<div class="card"><div class="notice notice--ok">Every rule that should fire on these logs fires on the platform.</div></div>' : ""}
      <div class="toolbar mt-4"><div class="tabs tabs--inline" id="fcTabs">${(res.mode === "replay" ? ["tested"] : []).concat(["silent", "partial", "error", "hidden", "extra", "fires", "hits", "untested", "no_data", "skipped", "all"]).filter((k) => k === "all" || k === "tested" || c[k]).map((k, i) => `<button class="tab ${i === 0 ? "is-active" : ""}" type="button" data-f="${k}">${k === "all" ? "All" : k === "tested" ? "Should fire" : VERDICT[k][0]} <span class="tab__count">${k === "all" ? res.results.length : k === "tested" ? tested : c[k]}</span></button>`).join("")}</div></div>
      <div class="card"><ul class="list" id="fcList">${res.results
        .map((r, i) => `<li class="list__item" data-v="${r.verdict}" data-t="${isTested(r) ? "1" : ""}" ${res.mode === "replay" && !isTested(r) ? "hidden" : ""}><div class="list__main"><div class="list__title">${esc(r.title)}</div><div class="list__meta">${r.expected != null ? `should hit ${r.expected} · ` : ""}${r.got != null ? `platform found ${r.got}` : esc(r.error.slice(0, 120))}${r.diagnosis?.missing?.length ? ` · missing ${esc(r.diagnosis.missing.slice(0, 3).join(", "))}` : ""}${r.note ? ` · ${esc(r.note)}` : ""}</div></div>${levelBadge(r.level)}<span class="badge badge--${VERDICT[r.verdict][1]}">${esc(VERDICT[r.verdict][0])}</span><button class="btn btn--sm" type="button" data-show="${i}">Details</button></li>`)
        .join("")}</ul></div>`;
    $("#fcTabs", out).addEventListener("click", (e) => {
      const t = e.target.closest("[data-f]");
      if (!t) return;
      $$("#fcTabs .tab", out).forEach((x) => x.classList.toggle("is-active", x === t));
      const f = t.dataset.f;
      $$("#fcList [data-v]", out).forEach((li) => (li.hidden = f === "tested" ? !li.dataset.t : f !== "all" && li.dataset.v !== f));
    });
    out.onclick = async (e) => {
      const show = e.target.closest("[data-show]");
      if (show) {
        details(res.results[Number(show.dataset.show)]);
        return;
      }
      const fix = e.target.closest("[data-fix]")?.dataset.fix;
      if (fix === "alias") copyText(res.alias_config, "Copied");
      if (fix === "source") {
        const conv = readJson(CONVERT_KEY, {}) || {};
        writeJson(CONVERT_KEY, { ...conv, splunkSource: res.source_fix });
        const sel = $("#fcConn [data-k=splunk_windows_source]", root);
        if (sel) sel.value = res.source_fix;
        toast("Saved for Convert, Export and Deploy too", "ok");
        run({ settings: { splunk_windows_source: res.source_fix }, mapping: last.map });
      }
      if (fix === "mapping") {
        const merged = { ...last.map, ...res.mapping };
        const saved = mappings.save({ name: `Fire check ${res.platform_name}`, map: merged });
        mappings.setActive(saved.id);
        $("#fcMap", root).innerHTML = mappingOptions(saved.id);
        toast(`Saved ${saved.name} and turned it on`, "ok");
        run({ mapping: merged });
      }
    };
  }

  function details(r) {
    const d = r.diagnosis;
    const [label, cls, text] = VERDICT[r.verdict];
    openDrawer(r.title, `
      <div class="row"><span class="badge badge--${cls}">${esc(label)}</span><span class="muted">${esc(text)}</span></div>
      <dl class="meta mt-4">
        ${r.expected != null ? `<dt>Sigma matched</dt><dd>${esc(plural(r.expected, "event"))}</dd>` : ""}
        <dt>Platform found</dt><dd>${r.got != null ? r.got : "no answer"}</dd>
        ${r.wazuh_ids ? `<dt>Wazuh rule ids</dt><dd class="mono">${esc(r.wazuh_ids.join(", ") || "none")}</dd>` : ""}
      </dl>
      ${r.error ? `<div class="notice notice--bad mt-4">${esc(r.error)}</div>` : ""}
      ${r.note ? `<div class="notice notice--warn mt-4">${esc(r.note)}</div>` : ""}
      ${d ? `
        ${d.missing.length ? `<h3 class="section-title">Fields the platform does not have</h3><div class="chips">${d.missing.map((f) => `<span class="chip chip--bad mono">${esc(f)}</span>`).join("")}</div>` : ""}
        ${d.case.length ? `<h3 class="section-title">Wrong letter case</h3><ul class="list">${d.case.map((x) => `<li class="list__item"><div class="list__main mono">${esc(x.field)} is ${esc(x.seen)} on the platform</div></li>`).join("")}</ul>` : ""}
        ${d.values.length ? `<h3 class="section-title">Values that never show up</h3><ul class="list">${d.values.map((x) => `<li class="list__item"><div class="list__main"><div class="list__title mono">${esc(x.field)} = ${esc(x.want)}</div><div class="list__meta">The platform has ${esc(x.seen.join(", "))}</div></div></li>`).join("")}</ul>` : ""}
        ${d.hints.length ? `<h3 class="section-title">Where the values really are</h3><div class="card card__body--flush table-wrap"><table class="table table--compact fc__hints"><thead><tr><th>Sigma field</th><th>Query uses</th><th>Value found in</th></tr></thead><tbody>${d.hints.map((h) => `<tr><td class="mono">${esc(h.sigma_field)}</td><td class="mono">${esc(h.query_field || "")} ${h.ok ? '<span class="badge badge--ok">ok</span>' : '<span class="badge badge--bad">missing</span>'}</td><td class="mono">${h.fields.length ? esc(h.fields.join(", ")) : '<span class="muted">not found</span>'}</td></tr>`).join("")}</tbody></table></div>` : ""}
      ` : ""}
      <h3 class="section-title">Query run on the platform</h3>
      <div class="card"><pre class="code">${esc(r.query)}</pre><div class="row test__copy"><button class="btn btn--sm" type="button" id="fqCopy">${icons.copy} Copy</button></div></div>`, (panel) => {
      $("#fqCopy", panel)?.addEventListener("click", () => copyText(r.query, "Query copied"));
    });
  }

  if (!rules.length) {
    out.innerHTML = emptyState("No rules yet", "Add rules in the workspace first.", '<a class="btn btn--primary" href="/" data-link>Go to workspace</a>');
    $("#fcRun", root).disabled = true;
  } else if (last) {
    render();
  }
  return null;
}
