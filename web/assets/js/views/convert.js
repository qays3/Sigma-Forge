import { api } from "../api.js";
import { state } from "../state.js";
import { mappingOptions, mappings } from "../mappings.js";
import { $, $$, copyText, debounce, download, downloadBlob, emptyState, esc, forging, icons, levelBadge, openDrawer, plural, skeleton, toast } from "../ui.js";

const PREF_KEY = "sigma-forge-convert";
const EXT = { spl: "spl", spl2: "spl2", lucene: "txt", esql: "esql", eql: "eql", kql: "kql", xml: "xml", yaml: "yml", ppl: "ppl", logscale: "txt", s1ql: "txt", powerquery: "txt", xql: "xql", udm: "txt", cbc: "txt", aql: "aql", lpql: "txt", netwitness: "txt", json: "json", python: "py", tql: "txt", logql: "logql", quickwit: "txt", sql: "sql", surrealql: "surql" };
const FORMAT_EXT = { savedsearches: "conf", kibana_ndjson: "ndjson", siem_rule_ndjson: "ndjson", siem_rule: "json", dsl_lucene: "json", eqlapi: "json", dashboards_ndjson: "ndjson", monitor_rule: "json", module: "spl2", yara_l: "yaral", zircolite: "json", ruler: "yml", grafana_alerting: "yml", sdyaml: "yml", pantherflow: "txt", python: "py", cse_rule: "json", clickdetect: "yml", json: "json", data_model: "spl" };

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
        <label class="inline-field">
          <span class="field__label">Mapping</span>
          <select class="select" id="mapSelect">${mappingOptions(mappings.activeId())}</select>
        </label>
        <div class="spacer"></div>
        <button class="btn" type="button" id="pickRules">${icons.file} Rules <span class="badge badge--accent" id="selCount"></span></button>
        <button class="btn" type="button" id="exportPkg">${icons.box} Export package</button>
        <button class="btn" type="button" id="deployBtn" title="Push the rules to Splunk, Elastic, Sentinel or Wazuh">${icons.upload} Deploy</button>
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
    const stateOf = (r) => (r.error ? "failed" : r.queries.length ? "ok" : "skipped");
    const order = { ok: 0, skipped: 1, failed: 2 };
    const counts = { all: result.results.length, ok: 0, skipped: 0, failed: 0 };
    result.results.forEach((r) => (counts[stateOf(r)] += 1));
    const cards = result.results
      .map((r, i) => ({ r, i }))
      .sort((a, b) => order[stateOf(a.r)] - order[stateOf(b.r)])
      .map(({ r, i }) => {
        const body = r.queries.length ? r.queries.map((q) => `<pre class="code">${esc(q)}</pre>`).join("") : "";
        const warn = (r.warnings || []).map((w) => `<div class="notice notice--warn">${esc(w)}</div>`).join("");
        const err = r.error ? `<div class="notice notice--bad">${esc(r.error)}</div>` : "";
        return `<article class="card result" data-state="${stateOf(r)}">
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
        <div class="stat"><div class="stat__label">Failed</div><div class="stat__value ${s.failed ? "stat__value--bad" : ""}">${s.failed}</div><div class="stat__hint">${s.failed ? "see the Failed tab" : "nothing failed"}</div></div>
      </div>
      ${(result.notes || []).length ? `<div class="card result">${result.notes.map((n) => `<div class="notice notice--info">${esc(n)}</div>`).join("")}</div>` : ""}
      <div class="toolbar">
        <div class="tabs tabs--inline" role="tablist" id="resultFilter">
          ${[["all", "All"], ["ok", "Converted"], ["skipped", "Skipped"], ["failed", "Failed"]].map(([k, label]) => `<button class="tab ${k === "all" ? "is-active" : ""}" type="button" data-filter="${k}" ${counts[k] ? "" : k === "all" ? "" : "disabled"}>${label} <span class="tab__count">${counts[k]}</span></button>`).join("")}
        </div>
        <div class="toolbar__grow muted">${result.bundle_error ? `Bundle failed: ${esc(result.bundle_error)}` : ""}</div>
        <button class="btn btn--sm" type="button" id="copyBundle" ${result.bundle ? "" : "disabled"}>${icons.copy} Copy bundle</button>
        <button class="btn btn--sm btn--primary" type="button" id="dlBundle" ${result.bundle ? "" : "disabled"}>${icons.download} Download .${esc(ext)}</button>
      </div>
      ${cards}`;
    $("#resultFilter", root)?.addEventListener("click", (e) => {
      const tab = e.target.closest("[data-filter]");
      if (!tab || tab.disabled) return;
      $$("#resultFilter .tab", root).forEach((t) => t.classList.toggle("is-active", t === tab));
      $$(".result[data-state]", root).forEach((card) => {
        card.hidden = tab.dataset.filter !== "all" && card.dataset.state !== tab.dataset.filter;
      });
    });
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
      const options = currentOptions();
      lastResult = await api.convert(chosen, targetId, formatSelect.value, options, currentMap());
      renderResult(lastResult);
    } catch (err) {
      $("#output", root).innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    } finally {
      btn.disabled = false;
    }
  }

  function currentMap() {
    return mappings.get($("#mapSelect", root).value)?.map || {};
  }

  function currentOptions() {
    return {
      wazuh_rule_id_start: Number($("#wazuhStart", root).value) || 100100,
      wazuh_double_backslash: $("#wazuhDouble", root).checked,
      wazuh_parent_group: $("#wazuhParent", root).checked,
    };
  }

  $("#mapSelect", root).addEventListener("change", run);

  let packageCache = null;
  async function openExport() {
    const t = currentTarget();
    const chosen = rules.filter((r) => selected.has(r.id));
    if (!chosen.length) {
      toast("Select at least one rule", "bad");
      return;
    }
    openDrawer(`Export for ${t.name}`, forging("Loading packages"), async (panel) => {
      try {
        if (!packageCache) packageCache = (await api.packages()).packages;
      } catch (err) {
        panel.innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
        return;
      }
      const list = packageCache[t.id] || [];
      panel.innerHTML = `
        <p class="muted">Build a zip with ${esc(plural(chosen.length, "rule file"))}, a manifest and a README with install steps.</p>
        <div class="pkg" role="radiogroup" aria-label="Package">
          ${list
            .map(
              (p, i) => `<label class="pkg__item">
                <input type="radio" name="pkg" value="${esc(p.id)}" ${i === 0 ? "checked" : ""}>
                <span class="pkg__body"><span class="pkg__name">${esc(p.name)}</span><span class="pkg__desc">${esc(p.description)}</span><span class="pkg__fmt mono">format ${esc(p.id === "queries" ? formatSelect.value : p.format)}</span></span>
              </label>`
            )
            .join("")}
        </div>
        <label class="field mt-4">
          <span class="field__label">Package name</span>
          <input class="input mono" id="pkgName" value="sigma_forge" spellcheck="false">
        </label>
        <div class="row"><div class="spacer"></div><button class="btn btn--primary" type="button" id="pkgGo">${icons.download} Download zip</button></div>
        <div id="pkgResult"></div>`;
      $("#pkgGo", panel).addEventListener("click", async (e) => {
        const btn = e.currentTarget;
        const pkg = panel.querySelector("input[name=pkg]:checked")?.value || "auto";
        btn.disabled = true;
        $("#pkgResult", panel).innerHTML = forging("Packing");
        try {
          const res = await api.exportZip(chosen, t.id, formatSelect.value, currentOptions(), currentMap(), pkg, $("#pkgName", panel).value.trim() || "sigma_forge");
          downloadBlob(res.filename, res.blob);
          const s = res.summary || {};
          $("#pkgResult", panel).innerHTML = `<div class="card mt-4"><div class="notice notice--ok">Saved ${esc(res.filename)}${s.converted !== undefined ? `: ${s.converted} converted, ${s.skipped} skipped, ${s.failed} failed` : ""}</div></div>`;
        } catch (err) {
          $("#pkgResult", panel).innerHTML = `<div class="card mt-4"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
        } finally {
          btn.disabled = false;
        }
      });
    });
  }
  $("#exportPkg", root).addEventListener("click", openExport);
  $("#deployBtn", root).addEventListener("click", openDeploy);

  async function openDeploy() {
    const chosen = rules.filter((r) => selected.has(r.id));
    if (!chosen.length) {
      toast("Select at least one rule", "bad");
      return;
    }
    let kinds;
    try {
      kinds = (await api.deployKinds()).kinds;
    } catch (err) {
      toast(err.message, "bad");
      return;
    }
    const saved = loadPrefs().deploy || {};
    const startKind = Object.keys(kinds).find((k) => kinds[k].targets.includes(targetId)) || saved.kind || "splunk";
    const body = `
      <p class="muted">Sends ${esc(plural(chosen.length, "rule"))} straight to your platform with its API. Start with a dry run to see every request first. Tokens and passwords are never saved.</p>
      <label class="field"><span class="field__label">Platform</span><select class="select" id="dpKind">${Object.entries(kinds).map(([k, v]) => `<option value="${esc(k)}" ${k === startKind ? "selected" : ""}>${esc(v.name)}</option>`).join("")}</select></label>
      <label class="field"><span class="field__label">Query language</span><select class="select" id="dpTarget"></select></label>
      <div id="dpFields"></div>
      <label class="check"><input type="checkbox" id="dpTls" checked> <span>Check the TLS certificate</span></label>
      <label class="check"><input type="checkbox" id="dpEnable"> <span>Turn the rules on after upload</span></label>
      <div class="row mt-4"><button class="btn" type="button" id="dpDry">${icons.play} Dry run</button><div class="spacer"></div><button class="btn btn--primary" type="button" id="dpGo">${icons.upload} Deploy now</button></div>
      <div id="dpOut" class="mt-4"></div>`;
    const FIELDS = {
      splunk: [["url", "Management URL", "https://splunk.lab:8089"], ["token", "Token", "", "password"], ["username", "Or username", ""], ["password", "Password", "", "password"], ["app", "App", "search"], ["owner", "Owner", "nobody"], ["prefix", "Name prefix", "Sigma - "], ["cron", "Schedule (cron)", "*/15 * * * *"], ["earliest", "Search window", "-15m@m"]],
      elastic: [["url", "Kibana URL", "https://kibana.lab:5601"], ["token", "API key", "", "password"], ["username", "Or username", ""], ["password", "Password", "", "password"], ["space", "Space (empty for default)", ""]],
      sentinel: [["subscription", "Subscription id", ""], ["resource_group", "Resource group", ""], ["workspace", "Workspace name", ""], ["token", "Bearer token (az account get-access-token)", "", "password"], ["frequency", "Run every", "PT1H"], ["period", "Look back", "PT1H"]],
      wazuh: [["url", "Manager API URL", "https://wazuh.lab:55000"], ["username", "Username", "wazuh"], ["password", "Password", "", "password"], ["token", "Or JWT token", "", "password"], ["filename", "Rules file", "sigma_forge_rules.xml"]],
    };
    openDrawer("Deploy rules", body, (panel) => {
      const kindSel = $("#dpKind", panel);
      const paint = () => {
        const k = kindSel.value;
        const keep = saved[k] || {};
        $("#dpTarget", panel).innerHTML = kinds[k].targets
          .map((id) => targets.find((t) => t.id === id))
          .filter((t) => t && t.available)
          .map((t) => `<option value="${esc(t.id)}" ${t.id === targetId ? "selected" : ""}>${esc(t.name)}</option>`)
          .join("");
        $("#dpFields", panel).innerHTML = FIELDS[k]
          .map(([key, label, ph, type]) => `<label class="field"><span class="field__label">${esc(label)}</span><input class="input ${type ? "" : "mono"}" type="${type || "text"}" data-set="${key}" placeholder="${esc(ph)}" value="${type ? "" : esc(keep[key] ?? "")}" autocomplete="off" spellcheck="false"></label>`)
          .join("") + (k === "wazuh" ? `<label class="check"><input type="checkbox" data-set="restart" ${keep.restart ? "checked" : ""}> <span>Restart the manager after upload</span></label>` : "");
        $("#dpTls", panel).checked = keep.verify_tls !== false;
        $("#dpEnable", panel).checked = !!keep.enable;
        $("#dpOut", panel).innerHTML = "";
      };
      paint();
      kindSel.addEventListener("change", paint);
      const collect = () => {
        const out = { verify_tls: $("#dpTls", panel).checked, enable: $("#dpEnable", panel).checked };
        $$("[data-set]", panel).forEach((el) => {
          out[el.dataset.set] = el.type === "checkbox" ? el.checked : el.value.trim();
        });
        return out;
      };
      const remember = (k, st) => {
        const keep = { ...st };
        delete keep.token;
        delete keep.password;
        const prefs = loadPrefs();
        prefs.deploy = { ...(prefs.deploy || {}), kind: k, [k]: keep };
        savePrefs(prefs);
      };
      const go = async (dry, btn) => {
        const k = kindSel.value;
        const st = collect();
        remember(k, st);
        btn.disabled = true;
        $("#dpOut", panel).innerHTML = `${forging(dry ? "Planning requests" : `Deploying to ${kinds[k].name}`)}`;
        try {
          const res = await api.deploy(chosen, k, $("#dpTarget", panel).value, st, currentOptions(), currentMap(), dry);
          const ok = res.results.filter((r) => r.status === "ok" || r.status === "planned").length;
          const bad = res.results.filter((r) => r.status === "failed").length;
          const skipped = res.results.filter((r) => r.status === "skipped").length;
          $("#dpOut", panel).innerHTML = `
            <div class="notice ${bad ? "notice--bad" : "notice--ok"}">${dry ? `${esc(plural(ok, "request"))} planned. Nothing was sent.` : `${ok} sent, ${bad} failed`}${skipped ? `, ${skipped} rules skipped (no query)` : ""}</div>
            <div class="card mt-4"><ul class="list">${res.results
              .map((r) => `<li class="list__item deploy__row"><div class="list__main"><div class="list__title">${esc(r.title)}</div>${r.url ? `<div class="list__meta mono">${esc(r.method)} ${esc(r.url)}</div>` : ""}${r.message ? `<div class="list__meta">${esc(r.message)}</div>` : ""}${r.body ? `<details><summary class="muted">Request body</summary><pre class="code">${esc(r.body)}</pre></details>` : ""}</div><span class="badge badge--${r.status === "ok" ? "ok" : r.status === "planned" ? "accent" : r.status === "failed" ? "bad" : "warn"}">${esc(r.status)}${r.code ? ` ${r.code}` : ""}</span></li>`)
              .join("")}</ul></div>`;
          if (!dry) toast(bad ? `${bad} requests failed` : `Deployed to ${kinds[k].name}`, bad ? "bad" : "ok");
        } catch (err) {
          $("#dpOut", panel).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
        } finally {
          btn.disabled = false;
        }
      };
      $("#dpDry", panel).addEventListener("click", (e) => go(true, e.currentTarget));
      $("#dpGo", panel).addEventListener("click", (e) => go(false, e.currentTarget));
    });
  }

  $("#runConvert", root).addEventListener("click", run);
  renderTargets();
  renderChecks();
  run();
  return null;
}
