import { api } from "../api.js";
import { mappingOptions, mappings } from "../mappings.js";
import { fileChips, readJson, writeJson } from "../shared.js";
import { state } from "../state.js";
import { $, $$, debounce, emptyState, esc, forging, icons, logo, openDrawer, plural, skeleton, toast } from "../ui.js";
import { renderResults } from "./results.js";
import { renderYaraScan, yaraStore } from "./yarakit.js";

const PREF_KEY = "sigma-forge-hunt";
const HOURS = [[1, "Last hour"], [6, "Last 6 hours"], [24, "Last 24 hours"], [72, "Last 3 days"], [168, "Last 7 days"], [720, "Last 30 days"]];

let evtxFiles = [];
let last = null;

export async function huntView(root) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Hunt</div>
          <h1>Scan this machine</h1>
          <p>Run your Sigma rules on the live Windows Event Logs, scan folders with your YARA rules, or upload .evtx files from another machine.</p>
        </div>
        <div class="page-head__side" id="huntStatus">${skeleton.rows(1)}</div>
      </div>
      <div class="tabs hunt__tabs" role="tablist" id="huntTabs">
        <button class="tab is-active" type="button" data-hunt="live">Live event logs</button>
        <button class="tab" type="button" data-hunt="evtx">Upload .evtx</button>
        <button class="tab" type="button" data-hunt="yara">YARA folder scan</button>
      </div>
      <div class="card setup setup--stack mt-4">
        <div data-hpane="live" id="livePane">${skeleton.rows(4)}</div>
        <div data-hpane="evtx" hidden>
          <div class="setup__grid">
            <label class="dropzone dropzone--row" id="evtxDrop" for="evtxInput">
              ${logo(40, "dropzone__logo")}
              <span class="dropzone__body"><span class="dropzone__title">Drop .evtx files here</span><span class="dropzone__text">Security, Sysmon, PowerShell and more, up to 64 MB</span></span>
              <input class="hidden-input" type="file" id="evtxInput" multiple accept=".evtx,.json,.jsonl">
            </label>
            <div class="setup__note">Export a log on any Windows machine with<code class="mono">wevtutil epl Security C:\\Temp\\Security.evtx</code></div>
          </div>
          <ul class="filechips" id="evtxList"></ul>
          <div class="setup__bar"><div class="spacer"></div><button class="btn btn--primary" type="button" id="evtxRun">${icons.play} Scan with Sigma</button></div>
        </div>
        <div data-hpane="yara" id="yaraPane" hidden></div>
        <div class="setup__foot">
          <button class="btn btn--sm" type="button" id="huntRules">${icons.file} Sigma rules <span class="badge badge--accent" id="huntRuleCount"></span></button>
          <a class="btn btn--sm" href="/yara" data-link>${icons.grid} YARA rules <span class="badge badge--accent" id="huntYaraCount"></span></a>
          <label class="inline-field"><span class="field__label">Field mapping</span><select class="select" id="huntMap"></select></label>
        </div>
      </div>
      <div id="huntOut" class="mt-5"></div>
    </section>`;

  const out = $("#huntOut", root);
  const prefs = readJson(PREF_KEY, {});
  const rules = await state.rules();
  let selected = new Set(rules.map((r) => r.id));
  $("#huntMap", root).innerHTML = mappingOptions(mappings.activeId());
  const paintCounts = () => {
    $("#huntRuleCount", root).textContent = `${selected.size} / ${rules.length}`;
    $("#huntYaraCount", root).textContent = String(yaraStore.all().length);
  };
  paintCounts();

  $("#huntTabs", root).addEventListener("click", (e) => {
    const tab = e.target.closest("[data-hunt]");
    if (!tab) return;
    $$("#huntTabs .tab", root).forEach((t) => t.classList.toggle("is-active", t === tab));
    $$("[data-hpane]", root).forEach((p) => (p.hidden = p.dataset.hpane !== tab.dataset.hunt));
    prefs.tab = tab.dataset.hunt;
    writeJson(PREF_KEY, prefs);
  });
  if (prefs.tab) $(`#huntTabs [data-hunt="${prefs.tab}"]`, root)?.click();

  let status;
  try {
    status = await api.hunt.status();
  } catch (err) {
    status = { error: err.message, windows: false, channels: [], paths: [], yara: { available: false } };
  }
  $("#huntStatus", root).innerHTML = status.error
    ? `<span class="badge badge--bad" title="${esc(status.error)}">Scans blocked</span>`
    : `<span class="badge">${esc(status.platform)} · ${esc(status.host)}</span>${status.admin ? '<span class="badge badge--ok">admin</span>' : '<span class="badge badge--warn" title="Some logs like Security need admin rights">not admin</span>'}${status.yara?.available ? `<span class="badge badge--ok">YARA ${esc(status.yara.version)}</span>` : '<span class="badge badge--bad">no YARA</span>'}`;

  const chosenChannels = new Set(prefs.channels || ["Microsoft-Windows-Sysmon/Operational", "Security", "Microsoft-Windows-PowerShell/Operational", "System"]);
  function paintLive() {
    const box = $("#livePane", root);
    if (status.error) {
      box.innerHTML = `<div class="notice notice--bad">${esc(status.error)}</div>`;
      return;
    }
    if (!status.windows) {
      box.innerHTML = `<div class="notice notice--warn">Sigma Forge is running on ${esc(status.platform)}. Live event log scans need it to run on Windows (not in Docker). Use Upload .evtx instead, or start Sigma Forge on the Windows machine you want to scan.</div>`;
      return;
    }
    box.innerHTML = `
      <div class="field__label">Event logs</div>
      <div class="chgrid">${status.channels
        .map((c) => {
          const ok = c.exists && !c.error;
          const badge = ok ? `<span class="badge">${c.records.toLocaleString()}</span>` : c.exists ? '<span class="badge badge--warn">admin</span>' : '<span class="badge">off</span>';
          return `<label class="chcard ${ok ? "" : c.exists ? "is-locked" : "is-off"}"><input type="checkbox" data-ch="${esc(c.id)}" ${chosenChannels.has(c.id) && c.exists ? "checked" : ""} ${c.exists ? "" : "disabled"}><span class="chcard__body"><span class="chcard__top"><span class="chcard__name">${esc(c.name)}</span>${badge}</span><span class="chcard__note">${esc(c.error || c.note)}</span></span></label>`;
        })
        .join("")}</div>
      ${status.admin ? "" : '<div class="notice notice--warn mt-4">Sysmon and Security need admin rights. Close Sigma Forge and start it again from a terminal opened with Run as administrator.</div>'}
      <div class="setup__bar">
        <label class="inline-field"><span class="field__label">Time range</span><select class="select" id="liveHours">${HOURS.map(([h, label]) => `<option value="${h}" ${h === (prefs.hours || 24) ? "selected" : ""}>${label}</option>`).join("")}</select></label>
        <label class="inline-field"><span class="field__label">Max events</span><select class="select" id="liveMax">${[5000, 20000, 50000].map((n) => `<option value="${n}" ${n === (prefs.max || 20000) ? "selected" : ""}>${n.toLocaleString()}</option>`).join("")}</select></label>
        <div class="spacer"></div>
        <button class="btn btn--primary" type="button" id="liveRun">${icons.play} Scan now</button>
      </div>`;
    box.addEventListener("change", (e) => {
      const ch = e.target.closest("[data-ch]");
      if (ch) {
        if (ch.checked) chosenChannels.add(ch.dataset.ch);
        else chosenChannels.delete(ch.dataset.ch);
      }
    });
    $("#liveRun", box).addEventListener("click", runLive);
  }

  function chosenRules() {
    const list = rules.filter((r) => selected.has(r.id));
    if (!list.length) toast("Select at least one Sigma rule", "bad");
    return list;
  }

  async function runLive(e) {
    const list = chosenRules();
    if (!list.length) return;
    const channels = status.channels.filter((c) => chosenChannels.has(c.id) && c.exists).map((c) => c.id);
    if (!channels.length) {
      toast("Pick at least one event log", "bad");
      return;
    }
    const hours = Number($("#liveHours", root).value);
    const max = Number($("#liveMax", root).value);
    Object.assign(prefs, { channels: [...chosenChannels], hours, max });
    writeJson(PREF_KEY, prefs);
    const btn = e.currentTarget;
    btn.disabled = true;
    out.innerHTML = `${forging(`Reading ${plural(channels.length, "event log")} and running ${plural(list.length, "rule")}`)}${skeleton.stats(4)}${skeleton.rows(8)}`;
    try {
      const res = await api.hunt.events(list, channels, hours, max, "auto", mappings.get($("#huntMap", root).value)?.map || {});
      last = { kind: "sigma", res };
      paintLast();
    } catch (err) {
      out.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    } finally {
      btn.disabled = false;
    }
  }

  function channelHeader(res) {
    if (!res.channels) return "";
    return `<div class="card"><div class="card__head"><span class="card__title">Event logs read</span></div><ul class="list">${res.channels
      .map((c) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(c.channel)}</div>${c.error ? `<div class="list__meta">${esc(c.error)}</div>` : ""}</div><span class="badge ${c.error ? "badge--bad" : "badge--accent"}">${c.error ? "failed" : `${c.events.toLocaleString()} events`}</span><span class="muted">${c.seconds}s</span></li>`)
      .join("")}</ul></div>`;
  }

  function paintLast() {
    if (!last) {
      out.innerHTML = `<div class="card">${emptyState("Ready to hunt", "Pick a scan above. Results show here with the same noise checks and event details as the Test page.")}</div>`;
      return;
    }
    if (last.kind === "yara") renderYaraScan(out, last.res, "Files scanned");
    else renderResults(out, last.res, channelHeader(last.res));
  }

  function paintEvtx() {
    $("#evtxList", root).innerHTML = fileChips(evtxFiles, "No files yet");
  }
  const drop = $("#evtxDrop", root);
  const addEvtx = (list) => {
    Array.from(list || []).forEach((f) => {
      evtxFiles = evtxFiles.filter((x) => x.name !== f.name);
      evtxFiles.push(f);
    });
    paintEvtx();
  };
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.add("is-over"))));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.remove("is-over"))));
  drop.addEventListener("drop", (e) => addEvtx(e.dataTransfer.files));
  $("#evtxInput", root).addEventListener("change", (e) => {
    addEvtx(e.target.files);
    e.target.value = "";
  });
  $("#evtxList", root).addEventListener("click", (e) => {
    const btn = e.target.closest("[data-drop]");
    if (!btn) return;
    evtxFiles.splice(Number(btn.dataset.drop), 1);
    paintEvtx();
  });
  $("#evtxRun", root).addEventListener("click", async (e) => {
    const list = chosenRules();
    if (!list.length) return;
    if (!evtxFiles.length) {
      toast("Add an .evtx file first", "bad");
      return;
    }
    const btn = e.currentTarget;
    btn.disabled = true;
    out.innerHTML = `${forging(`Scanning ${plural(evtxFiles.length, "file")} with ${plural(list.length, "rule")}`)}${skeleton.stats(4)}${skeleton.rows(8)}`;
    try {
      const res = await api.test(list, evtxFiles, "auto", mappings.get($("#huntMap", root).value)?.map || {});
      last = { kind: "sigma", res };
      paintLast();
    } catch (err) {
      out.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    } finally {
      btn.disabled = false;
    }
  });

  function paintYara() {
    const box = $("#yaraPane", root);
    const yr = yaraStore.all();
    box.innerHTML = `
      ${status.yara?.available ? "" : `<div class="notice notice--bad">${esc(status.yara?.message || "YARA is not installed on the server")}</div>`}
      <div class="setup__grid">
        <div>
          <label class="field">
            <span class="field__label">Folders or files, one per line</span>
            <textarea class="textarea mono" id="yPaths" rows="5" spellcheck="false" placeholder="C:\\Users\\Public&#10;%TEMP%">${esc((prefs.paths || []).join("\n"))}</textarea>
          </label>
        </div>
        <div>
          <div class="field__label">Quick add</div>
          ${status.paths?.length ? `<div class="pathchips">${status.paths.map((p) => `<button class="pathchip" type="button" data-path="${esc(p)}" title="${esc(p)}">${esc(p.split(/[\\/]/).filter(Boolean).slice(-2).join("\\") || p)}</button>`).join("")}</div>` : '<p class="muted">No common folders found.</p>'}
        </div>
      </div>
      <div class="setup__bar">
        <label class="inline-field"><span class="field__label">Skip files over</span><select class="select" id="yMax">${[8, 32, 128, 512].map((n) => `<option value="${n}" ${n === (prefs.maxMb || 32) ? "selected" : ""}>${n} MB</option>`).join("")}</select></label>
        <label class="inline-field"><span class="field__label">Extensions</span><input class="input mono input--sm" id="yExt" placeholder="all" value="${esc((prefs.ext || []).join(" "))}"></label>
        <label class="check mb-0"><input type="checkbox" id="yRec" ${prefs.recursive === false ? "" : "checked"}> <span>Sub folders</span></label>
        <div class="spacer"></div>
        <span class="muted">${yr.length ? esc(plural(yr.length, "YARA file")) : "No YARA rules yet"}</span>
        ${yr.length ? "" : '<a class="btn btn--sm" href="/yara" data-link>Add YARA rules</a>'}
        <button class="btn btn--primary" type="button" id="yRun" ${yr.length ? "" : "disabled"}>${icons.play} Scan folders</button>
      </div>`;
    box.onclick = (e) => {
      const chip = e.target.closest("[data-path]");
      if (chip) {
        const area = $("#yPaths", box);
        const lines = area.value.split("\n").map((l) => l.trim()).filter(Boolean);
        if (!lines.includes(chip.dataset.path)) lines.push(chip.dataset.path);
        area.value = lines.join("\n");
      }
    };
    $("#yRun", box)?.addEventListener("click", runYara);
  }

  async function runYara(e) {
    const paths = $("#yPaths", root).value.split("\n").map((l) => l.trim()).filter(Boolean);
    if (!paths.length) {
      toast("Add at least one folder", "bad");
      return;
    }
    const ext = $("#yExt", root).value.split(/[\s,]+/).map((x) => x.trim().replace(/^\./, "")).filter(Boolean);
    const maxMb = Number($("#yMax", root).value);
    const recursive = $("#yRec", root).checked;
    Object.assign(prefs, { paths, ext, maxMb, recursive });
    writeJson(PREF_KEY, prefs);
    const btn = e.currentTarget;
    btn.disabled = true;
    out.innerHTML = `${forging(`Scanning ${plural(paths.length, "path")} with YARA`)}${skeleton.stats(3)}${skeleton.rows(6)}`;
    try {
      const res = await api.hunt.yara(yaraStore.all(), paths, recursive, 20000, maxMb, ext);
      last = { kind: "yara", res };
      paintLast();
    } catch (err) {
      out.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    } finally {
      btn.disabled = false;
    }
  }

  $("#huntRules", root).addEventListener("click", () => {
    const body = `
      <div class="row">
        <input class="input toolbar__grow" type="search" id="hrFilter" placeholder="Filter files" aria-label="Filter files">
        <button class="btn btn--sm" type="button" id="hrAll">All</button>
        <button class="btn btn--sm" type="button" id="hrNone">None</button>
      </div>
      <div id="hrChecks" class="mt-4"></div>`;
    openDrawer("Sigma rules to run", body, (panel) => {
      const draw = (f = "") => {
        $("#hrChecks", panel).innerHTML = rules
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
        paintCounts();
      });
      $("#hrFilter", panel).addEventListener("input", debounce((e) => draw(e.target.value), 120));
      $("#hrAll", panel).addEventListener("click", () => {
        selected = new Set(rules.map((r) => r.id));
        draw($("#hrFilter", panel).value);
        paintCounts();
      });
      $("#hrNone", panel).addEventListener("click", () => {
        selected = new Set();
        draw($("#hrFilter", panel).value);
        paintCounts();
      });
    });
  });

  paintLive();
  paintEvtx();
  paintYara();
  paintLast();
  if (!rules.length) toast("Add Sigma rules in the workspace to scan event logs", "info", 4200);
  return null;
}
