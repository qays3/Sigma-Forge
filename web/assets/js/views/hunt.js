import { api } from "../api.js";
import { mappingOptions, mappings } from "../mappings.js";
import { fileChips, readJson, writeJson } from "../shared.js";
import { state } from "../state.js";
import { $, $$, debounce, emptyState, esc, forging, icons, levelBadge, logo, openDrawer, plural, skeleton, toast } from "../ui.js";
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
          <p>Run your Sigma rules on the live logs of this machine (Windows, Linux or macOS), scan folders and running processes with YARA, upload .evtx files, or let a scheduled hunt watch for you.</p>
        </div>
        <div class="page-head__side" id="huntStatus">${skeleton.rows(1)}</div>
      </div>
      <div class="tabs hunt__tabs" role="tablist" id="huntTabs">
        <button class="tab is-active" type="button" data-hunt="live">Live event logs</button>
        <button class="tab" type="button" data-hunt="evtx">Upload .evtx</button>
        <button class="tab" type="button" data-hunt="yara">YARA folders</button>
        <button class="tab" type="button" data-hunt="procs">YARA processes</button>
        <button class="tab" type="button" data-hunt="schedule">Scheduled hunt</button>
      </div>
      <div class="card setup setup--stack mt-4">
        <div data-hpane="live" id="livePane">${skeleton.rows(4)}</div>
        <div data-hpane="evtx" hidden>
          <div class="setup__grid">
            <label class="dropzone dropzone--row" id="evtxDrop" for="evtxInput">
              ${logo(40, "dropzone__logo")}
              <span class="dropzone__body"><span class="dropzone__title">Drop .evtx files here</span><span class="dropzone__text">Security, Sysmon, PowerShell and more, or a triage .zip, up to 64 MB</span></span>
              <input class="hidden-input" type="file" id="evtxInput" multiple accept=".evtx,.json,.jsonl,.zip">
            </label>
            <div class="setup__note">Export a log on any Windows machine with<code class="mono">wevtutil epl Security C:\\Temp\\Security.evtx</code></div>
          </div>
          <ul class="filechips" id="evtxList"></ul>
          <div class="setup__bar"><div class="spacer"></div><button class="btn btn--primary" type="button" id="evtxRun">${icons.play} Scan with Sigma</button></div>
        </div>
        <div data-hpane="yara" id="yaraPane" hidden></div>
        <div data-hpane="procs" id="procPane" hidden></div>
        <div data-hpane="schedule" id="schedPane" hidden>${skeleton.rows(3)}</div>
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

  const chosenChannels = new Set(prefs.channels || (status.windows ? ["Microsoft-Windows-Sysmon/Operational", "Security", "Microsoft-Windows-PowerShell/Operational", "System"] : (status.channels || []).map((c) => c.id)));
  function paintLive() {
    const box = $("#livePane", root);
    if (status.error) {
      box.innerHTML = `<div class="notice notice--bad">${esc(status.error)}</div>`;
      return;
    }
    if (!status.live || !status.channels.length) {
      box.innerHTML = `<div class="notice notice--warn">Sigma Forge is running on ${esc(status.platform)}, where live log scans are not supported. Use Upload .evtx instead.</div>`;
      return;
    }
    const adminNote = status.windows
      ? "Sysmon and Security need admin rights. Close Sigma Forge and start it again from a terminal opened with Run as administrator."
      : "auditd and the auth log need root. Start Sigma Forge with sudo to read them.";
    box.innerHTML = `
      <div class="field__label">${status.windows ? "Event logs" : `${esc(status.platform)} logs`}</div>
      <div class="chgrid">${status.channels
        .map((c) => {
          const ok = c.exists && !c.error;
          const badge = ok ? (c.records ? `<span class="badge">${c.records.toLocaleString()}</span>` : '<span class="badge badge--ok">ready</span>') : c.exists ? '<span class="badge badge--warn">admin</span>' : '<span class="badge">off</span>';
          return `<label class="chcard ${ok ? "" : c.exists ? "is-locked" : "is-off"}"><input type="checkbox" data-ch="${esc(c.id)}" ${chosenChannels.has(c.id) && c.exists ? "checked" : ""} ${c.exists ? "" : "disabled"}><span class="chcard__body"><span class="chcard__top"><span class="chcard__name">${esc(c.name)}</span>${badge}</span><span class="chcard__note">${esc(c.error || c.note)}</span></span></label>`;
        })
        .join("")}</div>
      ${status.admin ? "" : `<div class="notice notice--warn mt-4">${adminNote}</div>`}
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
      last = { kind: "sigma", res, scope: `${channels.join(", ")}, last ${HOURS.find(([h]) => h === hours)?.[1].toLowerCase().replace("last ", "") || `${hours} hours`}` };
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
    if (last.kind === "yara") renderYaraScan(out, last.res, last.label || "Files scanned");
    else renderResults(out, last.res, channelHeader(last.res), { title: `Hunt on ${status.host || "this machine"}`, scope: last.scope || "" });
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
      last = { kind: "sigma", res, scope: evtxFiles.map((f) => f.name).join(", ") };
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
      last = { kind: "yara", res, label: "Files scanned" };
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

  function paintProcs() {
    const box = $("#procPane", root);
    const yr = yaraStore.all();
    box.innerHTML = `
      ${status.yara?.available ? "" : `<div class="notice notice--bad">${esc(status.yara?.message || "YARA is not installed on the server")}</div>`}
      <p class="muted">Scans the memory of every running process with your YARA rules. This finds code that only lives in memory, like injected payloads and unpacked malware. It needs ${status.windows ? "admin rights" : "root"}, and takes a few minutes on a busy machine.</p>
      ${status.admin ? "" : `<div class="notice notice--warn mt-4">Without ${status.windows ? "admin" : "root"} most processes can not be read and will be skipped.</div>`}
      <div class="setup__bar">
        <label class="inline-field"><span class="field__label">Only these PIDs</span><input class="input mono input--sm" id="procPids" placeholder="all" value="${esc(prefs.pids || "")}"></label>
        <div class="spacer"></div>
        <span class="muted">${yr.length ? esc(plural(yr.length, "YARA file")) : "No YARA rules yet"}</span>
        ${yr.length ? "" : '<a class="btn btn--sm" href="/yara" data-link>Add YARA rules</a>'}
        <button class="btn btn--primary" type="button" id="procRun" ${yr.length ? "" : "disabled"}>${icons.play} Scan processes</button>
      </div>`;
    $("#procRun", box)?.addEventListener("click", async (e) => {
      const pids = $("#procPids", box).value.split(/[\s,]+/).map(Number).filter((n) => Number.isInteger(n) && n > 0);
      prefs.pids = $("#procPids", box).value.trim();
      writeJson(PREF_KEY, prefs);
      const btn = e.currentTarget;
      btn.disabled = true;
      out.innerHTML = `${forging(pids.length ? `Scanning ${pids.length} process${pids.length === 1 ? "" : "es"}` : "Scanning every running process")}${skeleton.stats(3)}${skeleton.rows(6)}`;
      try {
        const res = await api.hunt.processes(yaraStore.all(), pids);
        last = { kind: "yara", res, label: "Processes scanned" };
        paintLast();
      } catch (err) {
        out.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
      } finally {
        btn.disabled = false;
      }
    });
  }

  const LEVELS = ["low", "medium", "high", "critical"];
  const KINDS = [["slack", "Slack"], ["teams", "Microsoft Teams"], ["discord", "Discord"], ["webhook", "Any webhook (JSON)"]];
  async function paintSchedule() {
    const box = $("#schedPane", root);
    if (status.error || !status.live) {
      box.innerHTML = `<div class="notice notice--warn">${esc(status.error || "Scheduled hunts need Sigma Forge running on Windows, Linux or macOS.")}</div>`;
      return;
    }
    let sch;
    try {
      sch = await api.hunt.schedule();
    } catch (err) {
      box.innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
      return;
    }
    const chosen = new Set(sch.channels.length ? sch.channels : [...chosenChannels]);
    const next = sch.enabled && sch.next_run ? new Date(sch.next_run * 1000).toLocaleTimeString() : "";
    box.innerHTML = `
      <div class="sched__head">
        <div><div class="sched__state ${sch.enabled ? "is-on" : ""}"><span class="sched__dot"></span>${sch.enabled ? `On, every ${sch.every_minutes} minutes` : "Off"}</div>
        <div class="muted">${sch.last_run ? `Last run ${esc(sch.last_run)}` : "Never ran yet"}${next ? ` · next at ${esc(next)}` : ""} · ${esc(plural(sch.rule_count, "rule"))} saved</div></div>
        <div class="spacer"></div>
        <button class="btn btn--sm" type="button" id="schRun">${icons.play} Run now</button>
      </div>
      <p class="muted">Sigma Forge runs the hunt in the background while it is open, and sends only new hits to your chat or webhook. The same hit is never sent twice.</p>
      <div class="field__label mt-4">Logs to watch</div>
      <div class="chgrid">${status.channels.filter((c) => c.exists).map((c) => `<label class="chcard"><input type="checkbox" data-sch="${esc(c.id)}" ${chosen.has(c.id) ? "checked" : ""}><span class="chcard__body"><span class="chcard__top"><span class="chcard__name">${esc(c.name)}</span></span><span class="chcard__note">${esc(c.error || c.note)}</span></span></label>`).join("")}</div>
      <div class="setup__grid mt-4">
        <label class="field"><span class="field__label">Send to</span><select class="select" id="schKind">${KINDS.map(([k, l]) => `<option value="${k}" ${sch.webhook.kind === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <label class="field"><span class="field__label">Webhook URL ${sch.webhook.url_set ? `<span class="muted">(saved: ${esc(sch.webhook.url)})</span>` : ""}</span><input class="input mono" id="schUrl" type="url" placeholder="${sch.webhook.url_set ? "Leave empty to keep the saved one" : "https://hooks.slack.com/services/..."}" autocomplete="off"></label>
      </div>
      <div class="setup__bar">
        <label class="inline-field"><span class="field__label">Every</span><select class="select" id="schEvery">${[5, 15, 30, 60, 180, 720].map((m) => `<option value="${m}" ${m === sch.every_minutes ? "selected" : ""}>${m < 60 ? `${m} minutes` : `${m / 60} hour${m > 60 ? "s" : ""}`}</option>`).join("")}</select></label>
        <label class="inline-field"><span class="field__label">Alert from</span><select class="select" id="schLevel">${LEVELS.map((l) => `<option value="${l}" ${l === sch.min_level ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <label class="check mb-0" title="Alert when a log that used to send events goes quiet, and when it comes back"><input type="checkbox" id="schHealth" ${sch.health_watch ? "checked" : ""}> Log health watch</label>
        <label class="inline-field"><span class="field__label">Quiet after</span><select class="select" id="schQuiet">${[1, 2, 3, 4, 6, 12].map((n) => `<option value="${n}" ${n === sch.quiet_runs ? "selected" : ""}>${n} empty run${n > 1 ? "s" : ""}</option>`).join("")}</select></label>
        <button class="btn btn--sm" type="button" id="schTest">Send a test message</button>
        <div class="spacer"></div>
        ${sch.enabled ? '<button class="btn" type="button" id="schOff">Turn off</button>' : ""}
        <button class="btn btn--primary" type="button" id="schSave">${sch.enabled ? "Save" : "Turn on"}</button>
      </div>
      ${sch.health_watch && sch.health.length ? `<div class="field__label mt-4">Log health</div><div class="health">${sch.health.map((h) => `<div class="health__item health__item--${esc(h.state || "waiting")}"><span class="health__dot"></span><div><div class="health__name">${esc(h.channel)}</div><div class="muted">${h.state === "quiet" ? `Quiet since ${esc(h.quiet_since || "")}` : h.state === "dropping" ? `${esc(plural(h.quiet_runs, "empty run"))}` : h.state === "ok" ? `${h.last_count} events last run` : "Waiting for the first events"}${h.error ? ` · ${esc(h.error)}` : ""}</div></div></div>`).join("")}</div>` : ""}
      ${sch.history.length ? `<details class="mt-4"><summary class="field__label">Run history</summary><ul class="list">${sch.history.slice(0, 12).map((h) => `<li class="list__item"><div class="list__main"><div class="list__title mono">${esc(h.time)}</div><div class="list__meta">${h.events} events · ${h.fired} rules fired · ${h.new} new hits${h.sent ? ` · sent: ${esc(h.sent)}` : ""}${h.health ? ` · logs: ${esc(h.health.join(", "))}` : ""}</div>${h.error ? `<div class="list__meta">${esc(h.error)}</div>` : ""}</div><span class="badge ${h.error && !h.events ? "badge--bad" : h.new ? "badge--warn" : "badge--ok"}">${h.new ? `${h.new} new` : h.error && !h.events ? "error" : "clean"}</span></li>`).join("")}</ul></details>` : ""}
      ${sch.recent.length ? `<details class="mt-4"><summary class="field__label">Recent alerts</summary><ul class="list">${sch.recent.slice(0, 20).map((r) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(r.rule)}</div><div class="list__meta mono">${esc(r.ts)} · ${esc(r.host)} · ${esc(r.summary)}</div></div>${levelBadge(r.level)}</li>`).join("")}</ul></details>` : ""}`;
    const save = async (enabled, btn) => {
      const channels = $$("[data-sch]", box).filter((b) => b.checked).map((b) => b.dataset.sch);
      btn.disabled = true;
      try {
        await api.hunt.saveSchedule({
          enabled,
          every_minutes: Number($("#schEvery", box).value),
          channels,
          rules: rules.filter((r) => selected.has(r.id)),
          min_level: $("#schLevel", box).value,
          kind: $("#schKind", box).value,
          url: $("#schUrl", box).value.trim() || null,
          health_watch: $("#schHealth", box).checked,
          quiet_runs: Number($("#schQuiet", box).value),
        });
        toast(enabled ? "Scheduled hunt saved" : "Scheduled hunt turned off", "ok");
        paintSchedule();
      } catch (err) {
        toast(err.message, "bad");
        btn.disabled = false;
      }
    };
    $("#schSave", box).addEventListener("click", (e) => save(true, e.currentTarget));
    $("#schOff", box)?.addEventListener("click", (e) => save(false, e.currentTarget));
    $("#schTest", box).addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        if ($("#schUrl", box).value.trim()) await save(sch.enabled, $("#schSave", box));
        await api.hunt.testWebhook();
        toast("Test message sent", "ok");
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
    });
    $("#schRun", box).addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        const res = await api.hunt.runSchedule();
        const r = res.run;
        toast(r.error && !r.events ? r.error : `${r.events} events, ${r.new} new hits${r.sent ? `, sent: ${r.sent}` : ""}`, r.error && !r.events ? "bad" : "ok", 4200);
        paintSchedule();
      } catch (err) {
        toast(err.message, "bad");
        btn.disabled = false;
      }
    });
  }

  paintLive();
  paintEvtx();
  paintYara();
  paintProcs();
  paintSchedule();
  paintLast();
  if (!rules.length) toast("Add Sigma rules in the workspace to scan event logs", "info", 4200);
  return null;
}
