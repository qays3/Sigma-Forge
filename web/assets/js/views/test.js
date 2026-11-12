import { api } from "../api.js";
import { mappingOptions, mappings } from "../mappings.js";
import { trackState } from "../router.js";
import { state } from "../state.js";
import { fileChips } from "../shared.js";
import { $, debounce, emptyState, esc, forging, icons, logo, openDrawer, plural, skeleton, toast } from "../ui.js";
import { renderResults } from "./results.js";

const MODES = [
  ["auto", "Match log source when known", "Events with a known Windows channel only hit rules for that log source. Other events are tested against every rule."],
  ["strict", "Always match log source", "A rule only sees events whose product, service and category match its logsource."],
  ["off", "Ignore log source", "Every rule runs against every event. Good for logs with custom fields."],
];

let files = [];
let lastResult = null;

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
      <div class="card setup">
        <div class="setup__main">
          <label class="dropzone dropzone--row" id="logDrop" for="logInput">
            ${logo(40, "dropzone__logo")}
            <span class="dropzone__body"><span class="dropzone__title">Drop log files here</span><span class="dropzone__text">.evtx, .json, .jsonl, .ndjson up to 64 MB</span></span>
            <input class="hidden-input" type="file" id="logInput" multiple accept=".evtx,.json,.jsonl,.ndjson,.log,.txt">
          </label>
          <div class="setup__actions">
            <button class="btn btn--sm" type="button" id="sampleLogs">${icons.spark} Sample logs</button>
            <button class="btn btn--sm" type="button" id="baselineLogs" title="A normal week of Sysmon events with known noise">${icons.box} Baseline week</button>
            <button class="btn btn--sm" type="button" id="genEvents" title="Build events that each selected rule should catch">${icons.play} Generate test events</button>
            <button class="btn btn--sm btn--ghost" type="button" id="clearLogs">${icons.trash} Clear</button>
          </div>
          <ul class="filechips" id="logList"></ul>
        </div>
        <div class="setup__side">
          <label class="field">
            <span class="field__label">Log source matching</span>
            <select class="select" id="testMode">${MODES.map(([k, label]) => `<option value="${k}">${esc(label)}</option>`).join("")}</select>
            <span class="field__hint" id="modeHint"></span>
          </label>
          <label class="field">
            <span class="field__label">Field mapping</span>
            <select class="select" id="testMap"></select>
          </label>
          <div class="setup__run">
            <button class="btn" type="button" id="testRules">${icons.file} Rules <span class="badge badge--accent" id="testRuleCount"></span></button>
            <button class="btn btn--primary" type="button" id="runTest">${icons.play} Run test</button>
          </div>
        </div>
      </div>
      <div id="testOut" class="mt-5"></div>
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
    $("#logList", root).innerHTML = fileChips(files, "No log files yet");
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

  $("#baselineLogs", root).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const { logs } = await api.sampleLogs("baseline");
      addFiles(logs.map((l) => new File([l.content], l.name, { type: "application/json" })));
      toast("Loaded a normal week of events. Run the test to see which rules are noisy.", "ok", 4200);
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });

  $("#genEvents", root).addEventListener("click", async (e) => {
    const chosen = rules.filter((r) => selected.has(r.id));
    if (!chosen.length) {
      toast("Select at least one rule", "bad");
      return;
    }
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const res = await api.generateEvents(chosen);
      if (!res.count) {
        toast("Could not build events for these rules", "bad");
        return;
      }
      addFiles([new File([res.jsonl], "generated_events.jsonl", { type: "application/json" })]);
      const failed = res.rules.filter((r) => r.status !== "ok").length;
      toast(`Built ${plural(res.count, "event")} for ${plural(res.rules.length - failed, "rule")}${failed ? `, ${failed} skipped` : ""}`, "ok", 4200);
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
      renderResults(out, lastResult, "", { title: "Log test report", scope: files.map((f) => f.name).join(", ") });
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
    renderResults(out, lastResult, "", { title: "Log test report", scope: files.map((f) => f.name).join(", ") });
  } else {
    out.innerHTML = `<div class="card">${emptyState("Add logs to start", "Drop EVTX or JSON files above, or load the sample logs, then press Run test.")}</div>`;
  }
  return null;
}
