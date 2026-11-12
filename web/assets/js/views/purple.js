import { api } from "../api.js";
import { mappingOptions, mappings } from "../mappings.js";
import { fileChips, readJson, writeJson } from "../shared.js";
import { state } from "../state.js";
import { $, emptyState, esc, forging, icons, levelBadge, logo, plural, skeleton, toast } from "../ui.js";
import { renderResults } from "./results.js";

const KEY = "sigma-forge-purple";
const STATES = { detected: ["Detected", "ok"], missed: ["Missed", "bad"], no_rule: ["No rule", "warn"] };
let logFiles = [];
let last = null;

export async function purpleView(root) {
  const prefs = readJson(KEY, { techniques: [] });
  let techniques = Array.isArray(prefs.techniques) ? prefs.techniques : [];
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Purple team</div>
          <h1>Score your detections</h1>
          <p>Pick the techniques you test, run the matching Atomic Red Team tests on a lab machine, then drop the logs here. Each technique gets a pass or fail: did any of your rules catch it?</p>
        </div>
      </div>
      <div class="card setup">
        <div class="setup__main">
          <div class="field__label">1. Techniques to test</div>
          <div class="row">
            <input class="input mono toolbar__grow" id="ppAdd" placeholder="T1059.001, T1105, T1490" spellcheck="false" aria-label="Technique ids">
            <button class="btn" type="button" id="ppAddBtn">Add</button>
          </div>
          <div class="row">
            <select class="select toolbar__grow" id="ppGroup" aria-label="Threat group"><option value="">Add every technique of a threat group...</option></select>
            <button class="btn btn--sm" type="button" id="ppMine" title="Every technique your rules are tagged with">My rules' techniques</button>
            <button class="btn btn--sm btn--ghost" type="button" id="ppClear">${icons.trash} Clear</button>
          </div>
          <div class="chips pp__chips" id="ppChips"></div>
          <div class="field__label mt-4">2. Logs from the lab run</div>
          <label class="dropzone dropzone--row" id="ppDrop" for="ppInput">
            ${logo(40, "dropzone__logo")}
            <span class="dropzone__body"><span class="dropzone__title">Drop the logs here</span><span class="dropzone__text">.evtx, .json, .jsonl or a .zip, up to 64 MB</span></span>
            <input class="hidden-input" type="file" id="ppInput" multiple accept=".evtx,.json,.jsonl,.ndjson,.zip">
          </label>
          <div class="setup__actions"><button class="btn btn--sm" type="button" id="ppSample">${icons.spark} Sample attack chain logs</button></div>
          <ul class="filechips" id="ppFiles"></ul>
        </div>
        <div class="setup__side">
          <label class="field"><span class="field__label">Field mapping</span><select class="select" id="ppMap"></select></label>
          <div class="pp__how">
            <div class="field__label">How to run the tests</div>
            <ol>
              <li>Install Invoke-AtomicRedTeam on a lab machine with Sysmon.</li>
              <li>Run <span class="mono">Invoke-AtomicTest T1059.001</span> for each technique.</li>
              <li>Export the logs with <span class="mono">wevtutil epl</span> and drop them here.</li>
            </ol>
          </div>
          <div class="setup__run">
            <button class="btn btn--primary" type="button" id="ppRun">${icons.play} Score it</button>
          </div>
        </div>
      </div>
      <div id="ppOut" class="mt-5"></div>
    </section>`;

  const rules = await state.rules();
  const out = $("#ppOut", root);
  $("#ppMap", root).innerHTML = mappingOptions(mappings.activeId());

  const save = () => writeJson(KEY, { techniques });
  const paintChips = () => {
    $("#ppChips", root).innerHTML = techniques.length
      ? techniques.map((t) => `<span class="chip chip--x">${esc(t)}<button type="button" data-rm="${esc(t)}" aria-label="Remove ${esc(t)}">×</button></span>`).join("") + `<span class="muted">${plural(techniques.length, "technique")}</span>`
      : '<span class="muted">No techniques yet. Leave it empty to score every technique your rules cover.</span>';
  };
  const add = (ids) => {
    ids.map((x) => String(x).trim().toUpperCase()).filter((x) => /^T\d{4}(\.\d{3})?$/.test(x)).forEach((x) => {
      if (!techniques.includes(x)) techniques.push(x);
    });
    save();
    paintChips();
  };
  $("#ppAddBtn", root).addEventListener("click", () => {
    add($("#ppAdd", root).value.split(/[\s,;]+/));
    $("#ppAdd", root).value = "";
  });
  $("#ppAdd", root).addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#ppAddBtn", root).click();
  });
  $("#ppChips", root).addEventListener("click", (e) => {
    const b = e.target.closest("[data-rm]");
    if (!b) return;
    techniques = techniques.filter((t) => t !== b.dataset.rm);
    save();
    paintChips();
  });
  $("#ppClear", root).addEventListener("click", () => {
    techniques = [];
    save();
    paintChips();
  });
  $("#ppMine", root).addEventListener("click", async () => {
    try {
      const cov = (await state.coverage()).coverage;
      add(Object.keys(cov.rollup || {}));
    } catch (err) {
      toast(err.message, "bad");
    }
  });
  api.groups()
    .then((res) => {
      const list = res.groups.sort((a, b) => a.name.localeCompare(b.name));
      $("#ppGroup", root).innerHTML += list.map((g) => `<option value="${esc(g.id)}">${esc(g.name)} (${g.techniques})</option>`).join("");
    })
    .catch(() => null);
  $("#ppGroup", root).addEventListener("change", async (e) => {
    const gid = e.target.value;
    if (!gid) return;
    try {
      const cov = await api.coverage(rules, gid);
      add(cov.group.techniques.map((t) => t.id));
      toast(`Added the techniques of ${cov.group.name}`, "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
    e.target.value = "";
  });

  const paintFiles = () => ($("#ppFiles", root).innerHTML = fileChips(logFiles, "No logs yet"));
  const addFiles = (list) => {
    Array.from(list || []).forEach((f) => {
      logFiles = logFiles.filter((x) => x.name !== f.name);
      logFiles.push(f);
    });
    paintFiles();
  };
  const drop = $("#ppDrop", root);
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.add("is-over"))));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.remove("is-over"))));
  drop.addEventListener("drop", (e) => addFiles(e.dataTransfer.files));
  $("#ppInput", root).addEventListener("change", (e) => {
    addFiles(e.target.files);
    e.target.value = "";
  });
  $("#ppFiles", root).addEventListener("click", (e) => {
    const b = e.target.closest("[data-drop]");
    if (!b) return;
    logFiles.splice(Number(b.dataset.drop), 1);
    paintFiles();
  });
  $("#ppSample", root).addEventListener("click", async () => {
    try {
      const { logs } = await api.sampleLogs();
      const chain = logs.filter((l) => l.name.startsWith("attack_chain"));
      addFiles(chain.map((l) => new File([l.content], l.name, { type: "application/json" })));
      if (!techniques.length) add(["T1566.001", "T1059.001", "T1033", "T1105", "T1218.011", "T1053.005", "T1547.001", "T1490", "T1003.001", "T1021.002"]);
    } catch (err) {
      toast(err.message, "bad");
    }
  });

  function paint() {
    if (!last) {
      out.innerHTML = `<div class="card">${emptyState("No score yet", "Add techniques and lab logs, then press Score it. Try the sample attack chain logs to see how it works.")}</div>`;
      return;
    }
    const s = last.summary;
    out.innerHTML = `
      <div class="pp__score">
        <div class="pp__ring" data-score="${s.score}"><span>${s.score}%</span><small>detected</small></div>
        <div class="stats pp__stats">
          <div class="stat"><div class="stat__label">Detected</div><div class="stat__value stat__value--ok">${s.detected}</div><div class="stat__hint">a rule fired</div></div>
          <div class="stat"><div class="stat__label">Missed</div><div class="stat__value ${s.missed ? "stat__value--bad" : ""}">${s.missed}</div><div class="stat__hint">rules exist, none fired</div></div>
          <div class="stat"><div class="stat__label">No rule</div><div class="stat__value ${s.no_rule ? "stat__value--warn" : ""}">${s.no_rule}</div><div class="stat__hint">write one</div></div>
          <div class="stat"><div class="stat__label">Events</div><div class="stat__value">${s.events}</div><div class="stat__hint">${esc(plural(s.techniques, "technique"))} scored</div></div>
        </div>
      </div>
      <div class="card mt-4">
        <table class="table table--fit pp__table">
          <colgroup><col class="pp__c-tech"><col class="pp__c-state"><col><col class="pp__c-atomic"></colgroup>
          <thead><tr><th>Technique</th><th>Result</th><th>Rules</th><th>Atomic tests</th></tr></thead>
          <tbody>${last.techniques
            .map((t) => {
              const [label, cls] = STATES[t.state];
              return `<tr><td><div class="table__title mono">${esc(t.id)}</div><div class="table__sub">${esc(t.name)}</div></td><td><span class="badge badge--${cls}">${label}</span></td><td>${t.rules.length ? t.rules.map((r) => `<div class="pp__rule ${r.hits ? "is-hit" : ""}"><span class="pp__mark">${r.hits ? "+" : "-"}</span>${esc(r.title)} ${r.hits ? `<span class="muted">${esc(plural(r.hits, "hit"))}</span>` : ""}</div>`).join("") : '<span class="muted">No rule tagged with this technique</span>'}</td><td>${t.atomic ? `<a class="btn btn--sm" href="${esc(t.atomic_url)}" target="_blank" rel="noopener">${t.atomic} tests ${icons.external}</a>` : '<span class="muted">none</span>'}</td></tr>`;
            })
            .join("")}</tbody>
        </table>
      </div>
      <h2 class="section-title mt-5">Full test results</h2>
      <div id="ppTest"></div>`;
    const ring = $(".pp__ring", out);
    ring.style.setProperty("--score", ring.dataset.score);
    renderResults($("#ppTest", out), last.test, "", { title: "Purple team test", scope: logFiles.map((f) => f.name).join(", ") });
  }

  $("#ppRun", root).addEventListener("click", async (e) => {
    if (!rules.length) {
      toast("Add rules in the workspace first", "bad");
      return;
    }
    if (!logFiles.length) {
      toast("Add the lab logs first", "bad");
      return;
    }
    const btn = e.currentTarget;
    btn.disabled = true;
    out.innerHTML = `${forging("Running your rules on the lab logs")}${skeleton.stats(4)}${skeleton.rows(8)}`;
    try {
      last = await api.purple(rules, techniques, logFiles, "auto", mappings.get($("#ppMap", root).value)?.map || {});
      paint();
    } catch (err) {
      out.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    } finally {
      btn.disabled = false;
    }
  });

  paintChips();
  paintFiles();
  paint();
  return null;
}
