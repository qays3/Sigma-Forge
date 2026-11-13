import { api } from "../api.js";
import { feedback, ruleStats, unitTests } from "../localdata.js";
import { trackState } from "../router.js";
import { openInEditor, qualityBadge } from "../shared.js";
import { state } from "../state.js";
import { $, $$, debounce, download, emptyState, esc, forging, icons, levelBadge, plural, skeleton, toast } from "../ui.js";

const DAY = 86400000;

function ago(t) {
  if (!t) return "";
  const d = Date.now() - t;
  if (d < 3600000) return `${Math.max(1, Math.round(d / 60000))} min ago`;
  if (d < DAY) return `${Math.round(d / 3600000)} h ago`;
  return `${Math.round(d / DAY)} days ago`;
}

function build(files, analysis) {
  const stats = ruleStats.all();
  const byFile = new Map();
  analysis.rules.forEach((r) => {
    if (!byFile.has(r.file)) byFile.set(r.file, r);
  });
  return files.map((f) => {
    const a = byFile.get(f.name) || {};
    const st = stats[f.name] || null;
    const tests = unitTests.get(f.name);
    const testCount = tests.match.length + tests.nomatch.length;
    const prec = feedback.precision(f.name);
    const reasons = [];
    if (a.error) reasons.push(["bad", "Does not parse"]);
    if (a.quality && ["D", "F"].includes(a.quality.grade)) reasons.push(["warn", `Quality ${a.quality.grade}`]);
    if (tests.last && (tests.last.failed || tests.last.status !== "ok")) reasons.push(["bad", "Tests fail"]);
    if (!testCount && a.kind !== "correlation") reasons.push(["", "No tests"]);
    if (prec && prec.total >= 3 && prec.value < 50) reasons.push(["bad", `${prec.value}% precision`]);
    if (st && st.noise === "noisy") reasons.push(["warn", "Noisy"]);
    if (st && st.runs >= 3 && !st.fired_runs) reasons.push(["warn", `Silent in ${st.runs} runs`]);
    if (!st) reasons.push(["", "Never tested on logs"]);
    if (a.status === "deprecated") reasons.push(["warn", "Deprecated"]);
    const exp = (f.content || "").match(/^sf_expires:\s*'?(\d{4}-\d{2}-\d{2})/m);
    if (exp && exp[1] < new Date().toISOString().slice(0, 10)) reasons.push(["bad", "Expired IOC rule"]);
    if (!/^response\s*:/m.test(f.content || "") && ["high", "critical"].includes(a.level)) reasons.push(["", "No response steps"]);
    const serious = reasons.filter((r) => r[0]).length;
    return { file: f, a, st, tests, testCount, prec, reasons, serious };
  });
}

export async function inventoryView(root, route) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Inventory</div>
          <h1>Detection inventory</h1>
          <p>Every rule in one place with its quality, unit tests, your true and false positive verdicts, and when it last fired. Rules that need care rise to the top.</p>
        </div>
      </div>
      <div id="invStats">${skeleton.stats(4)}</div>
      <div class="toolbar mt-4" id="invBar">
        <div class="seg" id="invSeg">
          <button class="seg__btn is-active" type="button" data-f="attention">Needs attention</button>
          <button class="seg__btn" type="button" data-f="all">All</button>
          <button class="seg__btn" type="button" data-f="notests">No tests</button>
          <button class="seg__btn" type="button" data-f="silent">Never fired</button>
        </div>
        <input class="input toolbar__grow" type="search" id="invQ" placeholder="Filter rules" aria-label="Filter rules">
        <button class="btn btn--sm" type="button" id="invRun">${icons.play} Run all unit tests</button>
        <button class="btn btn--sm" type="button" id="invCsv">${icons.download} CSV</button>
      </div>
      <div class="card" id="invCard">${forging("Building the inventory")}${skeleton.rows(8)}</div>
    </section>`;
  const files = await state.rules();
  if (!files.length) {
    $("#invStats", root).innerHTML = "";
    $("#invBar", root).hidden = true;
    $("#invCard", root).innerHTML = emptyState("No rules yet", "Add Sigma rules in the workspace to build the inventory.", '<a class="btn btn--primary" href="/" data-link>Go to workspace</a>');
    return null;
  }
  let analysis;
  try {
    analysis = (await state.analysis()).analysis;
  } catch (err) {
    $("#invCard", root).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
    return null;
  }
  let rows = build(files, analysis);
  let filter = route.filter || "attention";
  $$("#invSeg [data-f]", root).forEach((b) => b.classList.toggle("is-active", b.dataset.f === filter));

  const paintStats = () => {
    const withTests = rows.filter((r) => r.testCount).length;
    const precs = rows.filter((r) => r.prec);
    const avg = precs.length ? Math.round(precs.reduce((a, r) => a + r.prec.value, 0) / precs.length) : null;
    const fired = rows.filter((r) => r.st?.last_fired && Date.now() - r.st.last_fired < 30 * DAY).length;
    $("#invStats", root).innerHTML = `<div class="stats">
      <div class="stat"><div class="stat__label">Rules</div><div class="stat__value stat__value--accent">${rows.length}</div><div class="stat__hint">${rows.filter((r) => r.st).length} tested on logs</div></div>
      <div class="stat"><div class="stat__label">Need attention</div><div class="stat__value ${rows.some((r) => r.serious) ? "stat__value--warn" : "stat__value--ok"}">${rows.filter((r) => r.serious).length}</div><div class="stat__hint">${rows.filter((r) => r.reasons.some((x) => x[0] === "bad")).length} serious</div></div>
      <div class="stat"><div class="stat__label">With unit tests</div><div class="stat__value">${withTests}</div><div class="stat__hint">${rows.length ? Math.round((withTests * 100) / rows.length) : 0}% of rules</div></div>
      <div class="stat"><div class="stat__label">Precision</div><div class="stat__value">${avg === null ? "none" : `${avg}%`}</div><div class="stat__hint">${fired} fired in 30 days</div></div>
    </div>`;
  };

  const paintTable = () => {
    const q = $("#invQ", root).value.trim().toLowerCase();
    const list = rows
      .filter((r) => {
        if (filter === "attention" && !r.serious) return false;
        if (filter === "notests" && r.testCount) return false;
        if (filter === "silent" && r.st?.fired_runs) return false;
        if (q && !`${r.a.title || ""} ${r.file.name}`.toLowerCase().includes(q)) return false;
        return true;
      })
      .sort((x, y) => y.serious - x.serious || (x.a.title || x.file.name).localeCompare(y.a.title || y.file.name));
    if (!list.length) {
      $("#invCard", root).innerHTML = `<div class="card__body"><p class="muted">${filter === "attention" ? "Nothing needs attention. Nice." : "No rules here."}</p></div>`;
      return;
    }
    $("#invCard", root).innerHTML = `<table class="table inv">
      <thead><tr><th>Rule</th><th>Quality</th><th>Tests</th><th>Precision</th><th>Last fired</th><th>Needs</th></tr></thead>
      <tbody>${list
        .map((r) => {
          const t = r.tests.last;
          const testCell = r.testCount ? `<span class="badge badge--${t ? (t.failed || t.status !== "ok" ? "bad" : "ok") : ""}">${r.testCount}${t ? (t.failed ? ` · ${t.failed} fail` : " · pass") : ""}</span>` : '<span class="muted">none</span>';
          const precCell = r.prec ? `<span class="badge badge--${r.prec.value >= 80 ? "ok" : r.prec.value >= 50 ? "warn" : "bad"}" title="${r.prec.tp} real, ${r.prec.fp} false">${r.prec.value}%</span>` : '<span class="muted">no verdicts</span>';
          const fireCell = r.st ? (r.st.last_fired ? `${esc(ago(r.st.last_fired))}<div class="muted">${esc(plural(r.st.total_hits, "hit"))} in ${esc(plural(r.st.runs, "run"))}</div>` : `<span class="muted">never, ${esc(plural(r.st.runs, "run"))}</span>`) : '<span class="muted">not run</span>';
          return `<tr data-open="${esc(r.file.id)}">
            <td class="inv__rule"><div class="inv__title">${esc(r.a.title || r.file.name)}</div><div class="inv__meta">${levelBadge(r.a.level || "")}<span class="mono">${esc(r.file.name)}</span></div></td>
            <td data-label="Quality">${qualityBadge(r.a.quality) || '<span class="badge badge--bad">error</span>'}</td>
            <td data-label="Tests">${testCell}</td>
            <td data-label="Precision">${precCell}</td>
            <td data-label="Last fired">${fireCell}</td>
            <td data-label="Needs"><div class="inv__needs">${r.reasons.map(([c, label]) => `<span class="badge ${c ? `badge--${c}` : ""}">${esc(label)}</span>`).join("") || '<span class="badge badge--ok">ok</span>'}</div></td>
          </tr>`;
        })
        .join("")}</tbody></table>`;
  };

  paintStats();
  paintTable();
  $("#invSeg", root).addEventListener("click", (e) => {
    const b = e.target.closest("[data-f]");
    if (!b) return;
    filter = b.dataset.f;
    $$("#invSeg [data-f]", root).forEach((x) => x.classList.toggle("is-active", x === b));
    trackState({ filter });
    paintTable();
  });
  $("#invQ", root).addEventListener("input", debounce(paintTable, 120));
  $("#invCard", root).addEventListener("click", (e) => {
    const tr = e.target.closest("[data-open]");
    if (!tr) return;
    const f = files.find((x) => x.id === tr.dataset.open);
    if (f) openInEditor(f.name, f.content, f.id);
  });
  $("#invRun", root).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const all = unitTests.all();
    const withTests = files.filter((f) => all[f.name]);
    if (!withTests.length) {
      toast("No rule has unit tests yet. Add them in the editor, Tests tab.", "bad", 4200);
      return;
    }
    btn.disabled = true;
    try {
      const tests = Object.fromEntries(withTests.map((f) => [f.name, { match: all[f.name].match, nomatch: all[f.name].nomatch }]));
      const res = await api.unitTests(withTests, tests);
      unitTests.saveRun(res);
      rows = build(files, analysis);
      paintStats();
      paintTable();
      toast(`${res.passed} passed, ${res.failed} failed in ${plural(res.rules.length, "rule")}`, res.failed ? "bad" : "ok", 4200);
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });
  $("#invCsv", root).addEventListener("click", () => {
    const cell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [["file", "title", "level", "quality", "tests", "tests_failed", "precision", "true_positive", "false_positive", "runs", "total_hits", "last_fired", "needs"].join(",")];
    rows.forEach((r) => {
      lines.push([r.file.name, r.a.title || "", r.a.level || "", r.a.quality?.score ?? "", r.testCount, r.tests.last?.failed ?? "", r.prec?.value ?? "", r.prec?.tp ?? "", r.prec?.fp ?? "", r.st?.runs ?? 0, r.st?.total_hits ?? 0, r.st?.last_fired ? new Date(r.st.last_fired).toISOString() : "", r.reasons.map((x) => x[1]).join("; ")].map(cell).join(","));
    });
    download("sigma-forge-inventory.csv", lines.join("\n"), "text/csv");
  });
  return null;
}
