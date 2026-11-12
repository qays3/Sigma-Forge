import { api } from "../api.js";
import { navigate, trackState } from "../router.js";
import { state } from "../state.js";
import { store } from "../store.js";
import { openInEditor, paintMeters, pushHistory, qualityBadge, qualityList } from "../shared.js";
import { $, $$, closeDrawer, copyText, debounce, emptyState, esc, forging, icons, levelBadge, openDrawer, plural, skeleton, toast } from "../ui.js";

const LEVEL_ORDER = { critical: 5, high: 4, medium: 3, low: 2, informational: 1, "": 0 };

function logsourceText(ls) {
  return [ls.product, ls.category, ls.service].filter(Boolean).join(" / ") || "none";
}

function options(values, label) {
  return `<option value="">${esc(label)}</option>${values.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("")}`;
}

function unique(rows, pick) {
  return [...new Set(rows.flatMap(pick).filter(Boolean))].sort();
}

export async function rulesView(root, route) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Rules</div>
          <h1>Review your rules</h1>
          <p>Search, filter and open any rule to see its metadata, validator findings, source and a quick conversion.</p>
        </div>
      </div>
      <div class="toolbar" id="filters">
        <input class="input toolbar__grow" type="search" id="q" placeholder="Search title, id, file, tag" aria-label="Search rules">
        <select class="select" id="fLevel" aria-label="Level"></select>
        <select class="select" id="fStatus" aria-label="Status"></select>
        <select class="select" id="fProduct" aria-label="Product"></select>
        <select class="select" id="fTactic" aria-label="Tactic"></select>
        <select class="select" id="fGrade" aria-label="Quality grade">
          <option value="">Any grade</option><option value="A">Grade A</option><option value="B">Grade B</option><option value="C">Grade C</option><option value="D">Grade D</option><option value="F">Grade F</option>
        </select>
        <select class="select" id="fState" aria-label="State">
          <option value="">Any state</option><option value="ok">Clean</option><option value="issues">Has issues</option><option value="error">Has errors</option><option value="correlation">Correlations</option>
        </select>
      </div>
      <div class="card">
        <div class="card__head"><span class="card__sub" id="count">Loading</span></div>
        <div class="card__body card__body--flush table-wrap" id="table">${forging("Reading rule metadata")}${skeleton.rows(10)}</div>
      </div>
    </section>`;

  const files = await state.rules();
  if (!files.length) {
    $("#filters", root).hidden = true;
    $("#table", root).innerHTML = emptyState("No rules yet", "Add Sigma rules in the workspace to review them here.", '<a class="btn btn--primary" href="/" data-link>Go to workspace</a>');
    $("#count", root).textContent = "0 rules";
    return null;
  }

  let rows;
  try {
    rows = (await state.analysis()).analysis.rules;
  } catch (err) {
    $("#table", root).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
    return null;
  }

  $("#fLevel", root).innerHTML = options(unique(rows, (r) => [r.level]), "Any level");
  $("#fStatus", root).innerHTML = options(unique(rows, (r) => [r.status]), "Any status");
  $("#fProduct", root).innerHTML = options(unique(rows, (r) => [r.logsource.product]), "Any product");
  $("#fTactic", root).innerHTML = options(unique(rows, (r) => r.tactics), "Any tactic");

  let sortKey = "title";
  let sortDir = 1;

  function filtered() {
    const q = $("#q", root).value.trim().toLowerCase();
    const level = $("#fLevel", root).value;
    const status = $("#fStatus", root).value;
    const product = $("#fProduct", root).value;
    const tactic = $("#fTactic", root).value;
    const st = $("#fState", root).value;
    const grade = $("#fGrade", root).value;
    return rows.filter((r) => {
      if (grade && r.quality?.grade !== grade) return false;
      if (level && r.level !== level) return false;
      if (status && r.status !== status) return false;
      if (product && r.logsource.product !== product) return false;
      if (tactic && !r.tactics.includes(tactic)) return false;
      if (st === "error" && !r.error) return false;
      if (st === "issues" && (!r.issues.length || r.error)) return false;
      if (st === "ok" && (r.error || r.issues.length)) return false;
      if (st === "correlation" && r.kind !== "correlation") return false;
      if (q) {
        const hay = `${r.title} ${r.id} ${r.key} ${r.tags.join(" ")} ${r.description}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function sortRows(list) {
    const val = (r) => {
      if (sortKey === "level") return LEVEL_ORDER[r.level] ?? 0;
      if (sortKey === "issues") return (r.error ? 100 : 0) + r.issues.length;
      if (sortKey === "logsource") return logsourceText(r.logsource);
      if (sortKey === "attack") return r.techniques.length;
      if (sortKey === "quality") return r.quality?.score ?? 0;
      return String(r[sortKey] || "").toLowerCase();
    };
    return [...list].sort((a, b) => (val(a) > val(b) ? sortDir : val(a) < val(b) ? -sortDir : 0));
  }

  function render() {
    const list = sortRows(filtered());
    $("#count", root).textContent = `${plural(list.length, "rule")} shown of ${rows.length}`;
    const th = (key, label) => `<th data-sort="${key}" class="${sortKey === key ? "is-sorted" : ""}" aria-sort="${sortKey === key ? (sortDir > 0 ? "ascending" : "descending") : "none"}">${label}${sortKey === key ? (sortDir > 0 ? " ↑" : " ↓") : ""}</th>`;
    $("#table", root).innerHTML = list.length
      ? `<table class="table table--fit rules__table">
          <colgroup><col><col class="rules__c-level"><col class="rules__c-attack"><col class="rules__c-quality"><col class="rules__c-checks"></colgroup>
          <thead><tr>${th("title", "Rule")}${th("level", "Level")}${th("attack", "ATT&amp;CK")}${th("quality", "Quality")}${th("issues", "Checks")}</tr></thead>
          <tbody>${list
            .map(
              (r) => `<tr data-key="${esc(r.key)}" tabindex="0">
                <td><div class="table__title">${esc(r.title)} ${r.kind === "correlation" ? '<span class="badge badge--accent">correlation</span>' : ""}</div><div class="table__sub" title="${esc(r.key)}">${esc(r.key)}</div><div class="table__sub">${esc(logsourceText(r.logsource))}</div></td>
                <td><div class="rules__stack">${levelBadge(r.level)}${r.status ? `<span class="badge">${esc(r.status)}</span>` : ""}</div></td>
                <td><div class="tags">${r.techniques.slice(0, 2).map((t) => `<span class="badge badge--accent">${esc(t)}</span>`).join("")}${r.techniques.length > 2 ? `<span class="badge">+${r.techniques.length - 2}</span>` : ""}</div></td>
                <td>${qualityBadge(r.quality)}</td>
                <td>${r.error ? '<span class="badge badge--bad">error</span>' : r.issues.length ? `<span class="badge badge--warn">${r.issues.length} issue${r.issues.length > 1 ? "s" : ""}</span>` : '<span class="badge badge--ok">clean</span>'}</td>
              </tr>`
            )
            .join("")}</tbody></table>`
      : emptyState("No rules match", "Change the search or filters.");
  }

  async function quickConvert(panel, row, targetId) {
    const out = $("#qcOut", panel);
    out.innerHTML = `${forging("Converting")}${skeleton.blocks(1)}`;
    const file = state.fileFor(row.key, files);
    try {
      const res = await api.convert([file], targetId, "default", {});
      const match = res.results.find((r) => r.key === row.key) || res.results[0];
      out.innerHTML = match.error
        ? `<div class="card"><div class="notice notice--bad">${esc(match.error)}</div></div>`
        : `<div class="card"><div class="result__head"><div class="result__title">${esc(res.target.name)}</div><button class="btn btn--sm" type="button" id="qcCopy">${icons.copy} Copy</button></div>${match.queries.map((q) => `<pre class="code">${esc(q)}</pre>`).join("")}${(match.warnings || []).map((w) => `<div class="notice notice--warn">${esc(w)}</div>`).join("")}</div>`;
      $("#qcCopy", panel)?.addEventListener("click", () => copyText(match.queries.join("\n\n")));
    } catch (err) {
      out.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    }
  }

  async function openRule(key) {
    const row = rows.find((r) => r.key === key);
    if (!row) return;
    const file = state.fileFor(row.key, files);
    const targets = (await state.targets()).filter((t) => t.available);
    const issues = row.error
      ? `<div class="card"><div class="notice notice--bad">${esc(row.error)}</div></div>`
      : row.issues.length
        ? `<div class="card">${row.issues.map((i) => `<div class="notice notice--warn"><span class="badge badge--warn">${esc(i.severity)}</span> ${esc(i.message)}</div>`).join("")}</div>`
        : '<div class="card"><div class="notice notice--ok">No problems found by the validators.</div></div>';
    const body = `
      <dl class="meta">
        <dt>File</dt><dd class="mono">${esc(row.key)}</dd>
        <dt>Id</dt><dd class="mono">${esc(row.id || "none")}</dd>
        <dt>Level</dt><dd>${levelBadge(row.level)}</dd>
        <dt>Status</dt><dd>${esc(row.status || "none")}</dd>
        <dt>Log source</dt><dd>${esc(logsourceText(row.logsource))}</dd>
        <dt>Author</dt><dd>${esc(row.author || "none")}</dd>
        <dt>Description</dt><dd>${esc(row.description || "none")}</dd>
        <dt>Condition</dt><dd class="mono">${esc(row.conditions.join(" | ") || "none")}</dd>
        <dt>Tags</dt><dd><div class="tags">${row.tags.map((t) => `<span class="chip">${esc(t)}</span>`).join("") || "none"}</div></dd>
        <dt>False positives</dt><dd>${esc(row.falsepositives.join(", ") || "none")}</dd>
      </dl>
      <h3 class="section-title">What it does</h3>
      <div class="explain" id="ruleExplain"><div class="skeleton sk-line"></div><div class="skeleton sk-line"></div></div>
      <h3 class="section-title">Checks ${row.error ? "" : `<button class="btn btn--sm" type="button" id="fixSrc">${icons.spark} Auto fix</button>`}</h3>
      ${issues}
      ${row.quality ? `<h3 class="section-title">Quality score</h3><div class="card"><div class="card__body">${qualityList(row.quality)}</div></div>` : ""}
      ${row.error ? "" : `<h3 class="section-title">Quick convert</h3>
      <div class="row"><select class="select" id="qcTarget" aria-label="Target">${targets.map((t) => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join("")}</select><button class="btn btn--primary" type="button" id="qcRun">${icons.play} Convert</button></div>
      <div class="mt-4" id="qcOut"></div>`}
      <h3 class="section-title">Source <button class="btn btn--sm" type="button" id="copySrc">${icons.copy} Copy</button> <button class="btn btn--sm" type="button" id="editSrc">${icons.file} Edit</button></h3>
      <pre class="code code--tall">${esc(file?.content || "")}</pre>`;
    trackState({ key });
    openDrawer(row.title, body, (panel) => {
      paintMeters(panel);
      $("#copySrc", panel)?.addEventListener("click", () => copyText(file?.content || ""));
      $("#editSrc", panel)?.addEventListener("click", () => file && openInEditor(file.name, file.content, file.id));
      $("#qcRun", panel)?.addEventListener("click", () => quickConvert(panel, row, $("#qcTarget", panel).value));
      if (file) {
        api.explain([file])
          .then((res) => {
            const hit = res.rules.find((x) => x.key === row.key) || res.rules[0];
            $("#ruleExplain", panel).innerHTML = hit?.lines?.length ? hit.lines.map((l) => `<p>${esc(l)}</p>`).join("") : `<p class="muted">${esc(hit?.error || "Could not explain this rule.")}</p>`;
          })
          .catch((err) => ($("#ruleExplain", panel).innerHTML = `<p class="muted">${esc(err.message)}</p>`));
      }
      $("#fixSrc", panel)?.addEventListener("click", async (e) => {
        if (!file) return;
        const btn = e.currentTarget;
        btn.disabled = true;
        try {
          const res = await api.autofix(file.content, file.name);
          if (!res.changed) {
            toast("Nothing to fix in this rule", "ok");
            return;
          }
          pushHistory(file.name, file.content, "before auto fix");
          await store.replace(file.id, { name: file.name, content: res.content });
          toast(`Fixed: ${res.changes.slice(0, 3).join(", ")}${res.changes.length > 3 ? ` and ${res.changes.length - 3} more` : ""}`, "ok", 5000);
          closeDrawer();
          navigate("/rules", { refresh: Date.now() });
        } catch (err) {
          toast(err.message, "bad");
          btn.disabled = false;
        }
      });
    }, () => trackState({ key: undefined }));
  }

  $("#table", root).addEventListener("click", (e) => {
    const head = e.target.closest("[data-sort]");
    if (head) {
      const key = head.dataset.sort;
      sortDir = sortKey === key ? -sortDir : 1;
      sortKey = key;
      render();
      return;
    }
    const tr = e.target.closest("tr[data-key]");
    if (tr) openRule(tr.dataset.key);
  });
  $("#table", root).addEventListener("keydown", (e) => {
    const tr = e.target.closest("tr[data-key]");
    if (tr && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      openRule(tr.dataset.key);
    }
  });
  $("#q", root).addEventListener("input", debounce(render, 150));
  $$("#filters select", root).forEach((s) => s.addEventListener("change", render));

  render();
  if (route.key) openRule(route.key);
  return null;
}
