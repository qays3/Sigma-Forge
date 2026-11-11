import { api } from "../api.js";
import { navigate, trackState } from "../router.js";
import { state } from "../state.js";
import { $, cssVar, debounce, download, emptyState, esc, forging, icons, levelBadge, openDrawer, plural, skeleton, toast } from "../ui.js";

function heat(count) {
  if (!count) return "";
  if (count >= 8) return "cell--h5";
  if (count >= 5) return "cell--h4";
  if (count >= 3) return "cell--h3";
  if (count >= 2) return "cell--h2";
  return "cell--h1";
}

function rulesFor(tid, attack, coverage) {
  const tech = attack.techniques[tid];
  const ids = [tid, ...(tech?.subs || [])];
  const seen = new Map();
  ids.forEach((id) => (coverage.techniques[id]?.rules || []).forEach((r) => seen.set(r.key, { ...r, via: id })));
  return Array.from(seen.values());
}

export async function coverageView(root, route) {
  root.innerHTML = `
    <section class="view cov">
      <div class="cov__top">
        <div class="cov__title">
          <div class="page-head__eyebrow">Coverage</div>
          <h1>MITRE ATT&amp;CK heat map</h1>
          <div class="cov__kpis" id="covStats">${forging("Mapping rules to ATT&CK")}</div>
        </div>
        <button class="btn btn--primary" type="button" id="exportLayer" disabled>${icons.download} Navigator layer</button>
      </div>
      <div class="cov__bar">
        <input class="input cov__search" type="search" id="techFilter" placeholder="Find a technique by name or id" aria-label="Find technique">
        <label class="check mb-0"><input type="checkbox" id="coveredOnly"> <span>Covered only</span></label>
        <div class="cov__notes" id="covNotes"></div>
        <div class="legend" aria-hidden="true">
          <span>0</span><span class="legend__swatch"></span>
          <span class="legend__swatch cell--h1"></span><span class="legend__swatch cell--h2"></span><span class="legend__swatch cell--h3"></span><span class="legend__swatch cell--h4"></span><span class="legend__swatch cell--h5"></span><span>8+ rules</span>
        </div>
      </div>
      <div class="card cov__map" id="matrix">${skeleton.matrix(15, 14)}</div>
    </section>`;

  const rules = await state.rules();
  if (!rules.length) {
    $("#covStats", root).innerHTML = "";
    $("#matrix", root).innerHTML = emptyState("No rules loaded", "Add Sigma rules with ATT&CK tags to see coverage.", '<a class="btn btn--primary" href="/" data-link>Go to workspace</a>');
    return null;
  }

  let attack;
  let coverage;
  try {
    [attack, { coverage }] = await Promise.all([state.attack(), state.coverage()]);
  } catch (err) {
    $("#covStats", root).innerHTML = "";
    $("#matrix", root).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
    return null;
  }

  const pct = coverage.parents_total ? Math.round((coverage.parents_covered / coverage.parents_total) * 100) : 0;
  const subCount = Object.keys(coverage.techniques).filter((t) => t.includes(".")).length;
  const revoked = Object.entries(coverage.revoked || {});
  const unknown = Object.keys(coverage.unknown || {});
  $("#covStats", root).innerHTML = `
    <div class="kpi"><span class="kpi__label">Tagged rules</span><span class="kpi__value">${coverage.rules_tagged}<small> of ${coverage.rules_total}</small></span></div>
    <div class="kpi"><span class="kpi__label">Techniques covered</span><span class="kpi__value kpi__value--accent">${coverage.parents_covered}<small> of ${coverage.parents_total} · ${pct}%</small></span></div>
    <div class="kpi"><span class="kpi__label">Sub techniques</span><span class="kpi__value">${subCount}</span></div>
    <div class="kpi"><span class="kpi__label">ATT&amp;CK data</span><span class="kpi__value">v${esc(coverage.attack_version || "?")}<small> Enterprise</small></span></div>`;
  $("#covNotes", root).innerHTML = `
    ${revoked.length ? `<span class="badge badge--warn" title="Revoked tags were mapped to their new ids">${revoked.map(([o, n]) => `${esc(o)} to ${esc(n)}`).join(", ")}</span>` : ""}
    ${unknown.length ? `<span class="badge badge--bad" title="Unknown technique tags">Unknown: ${unknown.map(esc).join(", ")}</span>` : ""}`;

  function renderMatrix() {
    const filter = $("#techFilter", root).value.trim().toLowerCase();
    const coveredOnly = $("#coveredOnly", root).checked;
    const cols = attack.tactics
      .map((tactic) => {
        const cells = tactic.techniques
          .map((tid) => attack.techniques[tid])
          .filter(Boolean)
          .filter((t) => !coveredOnly || coverage.rollup[t.id])
          .filter((t) => !filter || t.name.toLowerCase().includes(filter) || t.id.toLowerCase().includes(filter))
          .map((t) => {
            const n = coverage.rollup[t.id] || 0;
            return `<button class="cell ${heat(n)}" type="button" data-tech="${esc(t.id)}" title="${esc(`${t.id} ${t.name}`)}"><span>${esc(t.name)}</span>${n ? `<span class="cell__count">${n}</span>` : ""}</button>`;
          })
          .join("");
        const cov = coverage.tactics.find((c) => c.short === tactic.short) || { covered: 0, total: tactic.techniques.length };
        const width = cov.total ? Math.round((cov.covered / cov.total) * 100) : 0;
        return `<div class="matrix__col">
          <div class="matrix__head">
            <div class="matrix__tactic">${esc(tactic.name)}</div>
            <div class="matrix__count">${cov.covered}/${cov.total}</div>
            <div class="matrix__progress"><span data-width="${width}"></span></div>
          </div>${cells || '<div class="matrix__empty">None</div>'}</div>`;
      })
      .join("");
    $("#matrix", root).innerHTML = `<div class="matrix-wrap"><div class="matrix matrix--fit">${cols}</div></div>`;
    $(".matrix--fit", root).style.setProperty("--cols", attack.tactics.length);
    root.querySelectorAll(".matrix__progress span").forEach((el) => el.style.setProperty("width", `${el.dataset.width}%`));
  }

  function showTechnique(tid) {
    const tech = attack.techniques[tid];
    if (!tech) return;
    const list = rulesFor(tid, attack, coverage);
    const subs = (tech.subs || []).map((s) => attack.techniques[s]).filter(Boolean);
    const body = `
      <dl class="meta">
        <dt>Id</dt><dd class="mono">${esc(tech.id)}</dd>
        <dt>Tactics</dt><dd>${tech.tactics.map((t) => `<span class="chip">${esc(t)}</span>`).join(" ")}</dd>
        <dt>Rules</dt><dd>${list.length}</dd>
        <dt>Reference</dt><dd><a href="${esc(tech.url)}" target="_blank" rel="noopener">Open on attack.mitre.org</a></dd>
      </dl>
      ${subs.length ? `<h3 class="section-title">Sub techniques</h3><div class="tags">${subs.map((s) => `<span class="badge ${coverage.techniques[s.id] ? "badge--accent" : ""}" title="${esc(s.name)}">${esc(s.id)} ${esc(s.name)}${coverage.techniques[s.id] ? ` (${coverage.techniques[s.id].count})` : ""}</span>`).join("")}</div>` : ""}
      <h3 class="section-title">Rules</h3>
      ${list.length ? `<div class="card"><ul class="list">${list.map((r) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(r.title)}</div><div class="list__meta">${esc(r.via)} · ${esc(r.key)}</div></div>${levelBadge(r.level)}<button class="btn btn--sm" type="button" data-open="${esc(r.key)}">Open</button></li>`).join("")}</ul></div>` : '<p class="muted">No rules cover this technique yet. This is a gap you could write a rule for.</p>'}`;
    trackState({ technique: tid });
    openDrawer(`${tech.id} ${tech.name}`, body, (el) => {
      el.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-open]");
        if (btn) navigate("/rules", { key: btn.dataset.open });
      });
    }, () => trackState({ technique: undefined }));
  }

  $("#matrix", root).addEventListener("click", (e) => {
    const cell = e.target.closest("[data-tech]");
    if (cell) showTechnique(cell.dataset.tech);
  });
  $("#techFilter", root).addEventListener("input", debounce(renderMatrix, 150));
  $("#coveredOnly", root).addEventListener("change", renderMatrix);

  const exportBtn = $("#exportLayer", root);
  exportBtn.disabled = false;
  exportBtn.addEventListener("click", async () => {
    exportBtn.disabled = true;
    try {
      const colors = [cssVar("--black-panel"), cssVar("--violet-dim"), cssVar("--violet")].filter(Boolean);
      const layer = await api.navigator(rules, "Sigma Forge coverage", colors);
      download("sigma-forge_navigator_layer.json", JSON.stringify(layer, null, 2), "application/json");
      toast("Layer saved. Open it in ATT&CK Navigator.", "ok");
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      exportBtn.disabled = false;
    }
  });

  renderMatrix();
  if (route.technique) showTechnique(route.technique);
  return null;
}
