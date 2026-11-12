import { api } from "../api.js";
import { navigate, trackState } from "../router.js";
import { state } from "../state.js";
import { store } from "../store.js";
import { paintMeters, readJson, writeJson } from "../shared.js";
import { $, $$, cssVar, debounce, download, downloadBlob, emptyState, esc, forging, icons, levelBadge, openDrawer, plural, skeleton, toast } from "../ui.js";

const COLLECTED_KEY = "sigma-forge-collected";
const GROUP_KEY = "sigma-forge-group";

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
      </div>
      <div class="cov__bar">
        <input class="input cov__search" type="search" id="techFilter" placeholder="Find a technique by name or id" aria-label="Find technique">
        <button class="btn btn--primary" type="button" id="exportLayer" disabled>${icons.download} Navigator layer</button>
        <select class="select cov__group" id="groupSel" aria-label="Threat group"><option value="">Threat group: none</option></select>
        <button class="btn" type="button" id="readyBtn" title="Tick the log sources you really collect">${icons.grid} Log readiness</button>
        <button class="btn" type="button" id="reportBtn" title="Download a printable coverage report">${icons.file} Report</button>
        <label class="check mb-0"><input type="checkbox" id="coveredOnly"> <span>Covered only</span></label>
        <div class="cov__notes" id="covNotes"></div>
        <div class="legend" aria-hidden="true">
          <span>0</span><span class="legend__swatch"></span>
          <span class="legend__swatch cell--h1"></span><span class="legend__swatch cell--h2"></span><span class="legend__swatch cell--h3"></span><span class="legend__swatch cell--h4"></span><span class="legend__swatch cell--h5"></span><span>8+ rules</span>
        </div>
      </div>
      <div id="covGroup"></div>
      <div class="card cov__map" id="matrix">${skeleton.matrix(15, 14)}</div>
      <div class="grid grid--2 mt-5 cov__extra" id="covExtra"></div>
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

  let groupId = route.group ?? readJson(GROUP_KEY, "");
  let collected = readJson(COLLECTED_KEY, null);
  let groups = [];

  async function fetchCoverage() {
    if (!groupId && !collected) return (await state.coverage()).coverage;
    return api.coverage(rules, groupId || "", collected);
  }

  try {
    if (groupId || collected) coverage = await fetchCoverage();
  } catch (err) {
    toast(err.message, "bad");
  }

  function paintKpis() {
  const pct = coverage.parents_total ? Math.round((coverage.parents_covered / coverage.parents_total) * 100) : 0;
  const subCount = Object.keys(coverage.techniques).filter((t) => t.includes(".")).length;
  const revoked = Object.entries(coverage.revoked || {});
  const unknown = Object.keys(coverage.unknown || {});
  const rd = collected && coverage.readiness ? coverage.readiness : null;
  $("#covStats", root).innerHTML = rd
    ? `
    <div class="kpi"><span class="kpi__label">Rules with their logs</span><span class="kpi__value">${rd.rules_ready}<small> of ${rd.rules_total}</small></span></div>
    <div class="kpi"><span class="kpi__label">Covered with your logs</span><span class="kpi__value kpi__value--ok">${coverage.parents_covered}<small> of ${coverage.parents_total} · ${pct}%</small></span></div>
    <div class="kpi"><span class="kpi__label">Blind spots</span><span class="kpi__value ${rd.blind_count ? "kpi__value--warn" : ""}">${rd.blind_count}<small> techniques, logs missing</small></span></div>
    <div class="kpi"><span class="kpi__label">Log sources</span><span class="kpi__value">${rd.collected}<small> of ${rd.sources_total} collected</small></span></div>`
    : `
    <div class="kpi"><span class="kpi__label">Tagged rules</span><span class="kpi__value">${coverage.rules_tagged}<small> of ${coverage.rules_total}</small></span></div>
    <div class="kpi"><span class="kpi__label">Techniques covered</span><span class="kpi__value kpi__value--accent">${coverage.parents_covered}<small> of ${coverage.parents_total} · ${pct}%</small></span></div>
    <div class="kpi"><span class="kpi__label">Sub techniques</span><span class="kpi__value">${subCount}</span></div>
    <div class="kpi"><span class="kpi__label">ATT&amp;CK data</span><span class="kpi__value">v${esc(coverage.attack_version || "?")}<small> Enterprise</small></span></div>`;
  $("#covNotes", root).innerHTML = `
    ${revoked.length ? `<span class="badge badge--warn" title="Revoked tags were mapped to their new ids">${revoked.map(([o, n]) => `${esc(o)} to ${esc(n)}`).join(", ")}</span>` : ""}
    ${unknown.length ? `<span class="badge badge--bad" title="Unknown technique tags">Unknown: ${unknown.map(esc).join(", ")}</span>` : ""}
    ${rd && rd.blind_count ? `<span class="badge badge--warn" title="Covered on paper, but you do not collect the logs these rules need">${rd.blind_count} blind</span>` : ""}`;
  }
  paintKpis();

  function renderMatrix() {
    const filter = $("#techFilter", root).value.trim().toLowerCase();
    const coveredOnly = $("#coveredOnly", root).checked;
    const grp = coverage.group;
    const grpParents = grp?.parents || {};
    const blind = new Set((collected && coverage.readiness ? coverage.readiness.blind : []).map((b) => b.id.split(".")[0]));
    const cols = attack.tactics
      .map((tactic) => {
        const cells = tactic.techniques
          .map((tid) => attack.techniques[tid])
          .filter(Boolean)
          .filter((t) => !coveredOnly || coverage.rollup[t.id])
          .filter((t) => !filter || t.name.toLowerCase().includes(filter) || t.id.toLowerCase().includes(filter))
          .map((t) => {
            const n = coverage.rollup[t.id] || 0;
            const g = grp ? grpParents[t.id] : "";
            const cls = [heat(n), grp ? (g ? `cell--grp cell--grp-${g}` : "cell--dim") : "", blind.has(t.id) ? "cell--blind" : ""].filter(Boolean).join(" ");
            const tip = `${t.id} ${t.name}${g ? ` · ${grp.name}: ${g}` : ""}${blind.has(t.id) ? " · blind: logs not collected" : ""}`;
            return `<button class="cell ${cls}" type="button" data-tech="${esc(t.id)}" title="${esc(tip)}"><span>${esc(t.name)}</span>${n ? `<span class="cell__count">${n}</span>` : ""}</button>`;
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
      ${list.length ? `<div class="card"><ul class="list">${list.map((r) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(r.title)}</div><div class="list__meta">${esc(r.via)} · ${esc(r.key)}</div></div>${levelBadge(r.level)}<button class="btn btn--sm" type="button" data-open="${esc(r.key)}">Open</button></li>`).join("")}</ul></div>` : '<p class="muted">No rules cover this technique yet. This is a gap you could write a rule for.</p>'}
      <h3 class="section-title">Atomic Red Team tests</h3>
      <div id="techAtomic">${skeleton.rows(2)}</div>
      <h3 class="section-title">From SigmaHQ</h3>
      <div id="techLib">${skeleton.rows(3)}</div>`;
    trackState({ technique: tid });
    openDrawer(`${tech.id} ${tech.name}`, body, (el) => {
      el.addEventListener("click", async (e) => {
        const btn = e.target.closest("[data-open]");
        if (btn) navigate("/rules", { key: btn.dataset.open });
        const add = e.target.closest("[data-addlib]");
        if (add) {
          add.disabled = true;
          try {
            const { rules: picked } = await api.library.rules([add.dataset.addlib]);
            const n = await store.add(picked);
            add.textContent = n ? "Added" : "In workspace";
            toast(n ? "Rule added. Coverage updates when you reopen the map." : "Already in the workspace", "ok");
          } catch (err) {
            add.disabled = false;
            toast(err.message, "bad");
          }
        }
        if (e.target.closest("#techLibMore")) navigate("/library", { filters: { technique: tid } });
      });
      loadLibrary(tid, el);
      loadAtomic(tid, el);
    }, () => trackState({ technique: undefined }));
  }

  async function loadAtomic(tid, el) {
    const box = $("#techAtomic", el);
    if (!box) return;
    try {
      const res = await api.atomic(tid);
      const subs = res.subs || [];
      const total = res.tests.length + subs.reduce((n, x) => n + x.count, 0);
      if (!total) {
        box.innerHTML = '<p class="muted">Atomic Red Team has no test for this technique.</p>';
        return;
      }
      box.innerHTML = `<p class="muted">Run these on a lab machine to make your rules fire for real, then test the logs on the Test page.</p>
        ${res.tests.length ? `<div class="card"><ul class="list">${res.tests
          .slice(0, 12)
          .map((t) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(t.name)}</div><div class="list__meta">${esc(t.platforms.join(", "))} · ${esc(t.executor)}</div></div><a class="btn btn--sm" href="${esc(res.url)}" target="_blank" rel="noopener">${icons.external}</a></li>`)
          .join("")}</ul></div>${res.tests.length > 12 ? `<p class="muted">and ${res.tests.length - 12} more</p>` : ""}` : ""}
        ${subs.length ? `<div class="tags mt-4">${subs.map((x) => `<a class="chip" href="https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${esc(x.id)}/${esc(x.id)}.md" target="_blank" rel="noopener">${esc(x.id)} · ${esc(plural(x.count, "test"))}</a>`).join("")}</div>` : ""}
        <div class="row mt-4"><a class="btn btn--sm" href="${esc(res.url)}" target="_blank" rel="noopener">${icons.external} Open on GitHub</a></div>`;
    } catch (err) {
      box.innerHTML = `<p class="muted">${esc(err.message)}</p>`;
    }
  }

  function renderGroup() {
    const box = $("#covGroup", root);
    const grp = coverage.group;
    if (!grp) {
      box.innerHTML = "";
      return;
    }
    const missing = grp.techniques.filter((t) => t.state === "missing");
    box.innerHTML = `<div class="card cov__grp">
      <div class="card__head"><span class="card__title">${esc(grp.name)} <span class="muted mono">${esc(grp.id)}</span></span><span class="card__sub">${esc(grp.aliases.slice(0, 4).join(", "))}</span><div class="spacer"></div><a class="btn btn--sm" href="${esc(grp.url)}" target="_blank" rel="noopener">${icons.external}</a></div>
      <div class="card__body">
        <p class="muted">${esc(grp.description)}</p>
        <div class="cov__grpstats">
          <div class="cov__grppct"><span>${grp.percent}%</span><small>covered</small></div>
          <div class="cov__grpbar"><span class="cov__grpseg cov__grpseg--covered" data-width="${grp.total ? (grp.covered * 100) / grp.total : 0}"></span><span class="cov__grpseg cov__grpseg--partial" data-width="${grp.total ? (grp.partial * 100) / grp.total : 0}"></span></div>
          <div class="legend"><span class="legend__swatch cell--grp-covered"></span><span>${grp.covered} covered</span><span class="legend__swatch cell--grp-partial"></span><span>${grp.partial} partial</span><span class="legend__swatch cell--grp-missing"></span><span>${grp.missing} missing</span></div>
        </div>
        ${missing.length ? `<div class="field__label mt-4">Missing techniques, write rules for these first</div><div class="tags">${missing.slice(0, 40).map((t) => `<button class="chip chip--bad" type="button" data-tech="${esc(t.parent)}" title="${esc(t.tactics.join(", "))}">${esc(t.id)} ${esc(t.name)}</button>`).join("")}${missing.length > 40 ? `<span class="chip">+${missing.length - 40}</span>` : ""}</div>` : '<p class="notice notice--ok">Every technique this group uses has a rule.</p>'}
      </div>
    </div>`;
    box.querySelectorAll("[data-width]").forEach((el) => el.style.setProperty("width", `${el.dataset.width}%`));
  }

  async function reload() {
    $("#matrix", root).innerHTML = skeleton.matrix(15, 14);
    try {
      coverage = await fetchCoverage();
    } catch (err) {
      toast(err.message, "bad");
    }
    paintKpis();
    renderGroup();
    renderMatrix();
    renderExtra();
  }

  async function fillGroups() {
    try {
      groups = (await api.groups()).groups.sort((a, b) => a.name.localeCompare(b.name));
    } catch {
      groups = [];
    }
    $("#groupSel", root).innerHTML = `<option value="">Threat group: none</option>${groups.map((g) => `<option value="${esc(g.id)}" ${g.id === groupId ? "selected" : ""}>${esc(g.name)} (${g.techniques})${g.aliases.length ? ` · ${esc(g.aliases.slice(0, 2).join(", "))}` : ""}</option>`).join("")}`;
  }

  $("#groupSel", root).addEventListener("change", (e) => {
    groupId = e.target.value;
    writeJson(GROUP_KEY, groupId);
    trackState({ group: groupId || undefined });
    reload();
  });

  $("#readyBtn", root).addEventListener("click", () => {
    const all = coverage.all_logsources || coverage.logsources || [];
    const picked = new Set(collected || []);
    const body = `
      <p class="muted">Tick the log sources your SIEM really receives. Coverage then shows which techniques you can detect today and which are blind because the logs are missing.</p>
      <div class="row"><button class="btn btn--sm" type="button" id="rdAll">All</button><button class="btn btn--sm" type="button" id="rdNone">None</button><div class="spacer"></div><span class="muted" id="rdCount"></span></div>
      <div class="card mt-4"><ul class="list" id="rdList">${all
        .map((x) => `<li class="list__item"><label class="check list__main"><input type="checkbox" data-src="${esc(x.label)}" ${picked.has(x.label) ? "checked" : ""}> <span class="mono">${esc(x.label)}</span></label><span class="badge">${esc(plural(x.rules, "rule"))}</span><span class="badge badge--accent">${esc(plural(x.techniques.length, "technique"))}</span></li>`)
        .join("")}</ul></div>
      <div class="row mt-4"><button class="btn btn--ghost" type="button" id="rdOff">Turn readiness off</button><div class="spacer"></div><button class="btn btn--primary" type="button" id="rdSave">Save and update map</button></div>
      ${collected && coverage.readiness ? `<h3 class="section-title">Blind spots</h3>${coverage.readiness.blind.length ? `<div class="tags">${coverage.readiness.blind.map((b) => `<span class="chip chip--bad">${esc(b.id)} ${esc(b.name)}</span>`).join("")}</div>` : '<p class="muted">No blind spots. Every covered technique has its logs.</p>'}${coverage.readiness.missing_sources.length ? `<h3 class="section-title">Log sources to start collecting</h3><div class="tags">${coverage.readiness.missing_sources.map((m) => `<span class="chip">${esc(m)}</span>`).join("")}</div>` : ""}` : ""}`;
    openDrawer("Log readiness", body, (panel) => {
      const count = () => ($("#rdCount", panel).textContent = `${picked.size} of ${all.length} collected`);
      count();
      panel.addEventListener("change", (e) => {
        const box = e.target.closest("[data-src]");
        if (!box) return;
        if (box.checked) picked.add(box.dataset.src);
        else picked.delete(box.dataset.src);
        count();
      });
      $("#rdAll", panel).addEventListener("click", () => {
        all.forEach((x) => picked.add(x.label));
        $$("[data-src]", panel).forEach((b) => (b.checked = true));
        count();
      });
      $("#rdNone", panel).addEventListener("click", () => {
        picked.clear();
        $$("[data-src]", panel).forEach((b) => (b.checked = false));
        count();
      });
      $("#rdOff", panel).addEventListener("click", () => {
        collected = null;
        try {
          localStorage.removeItem(COLLECTED_KEY);
        } catch {
          collected = null;
        }
        document.querySelector("#drawer [data-close]")?.click();
        reload();
      });
      $("#rdSave", panel).addEventListener("click", () => {
        collected = [...picked];
        writeJson(COLLECTED_KEY, collected);
        document.querySelector("#drawer [data-close]")?.click();
        reload();
      });
    });
  });

  $("#reportBtn", root).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const { blob, filename } = await api.report(rules, "Detection coverage report", groupId || null, collected);
      downloadBlob(filename, blob);
      toast("Report saved. Open it in a browser and print to PDF if you need one.", "ok", 4200);
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });

  $("#covGroup", root).addEventListener("click", (e) => {
    const chip = e.target.closest("[data-tech]");
    if (chip) showTechnique(chip.dataset.tech);
  });

  async function loadLibrary(tid, el) {
    const box = $("#techLib", el);
    if (!box) return;
    try {
      const res = await api.library.search({ technique: tid, limit: 8 });
      const have = new Set(rules.map((r) => r.name));
      box.innerHTML = res.total
        ? `<div class="card"><ul class="list">${res.rules
            .map((r) => {
              const inWs = have.has(`sigmahq/${r.path}`);
              return `<li class="list__item"><div class="list__main"><div class="list__title">${esc(r.title)}</div><div class="list__meta">${esc([r.product, r.category || r.service].filter(Boolean).join(" / "))} · ${esc(r.status)}</div></div>${levelBadge(r.level)}<button class="btn btn--sm" type="button" data-addlib="${esc(r.path)}" ${inWs ? "disabled" : ""}>${inWs ? "In workspace" : "Add"}</button></li>`;
            })
            .join("")}</ul></div>${res.total > res.rules.length ? `<div class="row mt-4"><button class="btn btn--sm" type="button" id="techLibMore">See all ${res.total} in the library</button></div>` : ""}`
        : '<p class="muted">SigmaHQ has no rule for this technique either.</p>';
    } catch {
      box.innerHTML = '<p class="muted">Sync the SigmaHQ library to get rule suggestions for this technique. <a href="/library" data-link>Open library</a></p>';
    }
  }

  function levelMix(levels) {
    const order = ["critical", "high", "medium", "low", "informational"];
    return order.filter((l) => levels[l]).map((l) => `<span class="badge badge--${l}" title="${esc(l)}">${levels[l]}</span>`).join("");
  }

  async function renderExtra() {
    const box = $("#covExtra", root);
    const sources = coverage.logsources || [];
    const maxRules = Math.max(1, ...sources.map((x) => x.rules));
    box.innerHTML = `
      <div class="card">
        <div class="card__head"><span class="card__title">Coverage by log source</span><span class="card__sub">${esc(plural(sources.length, "source"))}</span></div>
        <div class="card__body card__body--flush table-wrap">
          <table class="table">
            <thead><tr><th>Log source</th><th>Rules</th><th>Techniques</th><th>Levels</th></tr></thead>
            <tbody>${sources
              .map(
                (x) => `<tr><td><div class="table__title mono">${esc(x.label)}</div><div class="cov__srcbar"><span data-width="${Math.round((x.rules / maxRules) * 100)}"></span></div></td><td>${x.rules}</td><td>${x.techniques.length}</td><td><div class="tags">${levelMix(x.levels)}</div></td></tr>`
              )
              .join("")}</tbody>
          </table>
        </div>
      </div>
      <div class="card" id="gapCard">
        <div class="card__head"><span class="card__title">Biggest gaps</span><span class="card__sub">from SigmaHQ</span></div>
        <div class="card__body">${skeleton.rows(5)}</div>
      </div>`;
    box.querySelectorAll(".cov__srcbar span").forEach((el) => el.style.setProperty("width", `${el.dataset.width}%`));
    const card = $("#gapCard", box);
    let gaps;
    try {
      gaps = await api.gaps(rules);
    } catch (err) {
      $(".card__body", card).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
      return;
    }
    if (!gaps.available) {
      $(".card__body", card).innerHTML = `<p class="muted">Sync the SigmaHQ library to see which techniques the community covers that you do not, and which log sources would close the most gaps.</p><a class="btn btn--primary" href="/library" data-link>${icons.download} Open library</a>`;
      return;
    }
    $(".card__sub", card).textContent = `${gaps.missing} techniques SigmaHQ covers and you do not`;
    $(".card__body", card).outerHTML = `
      <ul class="list">${gaps.techniques
        .slice(0, 8)
        .map(
          (t) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(t.id)} ${esc(t.name)}</div><div class="list__meta">${esc(t.tactics.join(", "))}${t.parent_covered ? " · parent covered" : ""}</div></div><span class="badge badge--accent">${esc(plural(t.library_rules, "rule"))}</span><button class="btn btn--sm" type="button" data-gap="${esc(t.id)}">Browse</button></li>`
        )
        .join("")}</ul>
      <div class="card__head"><span class="card__title">Log sources that close the most gaps</span></div>
      <div class="card__body"><div class="tags">${gaps.logsources
        .slice(0, 12)
        .map((x) => `<button class="chip chip--accent" type="button" data-src="${esc(JSON.stringify({ product: x.product, category: x.category, service: x.service }))}" title="${esc(plural(x.rules, "rule"))}">${esc(x.label)} · ${x.techniques}</button>`)
        .join("")}</div></div>`;
  }

  $("#covExtra", root).addEventListener("click", (e) => {
    const gap = e.target.closest("[data-gap]");
    if (gap) navigate("/library", { filters: { technique: gap.dataset.gap } });
    const src = e.target.closest("[data-src]");
    if (src) {
      const f = JSON.parse(src.dataset.src);
      navigate("/library", { filters: { product: f.product, category: f.category, service: f.service } });
    }
  });

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

  renderGroup();
  renderMatrix();
  renderExtra();
  fillGroups();
  if (route.technique) showTechnique(route.technique);
  return null;
}
