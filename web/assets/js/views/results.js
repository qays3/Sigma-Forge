import { api } from "../api.js";
import { openInEditor, pretty } from "../shared.js";
import { state } from "../state.js";
import { $, $$, copyText, debounce, esc, icons, levelBadge, openDrawer, plural, setDrawerBody, toast } from "../ui.js";

const NOISE_CLASS = { quiet: "ok", busy: "warn", noisy: "bad" };

export function statusBadge(r) {
  if (r.status === "failed" || r.status === "error") return '<span class="badge badge--bad">error</span>';
  if (r.status === "skipped") return '<span class="badge">skipped</span>';
  if (r.hits) return `<span class="badge badge--ok">${esc(plural(r.hits, r.kind === "correlation" ? "alert" : "hit"))}</span>`;
  return '<span class="badge badge--warn">silent</span>';
}

function groupOf(r) {
  if (r.status === "failed" || r.status === "error") return "errors";
  if (r.status === "skipped") return "skipped";
  return r.hits ? "hits" : "silent";
}

function noiseBadge(r) {
  if (!r.noise || r.kind === "correlation") return "";
  return `<span class="badge badge--${NOISE_CLASS[r.noise.level] || ""}" title="${esc(r.noise.per_1000)} hits per 1000 events">${esc(r.noise.level)}</span>`;
}

export function renderResults(out, res, extra = "") {
  const s = res.summary;
  const groups = { all: res.results.length, hits: 0, noisy: 0, silent: 0, errors: 0, skipped: 0 };
  res.results.forEach((r) => {
    groups[groupOf(r)] += 1;
    if (r.noise && r.noise.level !== "quiet" && r.kind !== "correlation") groups.noisy += 1;
  });
  const maxSource = Math.max(1, ...res.logsources.map((l) => l.events));
  out.innerHTML = `
    ${extra ? `<div class="results__extra">${extra}</div>` : ""}
    <div class="stats">
      <div class="stat"><div class="stat__label">Events</div><div class="stat__value stat__value--accent">${s.events}</div><div class="stat__hint">${esc(plural(s.files, "file"))} · ${esc(plural(res.fields, "field"))}</div></div>
      <div class="stat"><div class="stat__label">Rules that fired</div><div class="stat__value stat__value--ok">${s.matched_rules}</div><div class="stat__hint">of ${s.tested} tested</div></div>
      <div class="stat"><div class="stat__label">Noisy rules</div><div class="stat__value ${groups.noisy ? "stat__value--warn" : ""}">${groups.noisy}</div><div class="stat__hint">${s.matched_events} events hit</div></div>
      <div class="stat"><div class="stat__label">Errors</div><div class="stat__value ${s.errors ? "stat__value--bad" : ""}">${s.errors}</div><div class="stat__hint">ran in ${s.seconds}s</div></div>
    </div>
    <div class="card">
      <div class="card__head"><span class="card__title">Log sources found</span><span class="card__sub">mode ${esc(res.mode)}</span></div>
      <div class="card__body"><div class="bars">${res.logsources
        .map((l) => `<div class="bar"><span class="bar__label">${esc(l.name)}</span><span class="bar__track"><span class="bar__fill" data-width="${Math.round((l.events / maxSource) * 100)}"></span></span><span class="bar__value">${l.events}</span></div>`)
        .join("")}</div></div>
    </div>
    <div class="toolbar mt-4">
      <div class="tabs tabs--inline" data-role="tabs">
        ${[["all", "All"], ["hits", "Fired"], ["noisy", "Noisy"], ["silent", "Silent"], ["errors", "Errors"], ["skipped", "Skipped"]].map(([k, label]) => `<button class="tab ${k === "all" ? "is-active" : ""}" type="button" data-filter="${k}" ${groups[k] || k === "all" ? "" : "disabled"}>${label} <span class="tab__count">${groups[k]}</span></button>`).join("")}
      </div>
      <input class="input toolbar__grow" type="search" data-role="filter" placeholder="Filter rules" aria-label="Filter rules">
    </div>
    <div class="card">
      <ul class="list">${res.results
        .map(
          (r, i) => `<li class="list__item test__row" data-group="${groupOf(r)}" data-noisy="${r.noise && r.noise.level !== "quiet" && r.kind !== "correlation" ? "1" : ""}" data-title="${esc(r.title.toLowerCase())}">
            <div class="list__main">
              <div class="list__title">${esc(r.title)}</div>
              <div class="list__meta">${esc(r.key)}${r.logsource ? ` · ${esc(r.logsource)}` : ""}${r.message ? ` · ${esc(r.message)}` : ""}</div>
            </div>
            ${levelBadge(r.level)}
            ${noiseBadge(r)}
            ${statusBadge(r)}
            <button class="btn btn--sm" type="button" data-show="${i}">Details</button>
          </li>`
        )
        .join("")}</ul>
    </div>`;
  out.querySelectorAll(".bar__fill").forEach((el) => el.style.setProperty("width", `${el.dataset.width}%`));
  const tabs = $("[data-role=tabs]", out);
  const filter = $("[data-role=filter]", out);
  const apply = () => {
    const tab = $(".tab.is-active", tabs)?.dataset.filter || "all";
    const q = filter.value.trim().toLowerCase();
    $$(".test__row", out).forEach((row) => {
      const inTab = tab === "all" || (tab === "noisy" ? row.dataset.noisy === "1" : row.dataset.group === tab);
      row.hidden = !inTab || (q && !row.dataset.title.includes(q));
    });
  };
  tabs.addEventListener("click", (e) => {
    const tab = e.target.closest("[data-filter]");
    if (!tab || tab.disabled) return;
    $$(".tab", tabs).forEach((t) => t.classList.toggle("is-active", t === tab));
    apply();
  });
  filter.addEventListener("input", debounce(apply, 120));
  out.onclick = (e) => {
    const btn = e.target.closest("[data-show]");
    if (btn) showDetails(res.results[Number(btn.dataset.show)]);
  };
}

function noiseSection(r) {
  const n = r.noise;
  if (!n || r.kind === "correlation") return "";
  const fields = n.fields || [];
  const sugg = n.suggestions || [];
  return `
    <h3 class="section-title">Noise check</h3>
    <div class="card">
      <div class="card__body">
        <div class="noise__head">
          <span class="badge badge--${NOISE_CLASS[n.level] || ""}">${esc(n.level)}</span>
          <span><strong>${n.hits}</strong> hits, <strong>${n.per_1000}</strong> per 1000 events</span>
        </div>
        ${fields.length ? `<table class="table table--compact noise__table"><thead><tr><th>Field</th><th>Top values</th><th>Distinct</th></tr></thead><tbody>${fields
          .map((f) => `<tr><td class="mono">${esc(f.field)}${f.in_rule ? ' <span class="badge">in rule</span>' : ""}</td><td>${f.top.map((v) => `<div class="noise__val"><span class="mono">${esc(v.value)}</span><span class="muted">${v.count}</span></div>`).join("")}${f.tail ? `<div class="noise__val"><span class="mono">ends with ${esc(f.tail.value)}</span><span class="muted">${f.tail.count}</span></div>` : ""}</td><td>${f.distinct}</td></tr>`)
          .join("")}</tbody></table>` : ""}
        ${sugg.length
          ? `<div class="noise__sugg">
              <div class="field__label">Suggested filters</div>
              ${sugg.map((s, i) => `<label class="check"><input type="checkbox" data-sugg="${i}" checked> <span class="mono">${esc(s.field)}: ${esc(s.value)}</span> <span class="muted">${s.count} hits</span></label>`).join("")}
              <div class="row mt-4"><button class="btn btn--primary btn--sm" type="button" id="addFilter">${icons.file} Add filter, open in editor</button></div>
            </div>`
          : n.level !== "quiet"
            ? '<p class="muted">No single value explains most hits. Look at the events below to find what is normal here.</p>'
            : ""}
      </div>
    </div>`;
}

export function showDetails(r) {
  const samples = r.samples || [];
  const alerts = r.alerts || [];
  const body = `
    <dl class="meta">
      <dt>Status</dt><dd>${statusBadge(r)}</dd>
      <dt>File</dt><dd class="mono">${esc(r.key)}</dd>
      <dt>Log source</dt><dd>${esc(r.logsource || "not filtered")}</dd>
      ${r.kind === "correlation" ? `<dt>Events used</dt><dd>${r.events || 0}</dd>` : ""}
    </dl>
    ${r.message ? `<div class="card"><div class="notice notice--bad">${esc(r.message)}</div></div>` : ""}
    ${(r.warnings || []).length ? `<div class="card mt-4">${r.warnings.map((w) => `<div class="notice notice--warn">${esc(w)}</div>`).join("")}</div>` : ""}
    ${noiseSection(r)}
    ${alerts.length ? `<h3 class="section-title">Alerts</h3>${alerts.map((a) => `<div class="card"><pre class="code">${esc(pretty(a))}</pre></div>`).join("")}` : ""}
    ${samples.length ? `<h3 class="section-title">Matching events${r.hits > samples.length ? ` (first ${samples.length} of ${r.events || r.hits})` : ""}</h3>${samples
      .map(
        (s, i) => `<div class="card test__event"><div class="card__head"><span class="card__sub">${esc(s.source)} · ${esc([s.logsource.product, s.logsource.service, s.logsource.category].filter(Boolean).join(" / ") || "unknown source")}</span><button class="btn btn--sm" type="button" data-rulegen="${i}">${icons.spark} Make a rule from this event</button></div><pre class="code">${esc(pretty(s.event))}</pre></div>`
      )
      .join("")}` : r.status === "ok" ? '<p class="muted">No event matched this rule.</p>' : ""}
    ${r.query ? `<h3 class="section-title">SQLite query</h3><div class="card"><pre class="code">${esc(r.query)}</pre><div class="row test__copy"><button class="btn btn--sm" type="button" id="copyQuery">${icons.copy} Copy query</button></div></div>` : ""}`;
  openDrawer(r.title, body, (panel) => {
    $("#copyQuery", panel)?.addEventListener("click", () => copyText(r.query, "Query copied"));
    $("#addFilter", panel)?.addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      const picked = $$("[data-sugg]", panel).filter((b) => b.checked).map((b) => r.noise.suggestions[Number(b.dataset.sugg)]);
      if (!picked.length) {
        toast("Pick at least one filter", "bad");
        return;
      }
      const rules = await state.rules();
      const file = state.fileFor(r.key, rules);
      if (!file) {
        toast("This rule is no longer in the workspace", "bad");
        return;
      }
      btn.disabled = true;
      try {
        const res = await api.addFilter(file.content, r.title, picked.map((p) => ({ field: p.field, value: p.value })));
        openInEditor(file.name, res.content, file.id);
        toast("Filter added. Check it, then save.", "ok");
      } catch (err) {
        toast(err.message, "bad");
        btn.disabled = false;
      }
    });
    panel.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-rulegen]");
      if (!btn) return;
      const s = samples[Number(btn.dataset.rulegen)];
      ruleFromEvent(s.event, s.logsource);
    });
  });
}

export async function ruleFromEvent(event, logsource, inDrawer = true) {
  const draw = (html, ready) => (inDrawer && document.getElementById("drawer").classList.contains("is-open") ? setDrawerBody(html, ready) : openDrawer("Rule from an event", html, ready));
  const ls = logsource && Object.values(logsource).some(Boolean) ? logsource : null;
  draw('<div class="skeleton sk-title"></div><div class="skeleton sk-block"></div>');
  let res;
  try {
    res = await api.ruleGen(event, ls, null);
  } catch (err) {
    draw(`<div class="notice notice--bad">${esc(err.message)}</div>`);
    return;
  }
  let chosen = new Set(res.chosen);
  const body = `
    <p class="muted">Pick the fields that make this event stand out. Paths become "ends with", long command lines become "contains all".</p>
    <div class="grid grid--2 rulegen">
      <div class="card"><div class="card__head"><span class="card__title">Fields</span><span class="card__sub">${res.fields.length}</span></div><div class="card__body rulegen__fields">${res.fields
        .map((f) => `<label class="check"><input type="checkbox" data-field="${esc(f.name)}" ${chosen.has(f.name) ? "checked" : ""}> <span class="mono">${esc(f.name)}</span> <span class="muted rulegen__val">${esc(String(f.value).slice(0, 120))}</span></label>`)
        .join("")}</div></div>
      <div class="card"><div class="card__head"><span class="card__title">Draft rule</span></div><pre class="code code--tall" id="rgYaml">${esc(res.yaml)}</pre></div>
    </div>
    <div class="row mt-4">
      <input class="input toolbar__grow" id="rgTitle" placeholder="Rule title (optional)" aria-label="Rule title">
      <button class="btn btn--primary" type="button" id="rgOpen">${icons.file} Open in editor</button>
    </div>`;
  draw(body, (panel) => {
    const refresh = debounce(async () => {
      if (!chosen.size) {
        $("#rgYaml", panel).textContent = "Pick at least one field";
        return;
      }
      try {
        const next = await api.ruleGen(event, ls, [...chosen], $("#rgTitle", panel).value.trim());
        res.yaml = next.yaml;
        $("#rgYaml", panel).textContent = next.yaml;
      } catch (err) {
        $("#rgYaml", panel).textContent = err.message;
      }
    }, 200);
    panel.addEventListener("change", (e) => {
      const box = e.target.closest("[data-field]");
      if (!box) return;
      if (box.checked) chosen.add(box.dataset.field);
      else chosen.delete(box.dataset.field);
      refresh();
    });
    $("#rgTitle", panel).addEventListener("input", refresh);
    $("#rgOpen", panel).addEventListener("click", () => {
      if (!chosen.size) {
        toast("Pick at least one field", "bad");
        return;
      }
      const title = (res.yaml.match(/^title:\s*(.+)$/m) || [])[1] || "rule_from_event";
      const name = `${title.replace(/['"]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "rule_from_event"}.yml`;
      openInEditor(name, res.yaml);
    });
  });
}
