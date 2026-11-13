import { api } from "../api.js";
import { cases, feedback, fileOf, ruleStats, unitTests } from "../localdata.js";
import { navigate } from "../router.js";
import { openInEditor, pretty, writeJson } from "../shared.js";
import { state } from "../state.js";
import { $, $$, copyText, debounce, downloadBlob, esc, icons, levelBadge, openDrawer, plural, setDrawerBody, toast } from "../ui.js";

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

function shortTime(ts) {
  const m = String(ts || "").match(/(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/);
  return m ? { day: m[1], time: m[2] } : { day: "", time: ts || "no time" };
}

function exeName(path) {
  return String(path || "").split(/[\\/]/).pop() || path || "?";
}

export function processTree(tree) {
  if (!tree) return "";
  const node = (n, cls, depth) => `<li class="ptree__node ${cls}" data-depth="${depth}"><div class="ptree__row"><span class="ptree__exe">${esc(exeName(n.image))}</span>${n.pid ? `<span class="ptree__pid">pid ${esc(n.pid)}</span>` : ""}${n.user ? `<span class="ptree__user">${esc(n.user)}</span>` : ""}${n.guess ? '<span class="ptree__pid">from the event fields</span>' : ""}${n.ts ? `<span class="ptree__ts">${esc(shortTime(n.ts).time)}</span>` : ""}</div>${n.cmd && n.cmd !== n.image ? `<div class="ptree__cmd">${esc(n.cmd)}</div>` : ""}</li>`;
  let depth = 0;
  let html = "";
  tree.ancestors.forEach((a) => {
    html += node(a, "is-parent", depth);
    depth += 1;
  });
  html += node(tree.self, "is-self", depth);
  tree.children.forEach((c) => {
    html += node(c, "is-child", depth + 1);
  });
  return `<div class="ptree"><div class="field__label">Process tree</div><ul class="ptree__list">${html}</ul></div>`;
}

function paintDepth(root) {
  root.querySelectorAll(".ptree__node[data-depth]").forEach((el) => el.style.setProperty("--depth", el.dataset.depth));
}

function timelineView(res) {
  const tl = res.timeline || { items: [], hosts: [], tactics: [] };
  if (!tl.items.length) return `<div class="card"><div class="card__body"><p class="muted">No hits to put on a timeline.</p></div></div>`;
  const path = tl.tactics.map((t) => `<span class="tpath__step">${esc(t.name)}</span>`).join('<span class="tpath__arrow" aria-hidden="true"></span>');
  const hosts = tl.hosts
    .map((h) => `<button class="thost" type="button" data-host="${esc(h.host)}"><div class="thost__top"><span class="thost__name">${esc(h.host)}</span>${levelBadge(h.top)}</div><div class="thost__meta">${esc(plural(h.hits, "hit"))} · ${esc(plural(h.rules, "rule"))} · ${esc(shortTime(h.first).time)} to ${esc(shortTime(h.last).time)}</div><div class="thost__stage">Reached <strong>${esc(h.stage || "unknown")}</strong></div><div class="thost__bar">${tl.tactics.map((t) => `<span class="${h.tactics.includes(t.short) ? "is-on" : ""}" title="${esc(t.name)}"></span>`).join("")}</div></button>`)
    .join("");
  let lastDay = "";
  const rows = tl.items
    .map((it, i) => {
      const t = shortTime(it.ts);
      let head = "";
      if (t.day && t.day !== lastDay) {
        lastDay = t.day;
        head = `<li class="tline__day">${esc(t.day)}</li>`;
      }
      return `${head}<li class="tline__item tline__item--${esc(it.level || "none")}" data-host="${esc(it.host)}" data-key="${esc(it.key)}" data-i="${i}"><span class="tline__time">${esc(t.time)}</span><span class="tline__dot" aria-hidden="true"></span><div class="tline__body"><div class="tline__title"><span>${esc(it.rule)}</span>${levelBadge(it.level)}</div><div class="tline__meta"><span class="chip">${esc(it.host)}</span>${it.user ? `<span class="muted">${esc(it.user)}</span>` : ""}${it.tactics.map((x) => `<span class="badge badge--accent">${esc(x)}</span>`).join("")}</div>${it.summary ? `<div class="tline__sum">${esc(it.summary)}</div>` : ""}</div></li>`;
    })
    .join("");
  return `
    ${path ? `<div class="card"><div class="card__head"><span class="card__title">Attack path</span><span class="card__sub">tactics seen, in ATT&amp;CK order</span></div><div class="card__body"><div class="tpath">${path}</div></div></div>` : ""}
    <div class="thosts mt-4">${hosts}</div>
    <div class="card mt-4">
      <div class="card__head"><span class="card__title">Timeline</span><span class="card__sub">${esc(plural(tl.items.length, "hit"))}${tl.truncated ? ", cut at the limit" : ""}</span><div class="spacer"></div><select class="select select--sm" data-role="hostFilter" aria-label="Host"><option value="">All hosts</option>${tl.hosts.map((h) => `<option value="${esc(h.host)}">${esc(h.host)}</option>`).join("")}</select></div>
      <ul class="tline">${rows}</ul>
    </div>`;
}

export function renderResults(out, res, extra = "", opts = {}) {
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
    <div class="viewbar mt-4">
      <div class="seg" data-role="views">
        <button class="seg__btn is-active" type="button" data-view="rules">Rules <span class="tab__count">${res.results.length}</span></button>
        <button class="seg__btn" type="button" data-view="timeline" ${(res.timeline?.items || []).length ? "" : "disabled"}>Timeline <span class="tab__count">${(res.timeline?.items || []).length}</span></button>
      </div>
      <div class="spacer"></div>
      <button class="btn btn--sm" type="button" data-role="case" ${(res.timeline?.items || []).length ? "" : "disabled"}>${icons.file} Create case</button>
      <button class="btn btn--sm" type="button" data-role="report">${icons.download} Hunt report</button>
    </div>
    <div data-pane="timeline" hidden></div>
    <div data-pane="rules">
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
    </div>
    </div>`;
  out.querySelectorAll(".bar__fill").forEach((el) => el.style.setProperty("width", `${el.dataset.width}%`));
  if (!opts.noStats) ruleStats.record(res);
  $("[data-role=case]", out).addEventListener("click", () => createCase(res, opts));
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
  const tlPane = $("[data-pane=timeline]", out);
  $("[data-role=views]", out).addEventListener("click", (e) => {
    const b = e.target.closest("[data-view]");
    if (!b || b.disabled) return;
    $$("[data-view]", out).forEach((x) => x.classList.toggle("is-active", x === b));
    $("[data-pane=rules]", out).hidden = b.dataset.view !== "rules";
    tlPane.hidden = b.dataset.view !== "timeline";
    if (b.dataset.view === "timeline" && !tlPane.dataset.ready) {
      tlPane.innerHTML = timelineView(res);
      tlPane.dataset.ready = "1";
      const sel = $("[data-role=hostFilter]", tlPane);
      const filterHost = (h) => {
        sel.value = h;
        $$(".tline__item", tlPane).forEach((li) => (li.hidden = !!h && li.dataset.host !== h));
        $$(".thost", tlPane).forEach((c) => c.classList.toggle("is-active", c.dataset.host === h));
      };
      sel?.addEventListener("change", () => filterHost(sel.value));
      tlPane.addEventListener("click", (ev) => {
        const host = ev.target.closest("[data-host].thost");
        if (host) {
          filterHost(sel.value === host.dataset.host ? "" : host.dataset.host);
          return;
        }
        const item = ev.target.closest(".tline__item");
        if (item) {
          const r = res.results.find((x) => x.key === item.dataset.key);
          if (r) showDetails(r);
        }
      });
    }
  });
  $("[data-role=report]", out).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const { blob, filename } = await api.hunt.report(res, opts.title || "Hunt report", opts.scope || "");
      downloadBlob(filename, blob);
      toast("Report saved. Open it in a browser and print to PDF if you need one.", "ok", 4200);
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });
  out.onclick = (e) => {
    const btn = e.target.closest("[data-show]");
    if (btn) showDetails(res.results[Number(btn.dataset.show)]);
  };
}

function createCase(res, opts) {
  const hits = cases.hitsFrom(res);
  const rank = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };
  const top = hits.reduce((a, h) => ((rank[h.level] || 0) > (rank[a] || 0) ? h.level : a), "low");
  const stamp = new Date().toISOString().slice(0, 16).replace("T", " ");
  const fired = (res.results || []).filter((r) => r.hits && r.kind !== "correlation");
  openDrawer("Create case", `
    <label class="field"><span class="field__label">Title</span><input class="input" id="csTitle" value="${esc(opts.title || "Hunt")} ${esc(stamp)}"></label>
    <div class="grid grid--2 mt-4">
      <label class="field"><span class="field__label">Severity</span><select class="select" id="csSev">${["low", "medium", "high", "critical"].map((l) => `<option ${l === (top === "informational" ? "low" : top) ? "selected" : ""}>${l}</option>`).join("")}</select></label>
      <label class="field"><span class="field__label">Owner</span><input class="input" id="csOwner" placeholder="Who looks at it"></label>
    </div>
    <label class="field mt-4"><span class="field__label">Summary</span><textarea class="input textarea" id="csSum" rows="3" placeholder="What happened, in a few words"></textarea></label>
    <div class="field__label mt-4">Rules to include</div>
    <div class="case__pick">${fired.map((r) => `<label class="check"><input type="checkbox" data-ck="${esc(r.key)}" checked> <span>${esc(r.title)}</span> <span class="muted">${esc(plural(r.hits, "hit"))}</span></label>`).join("")}</div>
    <div class="row mt-4"><button class="btn btn--primary" type="button" id="csSave">${icons.file} Save case</button><span class="muted">${esc(plural(hits.length, "hit"))} on ${esc(plural(new Set(hits.map((h) => h.host)).size, "host"))}</span></div>`, (panel) => {
    $("#csSave", panel).addEventListener("click", () => {
      const keys = $$("[data-ck]", panel).filter((b) => b.checked).map((b) => b.dataset.ck);
      if (!keys.length) {
        toast("Pick at least one rule", "bad");
        return;
      }
      const c = cases.save({
        title: $("#csTitle", panel).value.trim() || "Case",
        severity: $("#csSev", panel).value,
        owner: $("#csOwner", panel).value.trim(),
        summary: $("#csSum", panel).value.trim(),
        hits: cases.hitsFrom(res, keys),
        notes: [{ time: stamp, text: `Created from ${opts.title || "a run"} with ${plural(keys.length, "rule")}.` }],
      });
      writeJson("sigma-forge-case-focus", c.id);
      toast("Case saved", "ok");
      navigate("/cases");
    });
  });
}

function feedbackBar(file, event) {
  const v = feedback.verdict(file, event);
  return `<div class="fb" data-fb><span class="fb__label">Was this real?</span><button class="fb__btn ${v === "tp" ? "is-tp" : ""}" type="button" data-verdict="tp">Real threat</button><button class="fb__btn ${v === "fp" ? "is-fp" : ""}" type="button" data-verdict="fp">False positive</button></div>`;
}

function precisionSection(file) {
  const p = feedback.precision(file);
  if (!p) return "";
  const sugg = feedback.suggestFilters(file);
  return `
    <h3 class="section-title">Your verdicts</h3>
    <div class="card"><div class="card__body">
      <div class="noise__head"><span class="badge badge--${p.value >= 80 ? "ok" : p.value >= 50 ? "warn" : "bad"}">${p.value}% precision</span><span><strong>${p.tp}</strong> real, <strong>${p.fp}</strong> false positive</span></div>
      ${sugg.length ? `<div class="noise__sugg"><div class="field__label">Shared by your false positives</div>${sugg.map((s, i) => `<label class="check"><input type="checkbox" data-fpsugg="${i}" ${i === 0 ? "checked" : ""}> <span class="fb__val"><span class="mono">${esc(s.field)}: ${esc(s.value.length > 140 ? `${s.value.slice(0, 140)}...` : s.value)}</span> <span class="muted">${s.count} of ${p.fp}</span></span></label>`).join("")}<div class="row mt-4"><button class="btn btn--primary btn--sm" type="button" id="fpFilter">${icons.file} Add filter, open in editor</button></div></div>` : ""}
    </div></div>`;
}

async function filterInEditor(r, picked, btn) {
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
  const file = fileOf(r.key);
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
    ${(r.response || []).length ? `<h3 class="section-title">Response steps</h3><div class="card"><div class="card__body"><ol class="rsp__steps">${r.response.map((x) => `<li>${esc(x)}</li>`).join("")}</ol></div></div>` : ""}
    ${noiseSection(r)}
    <div data-role="precision">${precisionSection(file)}</div>
    ${alerts.length ? `<h3 class="section-title">Alerts</h3>${alerts.map((a) => `<div class="card"><pre class="code">${esc(pretty(a))}</pre></div>`).join("")}` : ""}
    ${samples.length ? `<h3 class="section-title">Matching events${r.hits > samples.length ? ` (first ${samples.length} of ${r.events || r.hits})` : ""}</h3>${samples
      .map(
        (s, i) => `<div class="card test__event"><div class="card__head"><span class="card__sub">${esc(s.source)} · ${esc([s.logsource.product, s.logsource.service, s.logsource.category].filter(Boolean).join(" / ") || "unknown source")}</span><span class="row"><button class="btn btn--sm btn--ghost" type="button" data-unit="${i}" title="Keep this event as a unit test that must match">${icons.check} Save as test</button><button class="btn btn--sm" type="button" data-rulegen="${i}">${icons.spark} Make a rule from this event</button></span></div>${r.kind === "correlation" ? "" : `<div class="card__body card__body--tight" data-fbi="${i}">${feedbackBar(file, s.event)}</div>`}${s.lineage ? `<div class="card__body">${processTree(s.lineage)}</div>` : ""}<details class="test__raw" ${s.lineage ? "" : "open"}><summary>Raw event</summary><pre class="code">${esc(pretty(s.event))}</pre></details></div>`
      )
      .join("")}` : r.status === "ok" ? '<p class="muted">No event matched this rule.</p>' : ""}
    ${r.query ? `<h3 class="section-title">SQLite query</h3><div class="card"><pre class="code">${esc(r.query)}</pre><div class="row test__copy"><button class="btn btn--sm" type="button" id="copyQuery">${icons.copy} Copy query</button></div></div>` : ""}`;
  openDrawer(r.title, body, (panel) => {
    paintDepth(panel);
    $("#copyQuery", panel)?.addEventListener("click", () => copyText(r.query, "Query copied"));
    $("#addFilter", panel)?.addEventListener("click", (e) => {
      const btn = e.currentTarget;
      const picked = $$("[data-sugg]", panel).filter((b) => b.checked).map((b) => r.noise.suggestions[Number(b.dataset.sugg)]);
      if (!picked.length) {
        toast("Pick at least one filter", "bad");
        return;
      }
      filterInEditor(r, picked, btn);
    });
    const bindFp = () => {
      $("#fpFilter", panel)?.addEventListener("click", (e) => {
        const sugg = feedback.suggestFilters(file);
        const picked = $$("[data-fpsugg]", panel).filter((b) => b.checked).map((b) => sugg[Number(b.dataset.fpsugg)]);
        if (!picked.length) {
          toast("Pick at least one filter", "bad");
          return;
        }
        filterInEditor(r, picked, e.currentTarget);
      });
    };
    bindFp();
    panel.addEventListener("click", (e) => {
      const vb = e.target.closest("[data-verdict]");
      if (vb) {
        const box = vb.closest("[data-fbi]");
        const s = samples[Number(box.dataset.fbi)];
        feedback.mark(file, s.event, vb.dataset.verdict);
        box.innerHTML = feedbackBar(file, s.event);
        $("[data-role=precision]", panel).innerHTML = precisionSection(file);
        bindFp();
        return;
      }
      const ub = e.target.closest("[data-unit]");
      if (ub) {
        const cur = unitTests.add(file, "match", samples[Number(ub.dataset.unit)].event);
        ub.disabled = true;
        toast(`Saved. ${file} has ${plural(cur.match.length + cur.nomatch.length, "test")}.`, "ok");
        return;
      }
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
