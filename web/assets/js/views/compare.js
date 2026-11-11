import { api } from "../api.js";
import { mappingOptions, mappings } from "../mappings.js";
import { trackState } from "../router.js";
import { state } from "../state.js";
import { $, $$, copyText, debounce, emptyState, esc, forging, icons, levelBadge, openDrawer, skeleton, toast } from "../ui.js";

const PREF_KEY = "sigma-forge-compare";
const MAX = 4;
const DEFAULT_TARGETS = ["splunk", "elastic_esql", "sentinel_asim", "crowdstrike_falcon"];

function readPrefs() {
  try {
    return JSON.parse(localStorage.getItem(PREF_KEY)) || {};
  } catch {
    return {};
  }
}

function writePrefs(prefs) {
  try {
    localStorage.setItem(PREF_KEY, JSON.stringify(prefs));
  } catch {
    return;
  }
}

export async function compareView(root, route) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Compare</div>
          <h1>One rule, side by side</h1>
          <p>Pick a rule and up to ${MAX} platforms to see how each one writes the same detection.</p>
        </div>
      </div>
      <div id="cmpControls">${skeleton.card(2)}</div>
      <div id="cmpOut" class="mt-5"></div>
    </section>`;

  const [rules, targets] = await Promise.all([state.rules(), state.targets()]);
  if (!rules.length) {
    $("#cmpControls", root).innerHTML = `<div class="card">${emptyState("No rules to compare", "Add Sigma rules in the workspace first.", '<a class="btn btn--primary" href="/" data-link>Go to workspace</a>')}</div>`;
    return null;
  }

  const prefs = readPrefs();
  const usable = targets.filter((t) => t.available);
  let chosen = (route.targets || prefs.targets || DEFAULT_TARGETS).filter((id) => usable.some((t) => t.id === id)).slice(0, MAX);
  if (!chosen.length) chosen = usable.slice(0, MAX).map((t) => t.id);
  let file = rules.find((r) => r.name === (route.file || prefs.file)) || rules[0];
  let last = null;

  const families = [...new Set(targets.map((t) => t.family))];
  $("#cmpControls", root).innerHTML = `
    <div class="card convert-bar">
      <div class="convert-bar__row convert-bar__row--top">
        <button class="btn" type="button" id="cmpPick">${icons.file} <span class="cmp__file" id="cmpFile"></span></button>
        <label class="inline-field">
          <span class="field__label">Mapping</span>
          <select class="select" id="cmpMap"></select>
        </label>
        <div class="spacer"></div>
        <span class="muted" id="cmpCount"></span>
      </div>
      <div class="convert-bar__targets" aria-label="Targets">
        ${families
          .map(
            (fam) => `<div class="tgroup"><span class="tgroup__name">${esc(fam)}</span><div class="tgroup__items">${targets
              .filter((t) => t.family === fam)
              .map((t) => `<button class="pill" type="button" data-target="${esc(t.id)}" aria-pressed="false" ${t.available ? "" : "disabled"}>${esc(t.name)}</button>`)
              .join("")}</div></div>`
          )
          .join("")}
      </div>
    </div>`;

  const mapSel = $("#cmpMap", root);
  const paintMap = () => {
    mapSel.innerHTML = mappingOptions(mappings.activeId());
  };

  function paint() {
    $("#cmpFile", root).textContent = file.name;
    $$("[data-target]", root).forEach((b) => {
      const on = chosen.includes(b.dataset.target);
      b.classList.toggle("is-active", on);
      b.setAttribute("aria-pressed", String(on));
    });
    $("#cmpCount", root).textContent = `${chosen.length} of ${MAX} platforms`;
  }

  function persist() {
    writePrefs({ targets: chosen, file: file.name });
    trackState({ file: file.name, targets: chosen });
  }

  function column(res) {
    const name = res.target?.name || res.target?.id;
    if (res.error) {
      return `<article class="card cmp__col"><div class="card__head"><span class="card__title">${esc(name)}</span></div><div class="notice notice--bad">${esc(res.error)}</div></article>`;
    }
    const rows = res.results || [];
    const queries = rows.flatMap((r) => r.queries);
    const failed = rows.filter((r) => r.error);
    const warnings = [...new Set(rows.flatMap((r) => r.warnings || []))];
    return `<article class="card cmp__col">
      <div class="card__head">
        <span class="card__title">${esc(name)}</span>
        <span class="badge badge--accent">${esc(res.target.language)}</span>
        ${queries.length ? `<button class="btn btn--sm" type="button" data-copy="${esc(res.target.id)}">${icons.copy}</button>` : ""}
      </div>
      <div class="cmp__stats"><span>${queries.length ? `${queries.reduce((n, q) => n + q.length, 0)} chars` : "no query"}</span>${failed.length ? '<span class="badge badge--bad">failed</span>' : queries.length ? '<span class="badge badge--ok">ok</span>' : '<span class="badge badge--warn">skipped</span>'}</div>
      ${queries.map((q) => `<pre class="code code--tall">${esc(q)}</pre>`).join("")}
      ${failed.map((r) => `<div class="notice notice--bad">${esc(r.error)}</div>`).join("")}
      ${warnings.map((w) => `<div class="notice notice--warn">${esc(w)}</div>`).join("")}
    </article>`;
  }

  async function run() {
    persist();
    if (!chosen.length) {
      $("#cmpOut", root).innerHTML = `<div class="card">${emptyState("Pick a platform", "Choose at least one platform above.")}</div>`;
      return;
    }
    $("#cmpOut", root).innerHTML = `${forging(`Forging ${file.name} for ${chosen.length} platforms`)}<div class="cmp" data-cols="${chosen.length}">${chosen.map(() => skeleton.card(5)).join("")}</div>`;
    try {
      const profile = mappings.get(mapSel.value);
      last = await api.compare([file], chosen, {}, profile?.map || {});
      const first = last.targets.find((t) => t.results?.length)?.results || [];
      const head = first.length
        ? `<div class="cmp__rule">${first.map((r) => `<span class="cmp__title">${esc(r.title)}</span>${levelBadge(r.level)}${r.kind === "correlation" ? '<span class="badge badge--accent">correlation</span>' : ""}`).join("")}</div>`
        : "";
      $("#cmpOut", root).innerHTML = `${head}<div class="cmp" data-cols="${chosen.length}">${last.targets.map(column).join("")}</div>`;
    } catch (err) {
      $("#cmpOut", root).innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    }
  }

  const later = debounce(run, 250);

  root.addEventListener("click", (e) => {
    const pill = e.target.closest("[data-target]");
    if (pill && !pill.disabled) {
      const id = pill.dataset.target;
      if (chosen.includes(id)) chosen = chosen.filter((x) => x !== id);
      else if (chosen.length >= MAX) {
        toast(`Compare up to ${MAX} platforms at a time`, "bad");
        return;
      } else chosen = [...chosen, id];
      paint();
      later();
      return;
    }
    const copy = e.target.closest("[data-copy]");
    if (copy && last) {
      const res = last.targets.find((t) => t.target.id === copy.dataset.copy);
      copyText((res?.results || []).flatMap((r) => r.queries).join("\n\n"), "Query copied");
    }
  });

  mapSel.addEventListener("change", run);

  $("#cmpPick", root).addEventListener("click", () => {
    const body = `
      <input class="input" type="search" id="cmpFilter" placeholder="Filter files" aria-label="Filter files">
      <div class="card mt-4"><ul class="list" id="cmpList"></ul></div>`;
    openDrawer("Pick a rule", body, (panel) => {
      const draw = (f = "") => {
        $("#cmpList", panel).innerHTML = rules
          .filter((r) => !f || r.name.toLowerCase().includes(f.toLowerCase()))
          .slice(0, 400)
          .map((r) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(r.name)}</div></div><button class="btn btn--sm ${r.id === file.id ? "btn--primary" : ""}" type="button" data-pick="${esc(r.id)}">Pick</button></li>`)
          .join("");
      };
      draw();
      $("#cmpFilter", panel).addEventListener("input", debounce((e) => draw(e.target.value), 120));
      panel.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-pick]");
        if (!btn) return;
        file = rules.find((r) => r.id === btn.dataset.pick) || file;
        document.querySelector("#drawer [data-close]")?.click();
        paint();
        run();
      });
    });
  });

  paintMap();
  paint();
  run();
  return null;
}
