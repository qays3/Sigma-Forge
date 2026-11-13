import { api } from "../api.js";
import { pagerHtml } from "../pager.js";
import { readJson, writeJson } from "../shared.js";
import { $, debounce, emptyState, esc, forging, icons, logo, openDrawer, plural, skeleton, toast } from "../ui.js";
import { yaraStore } from "./yarakit.js";

const PAGE = 200;
const KEY = "sigma-forge-yaralib";

export function yaraLibrary(host) {
  const prefs = readJson(KEY, { pkg: "core", q: "", repo: "", tag: "", min: 0, sort: "" });
  let status = null;
  let rows = [];
  let total = 0;
  let page = 1;
  let picked = new Set();
  let poll = null;
  let token = 0;
  let alive = true;
  host.innerHTML = `<div id="ylStatus">${skeleton.card(2)}</div><div id="ylBody" class="mt-4"></div>`;
  const have = () => new Set(yaraStore.all().flatMap((f) => [...f.content.matchAll(/^\s*(?:private\s+|global\s+)*rule\s+(\w+)/gm)].map((m) => m[1])));
  let haveRules = have();

  function statusCard() {
    const busy = status.syncing;
    const pkgs = Object.entries(status.packages || {});
    $("#ylStatus", host).innerHTML = `
      <div class="card lib__status">
        <div class="lib__state">
          ${logo(44, busy ? "lib__logo is-busy" : "lib__logo")}
          <div>
            <div class="lib__title">${status.available ? `${esc(status.rules.toLocaleString())} YARA rules · ${esc(status.package)}${status.release ? ` · ${esc(status.release)}` : ""}` : busy ? `Downloading YARA Forge ${esc(status.syncing_package)}` : "YARA library not synced"}</div>
            <div class="muted">${status.available ? `Synced ${esc(status.synced_at)} · from ${esc(`${(status.repos || []).length} repositories`)} through YARA Forge` : busy ? "The core set is about 2 MB, full is bigger" : "YARA Forge (yarahq.github.io) collects and checks public YARA rules from many repositories. Pick a set and sync, or upload a YARA Forge zip if this machine is offline."}</div>
          </div>
        </div>
        ${status.error ? `<div class="notice notice--bad lib__error">${esc(status.error)}</div>` : ""}
        <div class="row">
          <select class="select" id="ylPkg" aria-label="Rule set">${pkgs.map(([k, d]) => `<option value="${k}" ${k === (status.package || prefs.pkg) ? "selected" : ""} title="${esc(d)}">${esc(d)}</option>`).join("")}</select>
          <button class="btn ${status.available ? "" : "btn--primary"}" type="button" id="ylSync" ${busy ? "disabled" : ""}>${icons.download} ${status.available ? "Update" : "Sync now"}</button>
          <label class="btn" for="ylZip">${icons.upload} Upload zip</label>
          <input class="hidden-input" type="file" id="ylZip" accept=".zip">
        </div>
      </div>`;
    $("#ylSync", host).addEventListener("click", async () => {
      prefs.pkg = $("#ylPkg", host).value;
      writeJson(KEY, prefs);
      try {
        status = await api.yaraLib.sync(prefs.pkg);
        statusCard();
        load();
      } catch (err) {
        toast(err.message, "bad");
      }
    });
    $("#ylZip", host).addEventListener("change", async (e) => {
      const file = e.target.files?.[0];
      e.target.value = "";
      if (!file) return;
      $("#ylStatus", host).innerHTML = forging(`Reading ${file.name}`);
      try {
        status = await api.yaraLib.upload(file);
        toast(`YARA library loaded with ${status.rules} rules`, "ok");
        $("#ylBody", host).innerHTML = "";
      } catch (err) {
        toast(err.message, "bad");
      }
      load();
    });
  }

  async function load() {
    if (!alive) return;
    try {
      status = await api.yaraLib.status();
    } catch (err) {
      $("#ylStatus", host).innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
      return;
    }
    statusCard();
    clearTimeout(poll);
    if (status.syncing) {
      poll = setTimeout(load, 1500);
    } else if (status.available) {
      if (!$("#ylQ", host)) build();
    } else {
      $("#ylBody", host).innerHTML = `<div class="card">${emptyState("No YARA rules yet", "Sync YARA Forge to browse thousands of checked public YARA rules.")}</div>`;
    }
  }

  const opts = (list, label, cur) => `<option value="">${esc(label)}</option>${list.map((x) => `<option value="${esc(x.name)}" ${x.name === cur ? "selected" : ""}>${esc(x.name)} (${x.count})</option>`).join("")}`;

  function build() {
    $("#ylBody", host).innerHTML = `
      <div class="toolbar">
        <input class="input toolbar__grow" type="search" id="ylQ" placeholder="Search name, description, author, malware family" aria-label="Search YARA library" value="${esc(prefs.q)}">
        <select class="select" id="ylRepo" aria-label="Repository">${opts(status.repos || [], "Any repository", prefs.repo)}</select>
        <select class="select" id="ylTag" aria-label="Tag">${opts(status.tags || [], "Any tag", prefs.tag)}</select>
        <select class="select" id="ylMin" aria-label="Lowest score">${[[0, "Any score"], [60, "Score 60+"], [70, "Score 70+"], [80, "Score 80+"]].map(([v, l]) => `<option value="${v}" ${Number(prefs.min) === v ? "selected" : ""}>${l}</option>`).join("")}</select>
        <select class="select" id="ylSort" aria-label="Sort">${[["", "By repository"], ["score", "Highest score"], ["date", "Newest"]].map(([v, l]) => `<option value="${v}" ${prefs.sort === v ? "selected" : ""}>${l}</option>`).join("")}</select>
      </div>
      <div class="card">
        <div class="card__head">
          <span class="card__sub" id="ylCount"></span>
          <div class="spacer"></div>
          <button class="btn btn--sm" type="button" id="ylPage">Select page</button>
          <button class="btn btn--sm btn--primary" type="button" id="ylAdd" disabled>${icons.upload} Add to YARA</button>
        </div>
        <ul class="list" id="ylList"></ul>
        <nav class="pager" id="ylMore" aria-label="Pages"></nav>
      </div>`;
    const read = () => {
      Object.assign(prefs, { q: $("#ylQ", host).value.trim(), repo: $("#ylRepo", host).value, tag: $("#ylTag", host).value, min: Number($("#ylMin", host).value), sort: $("#ylSort", host).value });
      writeJson(KEY, prefs);
      search(1);
    };
    $("#ylQ", host).addEventListener("input", debounce(read, 250));
    ["#ylRepo", "#ylTag", "#ylMin", "#ylSort"].forEach((id) => $(id, host).addEventListener("change", read));
    $("#ylList", host).addEventListener("change", (e) => {
      const b = e.target.closest("[data-name]");
      if (!b) return;
      if (b.checked) picked.add(b.dataset.name);
      else picked.delete(b.dataset.name);
      paintPicked();
    });
    $("#ylList", host).addEventListener("click", (e) => {
      const v = e.target.closest("[data-view]");
      if (v) view(v.dataset.view);
    });
    $("#ylPage", host).addEventListener("click", () => {
      const next = rows.filter((r) => !haveRules.has(r.name) && !picked.has(r.name));
      if (!next.length) {
        toast("Every rule on this page is already selected or added", "info");
        return;
      }
      next.forEach((r) => picked.add(r.name));
      paint();
    });
    $("#ylAdd", host).addEventListener("click", () => add([...picked]));
    $("#ylMore", host).addEventListener("click", (e) => {
      const b = e.target.closest("[data-page]");
      if (b && !b.disabled) search(Number(b.dataset.page), true);
    });
    search(1);
  }

  function paintPicked() {
    const b = $("#ylAdd", host);
    if (!b) return;
    b.disabled = !picked.size;
    b.innerHTML = `${icons.upload} Add ${picked.size ? plural(picked.size, "rule") : "to YARA"}`;
  }

  function scoreBadge(s) {
    if (s == null) return "";
    return `<span class="badge ${s >= 80 ? "badge--bad" : s >= 70 ? "badge--warn" : ""}" title="YARA Forge score: how strong a match is">score ${s}</span>`;
  }

  function paint() {
    $("#ylList", host).innerHTML = rows.length
      ? rows.map((r) => {
          const own = haveRules.has(r.name);
          return `<li class="list__item lib__row">
            <input type="checkbox" data-name="${esc(r.name)}" ${picked.has(r.name) ? "checked" : ""} ${own ? "disabled" : ""} aria-label="Select ${esc(r.name)}">
            <div class="list__main">
              <div class="list__title mono yl__name">${esc(r.name)}</div>
              <div class="list__meta">${esc(r.description || "No description")}</div>
              <div class="list__meta">${esc(r.repo)}${r.author ? ` · ${esc(r.author)}` : ""}${r.date ? ` · ${esc(r.date)}` : ""}${r.tags.length ? ` · ${esc(r.tags.slice(0, 4).join(", "))}` : ""}</div>
            </div>
            ${own ? '<span class="badge badge--ok">in YARA</span>' : ""}
            ${scoreBadge(r.score)}
            <button class="btn btn--sm" type="button" data-view="${esc(r.name)}">View</button>
          </li>`;
        }).join("")
      : `<li class="list__item">${emptyState("No rules match", "Try other words or fewer filters.")}</li>`;
    $("#ylCount", host).textContent = `${total.toLocaleString()} rules match`;
    $("#ylMore", host).innerHTML = total > PAGE ? pagerHtml(page, Math.ceil(total / PAGE), total, PAGE) : "";
    paintPicked();
  }

  async function search(n = 1, scroll = false) {
    const mine = ++token;
    page = n;
    $("#ylList", host).innerHTML = skeleton.rows(8);
    if (scroll) $("#ylList", host).closest(".card")?.scrollIntoView({ block: "start", behavior: "smooth" });
    try {
      const res = await api.yaraLib.search({ q: prefs.q, repo: prefs.repo, tag: prefs.tag, min_score: prefs.min || 0, sort: prefs.sort, limit: PAGE, offset: (page - 1) * PAGE });
      if (mine !== token || !alive) return;
      total = res.total;
      rows = res.rules;
      if (!rows.length && page > 1 && total) return search(Math.ceil(total / PAGE));
      paint();
    } catch (err) {
      $("#ylList", host).innerHTML = `<li class="list__item"><div class="notice notice--bad">${esc(err.message)}</div></li>`;
    }
  }

  async function view(name) {
    let r;
    try {
      [r] = (await api.yaraLib.rules([name])).rules;
    } catch (err) {
      toast(err.message, "bad");
      return;
    }
    const own = haveRules.has(name);
    openDrawer(r.name, `
      <dl class="meta">
        <dt>Repository</dt><dd>${esc(r.repo || "unknown")}</dd>
        ${r.description ? `<dt>Description</dt><dd>${esc(r.description)}</dd>` : ""}
        ${r.author ? `<dt>Author</dt><dd>${esc(r.author)}</dd>` : ""}
        ${r.date ? `<dt>Date</dt><dd>${esc(r.date)}${r.modified && r.modified !== r.date ? `, changed ${esc(r.modified)}` : ""}</dd>` : ""}
        ${r.score != null ? `<dt>Score</dt><dd>${r.score}${r.quality != null ? ` · quality ${r.quality}` : ""}</dd>` : ""}
        ${r.tags.length ? `<dt>Tags</dt><dd><div class="tags">${r.tags.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</div></dd>` : ""}
        ${r.reference && /^https?:\/\//.test(r.reference) ? `<dt>Reference</dt><dd><a href="${esc(r.reference)}" target="_blank" rel="noopener noreferrer">${esc(r.reference)}</a></dd>` : r.reference ? `<dt>Reference</dt><dd>${esc(r.reference)}</dd>` : ""}
        ${r.source_url ? `<dt>Source</dt><dd><a class="btn btn--sm" href="${esc(r.source_url)}" target="_blank" rel="noopener noreferrer">${icons.external} Open on GitHub</a></dd>` : ""}
        ${r.license_url && r.license_url !== "N/A" ? `<dt>License</dt><dd><a href="${esc(r.license_url)}" target="_blank" rel="noopener noreferrer">${esc(r.license_url.split("/").pop())}</a></dd>` : ""}
      </dl>
      ${r.rules.length > 1 ? `<div class="notice notice--info mt-4">This rule uses ${esc(r.rules.filter((n) => n !== r.name).join(", "))}, so it is added with it.</div>` : ""}
      <div class="card mt-4"><pre class="code">${esc(r.content)}</pre></div>
      <div class="row mt-4"><div class="spacer"></div><button class="btn btn--primary" type="button" id="ylOne" ${own ? "disabled" : ""}>${own ? "Already in YARA" : `${icons.upload} Add to YARA`}</button></div>`, (panel) => {
      $("#ylOne", panel)?.addEventListener("click", async () => {
        await add([name]);
        $("#ylOne", panel).disabled = true;
        $("#ylOne", panel).textContent = "Added";
      });
    });
  }

  async function add(names) {
    if (!names.length) return;
    try {
      const res = await api.yaraLib.rules(names);
      res.rules.forEach((r) => {
        const repo = (r.repo || "yara-forge").replace(/[^\w.-]+/g, "_");
        yaraStore.upsert({ name: `yaraforge/${repo}/${r.name}.yar`, content: r.content });
      });
      haveRules = have();
      picked = new Set();
      paint();
      toast(`Added ${plural(res.rules.length, "rule")} to YARA, under yaraforge/`, "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
  }

  load();
  return {
    destroy() {
      alive = false;
      clearTimeout(poll);
    },
  };
}
