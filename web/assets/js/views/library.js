import { api } from "../api.js";
import { navigate, trackState } from "../router.js";
import { state } from "../state.js";
import { store } from "../store.js";
import { $, $$, debounce, emptyState, esc, forging, icons, levelBadge, logo, openDrawer, plural, skeleton, toast } from "../ui.js";

const PAGE = 50;
const LEVELS = ["critical", "high", "medium", "low", "informational"];
const STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"];

export async function libraryView(root, route) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Library</div>
          <h1>SigmaHQ rule library</h1>
          <p>Pull the full SigmaHQ rule set, search it by technique or log source, and add the rules you need to your workspace.</p>
        </div>
      </div>
      <div id="libStatus">${skeleton.card(2)}</div>
      <div id="libBody" class="mt-4"></div>
    </section>`;

  let status;
  let filters = { q: "", technique: "", level: "", product: "", category: "", service: "", status: "", group: "", ...(route.filters || {}) };
  let offset = 0;
  let rows = [];
  let total = 0;
  let picked = new Set();
  let poll = null;
  let haveNames = new Set((await state.rules()).map((r) => r.name));

  function statusCard() {
    const box = $("#libStatus", root);
    const busy = status.syncing;
    box.innerHTML = `
      <div class="card lib__status">
        <div class="lib__state">
          ${logo(44, busy ? "lib__logo is-busy" : "lib__logo")}
          <div>
            <div class="lib__title">${status.available ? `${esc(status.rules.toLocaleString())} rules${status.release ? ` · ${esc(status.release)}` : ""}` : busy ? "Downloading SigmaHQ" : "Library not synced"}</div>
            <div class="muted">${status.available ? `Synced ${esc(status.synced_at)} · ${esc(plural(status.techniques, "technique"))} tagged` : busy ? "This takes a few seconds" : "Download the latest SigmaHQ release, or upload sigma_all_rules.zip if this machine is offline."}</div>
          </div>
        </div>
        ${status.error ? `<div class="notice notice--bad lib__error">${esc(status.error)}</div>` : ""}
        <div class="row">
          <button class="btn ${status.available ? "" : "btn--primary"}" type="button" id="libSync" ${busy ? "disabled" : ""}>${icons.download} ${status.available ? "Update" : "Sync now"}</button>
          <label class="btn" for="libZip">${icons.upload} Upload zip</label>
          <input class="hidden-input" type="file" id="libZip" accept=".zip">
          ${status.available ? `<button class="btn" type="button" id="libUpdates" title="Find workspace rules that are older copies of SigmaHQ rules">${icons.spark} Check my rules for updates</button>` : ""}
        </div>
      </div>`;
    $("#libSync", box).addEventListener("click", sync);
    $("#libUpdates", box)?.addEventListener("click", checkUpdates);
    $("#libZip", box).addEventListener("change", uploadZip);
  }

  async function checkUpdates(e) {
    const btn = e.currentTarget;
    btn.disabled = true;
    const files = await state.rules();
    let res;
    try {
      res = await api.libraryUpdates(files);
    } catch (err) {
      toast(err.message, "bad");
      btn.disabled = false;
      return;
    }
    btn.disabled = false;
    const { diffHtml, diffStats, lineDiff, pushHistory } = await import("../shared.js");
    const byName = new Map(files.map((f) => [f.name, f]));
    const list = res.updates;
    const listHtml = () => list.length
      ? `<p class="muted">${esc(plural(res.checked, "workspace rule"))} match SigmaHQ rules by id. ${esc(plural(list.length, "rule"))} differ from the library copy${res.release ? ` (${esc(res.release)})` : ""}. Your old text is kept in the editor History when you update.</p>
        <div class="row mt-4"><div class="spacer"></div><button class="btn btn--primary btn--sm" type="button" id="updAll">Update all ${list.length}</button></div>
        <div class="card mt-4"><ul class="list">${list.map((u, i) => {
          const st = diffStats(lineDiff(byName.get(u.name)?.content || "", u.library_content));
          return `<li class="list__item ${u.done ? "is-off" : ""}"><div class="list__main"><div class="list__title">${esc(u.title)} ${u.newer ? '<span class="badge badge--warn">newer upstream</span>' : '<span class="badge">different</span>'}</div><div class="list__meta mono">${esc(u.name)} · yours ${esc(u.local_date || "no date")} · SigmaHQ ${esc(u.library_date || "no date")} · <span class="diff__count diff__count--add">+${st.added}</span> <span class="diff__count diff__count--del">-${st.removed}</span></div></div><button class="btn btn--sm" type="button" data-diff="${i}">Diff</button><button class="btn btn--sm" type="button" data-upd="${i}" ${u.done ? "disabled" : ""}>${u.done ? "Updated" : "Update"}</button></li>`;
        }).join("")}</ul></div>`
      : `<div class="notice notice--ok">${res.checked ? `All ${esc(plural(res.checked, "rule"))} that come from SigmaHQ match the library.` : "None of your workspace rules come from SigmaHQ (no matching ids)."}</div>`;
    const apply = async (u) => {
      const f = byName.get(u.name);
      if (!f || u.done) return;
      pushHistory(f.name, f.content, "before SigmaHQ update");
      await store.replace(f.id, { name: f.name, content: u.library_content });
      u.done = true;
    };
    const bind = (panel) => {
      panel.onclick = async (ev) => {
        const d = ev.target.closest("[data-diff]");
        const up = ev.target.closest("[data-upd]");
        if (ev.target.closest("[data-back]")) {
          setBody(listHtml());
          return;
        }
        if (d) {
          const u = list[Number(d.dataset.diff)];
          const rows = lineDiff(byName.get(u.name)?.content || "", u.library_content);
          setBody(`<div class="row"><button class="btn btn--sm" type="button" data-back>Back</button><span class="muted">Your copy to the SigmaHQ copy</span></div><div class="card mt-4">${diffHtml(rows)}</div>`);
          return;
        }
        if (up) {
          await apply(list[Number(up.dataset.upd)]);
          toast("Rule updated from SigmaHQ", "ok");
          setBody(listHtml());
          return;
        }
        if (ev.target.closest("#updAll")) {
          for (const u of list) await apply(u);
          toast(`Updated ${plural(list.length, "rule")} from SigmaHQ`, "ok");
          setBody(listHtml());
        }
      };
    };
    const { setDrawerBody } = await import("../ui.js");
    const setBody = (html) => setDrawerBody(html, bind);
    openDrawer("SigmaHQ updates", listHtml(), bind);
  }

  async function loadStatus() {
    status = await api.library.status();
    statusCard();
    if (status.syncing) {
      clearTimeout(poll);
      poll = setTimeout(loadStatus, 1500);
    } else if (status.available) {
      if (!$("#libQ", root)) buildBrowser();
    } else {
      $("#libBody", root).innerHTML = `<div class="card">${emptyState("Nothing here yet", "Sync the SigmaHQ library to browse more than 3,000 community rules.")}</div>`;
    }
  }

  async function sync() {
    try {
      status = await api.library.sync();
      statusCard();
      loadStatus();
    } catch (err) {
      toast(err.message, "bad");
    }
  }

  async function uploadZip(e) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    $("#libStatus", root).innerHTML = forging(`Reading ${file.name}`);
    try {
      status = await api.library.upload(file);
      toast(`Library loaded with ${status.rules} rules`, "ok");
      $("#libBody", root).innerHTML = "";
    } catch (err) {
      toast(err.message, "bad");
    }
    loadStatus();
  }

  function optionList(values, label, current) {
    return `<option value="">${esc(label)}</option>${values.map((v) => `<option value="${esc(v)}" ${v === current ? "selected" : ""}>${esc(v)}</option>`).join("")}`;
  }

  function buildBrowser() {
    const products = (status.products || []).map((p) => p.name);
    const groups = Object.keys(status.groups || {});
    $("#libBody", root).innerHTML = `
      <div class="toolbar">
        <input class="input toolbar__grow" type="search" id="libQ" placeholder="Search title, id, path, description" aria-label="Search library" value="${esc(filters.q)}">
        <input class="input input--sm lib__tech" id="libTech" placeholder="T1059" aria-label="Technique" value="${esc(filters.technique)}">
        <select class="select" id="libProduct" aria-label="Product">${optionList(products, "Any product", filters.product)}</select>
        <input class="input input--sm" id="libCategory" placeholder="category" aria-label="Category" value="${esc(filters.category)}">
        <select class="select" id="libLevel" aria-label="Level">${optionList(LEVELS, "Any level", filters.level)}</select>
        <select class="select" id="libStatusSel" aria-label="Status">${optionList(STATUSES, "Any status", filters.status)}</select>
        ${groups.length > 1 ? `<select class="select" id="libGroup" aria-label="Folder">${optionList(groups, "All folders", filters.group)}</select>` : ""}
      </div>
      <div class="card">
        <div class="card__head">
          <span class="card__sub" id="libCount"></span>
          <div class="spacer"></div>
          <button class="btn btn--sm" type="button" id="libPickPage">Select page</button>
          <button class="btn btn--sm btn--primary" type="button" id="libAdd" disabled>${icons.upload} Add to workspace</button>
        </div>
        <ul class="list" id="libList"></ul>
        <div class="card__body lib__more" id="libMore"></div>
      </div>`;
    const read = () => {
      filters = {
        q: $("#libQ", root).value.trim(),
        technique: $("#libTech", root).value.trim(),
        product: $("#libProduct", root).value,
        category: $("#libCategory", root).value.trim().toLowerCase(),
        level: $("#libLevel", root).value,
        status: $("#libStatusSel", root).value,
        group: $("#libGroup", root)?.value || "",
        service: filters.service,
      };
      trackState({ filters });
      search(true);
    };
    const later = debounce(read, 250);
    ["#libQ", "#libTech", "#libCategory"].forEach((id) => $(id, root).addEventListener("input", later));
    ["#libProduct", "#libLevel", "#libStatusSel", "#libGroup"].forEach((id) => $(id, root)?.addEventListener("change", read));
    $("#libList", root).addEventListener("change", (e) => {
      const box = e.target.closest("[data-path]");
      if (!box) return;
      if (box.checked) picked.add(box.dataset.path);
      else picked.delete(box.dataset.path);
      paintPicked();
    });
    $("#libList", root).addEventListener("click", (e) => {
      const btn = e.target.closest("[data-view]");
      if (btn) showRule(btn.dataset.view);
    });
    $("#libPickPage", root).addEventListener("click", () => {
      rows.forEach((r) => !haveNames.has(`sigmahq/${r.path}`) && picked.add(r.path));
      paintRows();
    });
    $("#libAdd", root).addEventListener("click", () => addRules([...picked]));
    $("#libMore", root).addEventListener("click", (e) => {
      if (e.target.closest("#libLoadMore")) search(false);
    });
    search(true);
  }

  function paintPicked() {
    const btn = $("#libAdd", root);
    if (!btn) return;
    btn.disabled = !picked.size;
    btn.innerHTML = `${icons.upload} Add ${picked.size ? plural(picked.size, "rule") : "to workspace"}`;
  }

  function paintRows() {
    $("#libList", root).innerHTML = rows.length
      ? rows
          .map((r) => {
            const have = haveNames.has(`sigmahq/${r.path}`);
            const ls = [r.product, r.category || r.service].filter(Boolean).join(" / ");
            return `<li class="list__item lib__row">
              <input type="checkbox" data-path="${esc(r.path)}" ${picked.has(r.path) ? "checked" : ""} ${have ? "disabled" : ""} aria-label="Select ${esc(r.title)}">
              <div class="list__main">
                <div class="list__title">${esc(r.title)}${r.correlation ? ' <span class="badge badge--accent">correlation</span>' : ""}</div>
                <div class="list__meta">${esc(ls || "any log source")} · ${esc(r.status || "no status")}${r.techniques.length ? ` · ${esc(r.techniques.slice(0, 4).join(", "))}${r.techniques.length > 4 ? "…" : ""}` : ""}</div>
              </div>
              ${have ? '<span class="badge badge--ok">in workspace</span>' : ""}
              ${levelBadge(r.level)}
              <button class="btn btn--sm" type="button" data-view="${esc(r.path)}">View</button>
            </li>`;
          })
          .join("")
      : `<li class="list__item">${emptyState("No rules match", "Try fewer filters or another technique id.")}</li>`;
    $("#libCount", root).textContent = `${total.toLocaleString()} rules match`;
    $("#libMore", root).innerHTML = rows.length < total ? `<button class="btn" type="button" id="libLoadMore">Show ${Math.min(PAGE, total - rows.length)} more</button>` : "";
    paintPicked();
  }

  let token = 0;
  async function search(reset) {
    const mine = ++token;
    if (reset) {
      offset = 0;
      rows = [];
      $("#libList", root).innerHTML = skeleton.rows(8);
    }
    try {
      const res = await api.library.search({ ...filters, limit: PAGE, offset });
      if (mine !== token) return;
      total = res.total;
      rows = reset ? res.rules : rows.concat(res.rules);
      offset = rows.length;
      paintRows();
    } catch (err) {
      $("#libList", root).innerHTML = `<li class="list__item"><div class="notice notice--bad">${esc(err.message)}</div></li>`;
    }
  }

  async function addRules(paths) {
    if (!paths.length) return;
    try {
      const { rules } = await api.library.rules(paths);
      const added = await store.add(rules);
      haveNames = new Set((await state.rules()).map((r) => r.name));
      picked = new Set();
      paintRows();
      toast(`Added ${plural(added, "rule")} to the workspace`, "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
  }

  async function showRule(path) {
    const row = rows.find((r) => r.path === path);
    openDrawer(row?.title || path, forging("Opening rule"), async (panel) => {
      try {
        const { rules } = await api.library.rules([path]);
        const have = haveNames.has(`sigmahq/${path}`);
        panel.innerHTML = `
          <dl class="meta">
            <dt>Path</dt><dd class="mono">${esc(path)}</dd>
            <dt>Level</dt><dd>${levelBadge(row?.level)}</dd>
            <dt>Status</dt><dd>${esc(row?.status || "")}</dd>
            <dt>Techniques</dt><dd>${(row?.techniques || []).map((t) => `<span class="chip">${esc(t)}</span>`).join(" ") || "none"}</dd>
            <dt>Author</dt><dd>${esc(row?.author || "")}</dd>
          </dl>
          ${row?.description ? `<p>${esc(row.description)}</p>` : ""}
          <div class="row">
            <button class="btn btn--primary" type="button" id="libAddOne" ${have ? "disabled" : ""}>${icons.upload} ${have ? "Already in workspace" : "Add to workspace"}</button>
            <button class="btn" type="button" id="libEdit">Open in editor</button>
          </div>
          <div class="card mt-4"><pre class="code code--tall">${esc(rules[0].content)}</pre></div>`;
        $("#libAddOne", panel)?.addEventListener("click", async () => {
          await addRules([path]);
          document.querySelector("#drawer [data-close]")?.click();
        });
        $("#libEdit", panel).addEventListener("click", async () => {
          await addRules([path]);
          navigate("/editor", { file: `sigmahq/${path}` });
        });
      } catch (err) {
        panel.innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
      }
    });
  }

  try {
    await loadStatus();
  } catch (err) {
    $("#libStatus", root).innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
  }
  return {
    destroy() {
      clearTimeout(poll);
    },
  };
}
