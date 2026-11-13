import { state } from "../state.js";
import { store } from "../store.js";
import { $, debounce, esc, icons } from "../ui.js";
import { addRulesDrawer } from "./addrules.js";
import { editorView } from "./editor.js";

const CLOSED_KEY = "sigma-forge-sigma-closed";
const meta = (content) => {
  const get = (k) => (content.match(new RegExp(`^${k}:\\s*['"]?(.+?)['"]?\\s*$`, "m")) || [])[1] || "";
  const tags = [...content.matchAll(/^\s*-\s*(attack\.[\w.]+)/gm)].map((m) => m[1]);
  return { title: get("title"), level: get("level").toLowerCase(), status: get("status"), id: get("id"), tags };
};

export async function sigmaFilesView(root, route) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Sigma rules</div>
          <h1>Write, check and manage your Sigma rules</h1>
          <p>Pick a file on the left to open it in the editor. Checks, ATT&amp;CK mapping and the query for any platform update as you type.</p>
        </div>
      </div>
      <div class="sx">
        <aside class="card yfiles sx__files" aria-label="Sigma rule files">
          <div class="yfiles__tools">
            <button class="btn btn--sm" type="button" id="sxNew">${icons.file} New</button>
            <button class="btn btn--sm btn--primary" type="button" id="sxAdd" title="Upload files or folders, paste YAML, pull from GitHub, samples, SIEM exports or CTI feeds">${icons.upload} Add rules</button>
          </div>
          <div class="yfiles__search">
            <input class="input input--sm" type="search" id="sxFind" placeholder="Search name, title, id, tag" aria-label="Search Sigma files" spellcheck="false">
          </div>
          <div class="yfiles__filters">
            <select class="select select--sm" id="sxLevel" aria-label="Level"><option value="">Any level</option>${["critical", "high", "medium", "low", "informational"].map((l) => `<option>${l}</option>`).join("")}</select>
          </div>
          <div class="yfiles__sum muted" id="sxSum"></div>
          <div class="yfiles__list" id="sxList" role="tree"></div>
        </aside>
        <div class="sx__editor" id="sxEditor"></div>
      </div>
    </section>`;

  let files = await state.rules();
  let current = { id: "", name: "" };
  const closed = new Set(JSON.parse(sessionStorage.getItem(CLOSED_KEY) || "[]"));
  const list = $("#sxList", root);

  let alive = true;
  function paint() {
    if (!alive || !root.contains(list)) return;
    const q = $("#sxFind", root).value.trim().toLowerCase();
    const lvl = $("#sxLevel", root).value;
    const rows = files.map((f) => ({ f, m: meta(f.content) })).filter(({ f, m }) => {
      if (lvl && m.level !== lvl) return false;
      if (!q) return true;
      return [f.name, m.title, m.id, m.tags.join(" ")].join(" ").toLowerCase().includes(q);
    });
    $("#sxSum", root).textContent = q || lvl ? `${rows.length} of ${files.length} files match` : `${files.length} files`;
    const groups = new Map();
    rows.forEach((r) => {
      const i = r.f.name.lastIndexOf("/");
      const dir = i > 0 ? r.f.name.slice(0, i) : "";
      if (!groups.has(dir)) groups.set(dir, []);
      groups.get(dir).push(r);
    });
    const hl = (t) => {
      if (!q) return esc(t);
      const i = t.toLowerCase().indexOf(q);
      return i < 0 ? esc(t) : `${esc(t.slice(0, i))}<mark>${esc(t.slice(i, i + q.length))}</mark>${esc(t.slice(i + q.length))}`;
    };
    const active = (f) => (current.id ? f.id === current.id : f.name === current.name);
    const item = ({ f, m }) => {
      const base = f.name.slice(f.name.lastIndexOf("/") + 1);
      return `<button class="yfile sx__file ${active(f) ? "is-active" : ""}" type="button" role="treeitem" aria-selected="${active(f)}" data-id="${esc(f.id)}" title="${esc(m.title || f.name)}"><span class="sx__dot sx__dot--${esc(m.level || "none")}" aria-hidden="true"></span><span class="sx__text"><span class="yfile__name">${hl(base)}</span>${m.title ? `<span class="sx__title">${hl(m.title)}</span>` : ""}</span></button>`;
    };
    const dirs = [...groups.keys()].sort((a, b) => (a === "" ? -1 : b === "" ? 1 : a.localeCompare(b)));
    list.innerHTML = rows.length
      ? dirs.map((d) => d === "" ? groups.get(d).map(item).join("") : `<details class="ydir" data-dir="${esc(d)}" ${closed.has(d) && !q && !lvl ? "" : "open"}><summary class="ydir__head"><svg class="ydir__icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h6l2 2h10v11H3z"/></svg><span class="ydir__name">${esc(d)}</span><span class="yfile__count">${groups.get(d).length}</span></summary><div class="ydir__body">${groups.get(d).map(item).join("")}</div></details>`).join("")
      : `<p class="muted yara__empty">${files.length ? "No file matches." : "No Sigma rules yet. Press Add rules to upload files or folders, paste YAML, pull from GitHub or load samples."}</p>`;
  }

  const editor = await editorView($("#sxEditor", root), route, {
    embedded: true,
    onChange(id, name) {
      current = { id, name };
      paint();
    },
  });

  list.addEventListener("click", (e) => {
    const b = e.target.closest("[data-id]");
    if (!b) return;
    const f = files.find((x) => x.id === b.dataset.id);
    if (f) editor.open(f);
  });
  list.addEventListener("toggle", (e) => {
    const d = e.target.closest("[data-dir]");
    if (!d || !alive || !$("#sxFind", root) || $("#sxFind", root).value.trim() || $("#sxLevel", root).value) return;
    if (d.open) closed.delete(d.dataset.dir);
    else closed.add(d.dataset.dir);
    sessionStorage.setItem(CLOSED_KEY, JSON.stringify([...closed]));
  }, true);
  $("#sxFind", root).addEventListener("input", debounce(paint, 120));
  $("#sxAdd", root).addEventListener("click", () => addRulesDrawer("sigma"));
  $("#sxLevel", root).addEventListener("change", paint);
  $("#sxNew", root).addEventListener("click", () => {
    const sel = $("#edTemplate", root);
    if (sel && sel.options.length > 1) {
      sel.value = sel.options[1].value;
      sel.dispatchEvent(new Event("change"));
    }
  });
  const off = store.onChange(async () => {
    files = await state.rules();
    paint();
  });
  paint();
  return {
    destroy() {
      off();
      editor?.destroy();
      alive = false;
    },
  };
}
