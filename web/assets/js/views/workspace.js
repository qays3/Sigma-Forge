import { api } from "../api.js";
import { state } from "../state.js";
import { store } from "../store.js";
import { $, $$, emptyState, esc, forging, icons, logo, plural, skeleton, toast } from "../ui.js";

const YAML_RE = /\.ya?ml$/i;

async function readFiles(fileList) {
  const files = Array.from(fileList).filter((f) => YAML_RE.test(f.name));
  return Promise.all(files.map(async (f) => ({ name: f.webkitRelativePath || f.name, content: await f.text() })));
}

function readEntry(entry, prefix = "") {
  return new Promise((resolve) => {
    if (entry.isFile) {
      entry.file(async (file) => {
        if (!YAML_RE.test(file.name)) return resolve([]);
        resolve([{ name: `${prefix}${file.name}`, content: await file.text() }]);
      }, () => resolve([]));
      return;
    }
    if (entry.isDirectory) {
      const reader = entry.createReader();
      const all = [];
      const readBatch = () => {
        reader.readEntries(async (entries) => {
          if (!entries.length) {
            const nested = await Promise.all(all.map((e) => readEntry(e, `${prefix}${entry.name}/`)));
            resolve(nested.flat());
            return;
          }
          all.push(...entries);
          readBatch();
        }, () => resolve([]));
      };
      readBatch();
      return;
    }
    resolve([]);
  });
}

async function readDrop(dataTransfer) {
  const items = Array.from(dataTransfer.items || []);
  const entries = items.map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null)).filter(Boolean);
  if (entries.length) return (await Promise.all(entries.map((e) => readEntry(e)))).flat();
  return readFiles(dataTransfer.files);
}

function barList(counts, total) {
  const entries = Object.entries(counts || {});
  if (!entries.length) return '<p class="muted">No data yet.</p>';
  return `<div class="bars">${entries
    .slice(0, 8)
    .map(([label, value]) => `<div class="bar"><span class="bar__label" title="${esc(label)}">${esc(label)}</span><span class="bar__track"><span class="bar__fill" data-width="${total ? Math.round((value / total) * 100) : 0}"></span></span><span class="bar__value">${value}</span></div>`)
    .join("")}</div>`;
}

function animateBars(root) {
  requestAnimationFrame(() => $$(".bar__fill", root).forEach((el) => (el.style.width = `${el.dataset.width}%`)));
}

export async function workspaceView(root) {
  root.innerHTML = `
    <section class="view">
      <div class="hero">
        ${logo(150, "hero__logo")}
        <div>
          <h1 class="hero__title">Sigma <span>Forge</span></h1>
          <p class="hero__text">Load your Sigma rules, convert them to 31 SIEM, EDR and log platforms, check them for problems, and see which MITRE ATT&amp;CK techniques they cover.</p>
          <div class="hero__chips">
            <span class="chip chip--accent">Sigma</span><span class="chip">SPL</span><span class="chip">ES|QL</span><span class="chip">KQL</span><span class="chip">LogScale</span><span class="chip">XQL</span><span class="chip">YARA-L</span><span class="chip">AQL</span><span class="chip">LogQL</span><span class="chip">SQL</span><span class="chip">and more</span><span class="chip chip--accent">ATT&amp;CK</span>
          </div>
        </div>
      </div>

      <div class="grid grid--2">
        <div class="card">
          <div class="card__head">
            <div><h2 class="card__title">Add rules</h2><div class="card__sub">Files, folders or pasted YAML. Rules stay in this browser.</div></div>
          </div>
          <div class="card__body">
            <div class="tabs" role="tablist">
              <button class="tab is-active" type="button" role="tab" data-tab="files" aria-selected="true">Files</button>
              <button class="tab" type="button" role="tab" data-tab="paste" aria-selected="false">Paste</button>
            </div>
            <div data-panel="files">
              <div class="dropzone" id="dropzone" tabindex="0" role="button" aria-label="Drop Sigma rule files here or choose files">
                ${logo(64, "dropzone__logo")}
                <div class="dropzone__title">Drop .yml files or folders here</div>
                <div class="dropzone__text">Rules are sent to your local Sigma Forge server only when you analyze or convert them.</div>
                <div class="dropzone__actions">
                  <button class="btn btn--sm" type="button" id="pickFiles">${icons.file} Choose files</button>
                  <button class="btn btn--sm" type="button" id="pickFolder">${icons.folder} Choose folder</button>
                  <button class="btn btn--sm btn--primary" type="button" id="loadSamples">${icons.spark} Load samples</button>
                </div>
              </div>
              <input class="hidden-input" type="file" id="fileInput" accept=".yml,.yaml" multiple>
              <input class="hidden-input" type="file" id="folderInput" webkitdirectory directory multiple>
            </div>
            <div data-panel="paste" hidden>
              <label class="field">
                <span class="field__label">File name</span>
                <input class="input" id="pasteName" value="pasted_rule.yml" spellcheck="false">
              </label>
              <label class="field">
                <span class="field__label">Sigma YAML</span>
                <textarea class="textarea" id="pasteBody" spellcheck="false" placeholder="title: My rule&#10;logsource:&#10;  product: windows&#10;  category: process_creation&#10;detection:&#10;  selection:&#10;    Image|endswith: '\\whoami.exe'&#10;  condition: selection"></textarea>
              </label>
              <button class="btn btn--primary" type="button" id="addPaste">Add to workspace</button>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card__head">
            <div><h2 class="card__title">Workspace files</h2><div class="card__sub" id="fileSub">Loading</div></div>
            <button class="btn btn--sm btn--ghost btn--danger" type="button" id="clearAll">${icons.trash} Clear</button>
          </div>
          <div class="card__body card__body--flush scroll" id="fileList">${skeleton.rows(6)}</div>
        </div>
      </div>

      <h2 class="section-title mt-5">Overview</h2>
      <div id="overview">${forging("Reading your rules")}${skeleton.stats(4)}${skeleton.card(4)}</div>
    </section>`;

  const fileInput = $("#fileInput", root);
  const folderInput = $("#folderInput", root);
  const dropzone = $("#dropzone", root);

  async function addFiles(files) {
    if (!files.length) {
      toast("No .yml or .yaml files found", "bad");
      return;
    }
    const added = await store.add(files);
    toast(added ? `Added ${plural(added, "file")}` : "Those files are already in the workspace", added ? "ok" : "info");
  }

  $$(".tab", root).forEach((tab) =>
    tab.addEventListener("click", () => {
      $$(".tab", root).forEach((t) => {
        t.classList.toggle("is-active", t === tab);
        t.setAttribute("aria-selected", String(t === tab));
      });
      $$("[data-panel]", root).forEach((p) => (p.hidden = p.dataset.panel !== tab.dataset.tab));
    })
  );

  $("#pickFiles", root).addEventListener("click", (e) => {
    e.stopPropagation();
    fileInput.click();
  });
  $("#pickFolder", root).addEventListener("click", (e) => {
    e.stopPropagation();
    folderInput.click();
  });
  dropzone.addEventListener("click", (e) => {
    if (e.target === dropzone || e.target.closest(".dropzone__title, .dropzone__text, svg")) fileInput.click();
  });
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });
  fileInput.addEventListener("change", async () => {
    await addFiles(await readFiles(fileInput.files));
    fileInput.value = "";
  });
  folderInput.addEventListener("change", async () => {
    await addFiles(await readFiles(folderInput.files));
    folderInput.value = "";
  });
  ["dragenter", "dragover"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.add("is-over");
    })
  );
  ["dragleave", "drop"].forEach((ev) => dropzone.addEventListener(ev, () => dropzone.classList.remove("is-over")));
  dropzone.addEventListener("drop", async (e) => {
    e.preventDefault();
    await addFiles(await readDrop(e.dataTransfer));
  });

  $("#loadSamples", root).addEventListener("click", async (e) => {
    e.stopPropagation();
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const data = await api.samples();
      await addFiles(data.rules.map((r) => ({ name: `sample/${r.name}`, content: r.content })));
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });

  $("#addPaste", root).addEventListener("click", async () => {
    const name = $("#pasteName", root).value.trim() || "pasted_rule.yml";
    const content = $("#pasteBody", root).value;
    if (!content.trim()) {
      toast("Paste a Sigma rule first", "bad");
      return;
    }
    await addFiles([{ name: YAML_RE.test(name) ? name : `${name}.yml`, content }]);
    $("#pasteBody", root).value = "";
  });

  $("#clearAll", root).addEventListener("click", async () => {
    const rules = await store.all();
    if (!rules.length) return;
    await store.clear();
    toast("Workspace cleared", "ok");
  });

  $("#fileList", root).addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-remove]");
    if (!btn) return;
    await store.remove(btn.dataset.remove);
  });

  let token = 0;
  async function refresh() {
    const my = ++token;
    const rules = await store.all();
    $("#fileSub", root).textContent = rules.length ? `${plural(rules.length, "file")} stored in this browser` : "No files yet";
    $("#fileList", root).innerHTML = rules.length
      ? `<ul class="list">${rules
          .map((r) => `<li class="list__item"><div class="list__main"><div class="list__title" title="${esc(r.name)}">${esc(r.name.split("/").pop())}</div><div class="list__meta">${esc(r.name)} · ${(r.size / 1024).toFixed(1)} KB</div></div><button class="icon-btn" type="button" data-remove="${esc(r.id)}" aria-label="Remove ${esc(r.name)}">${icons.trash}</button></li>`)
          .join("")}</ul>`
      : emptyState("Your workspace is empty", "Drop rule files, choose a folder or load the sample rules to start.");

    const overview = $("#overview", root);
    if (!rules.length) {
      overview.innerHTML = '<p class="muted">Add rules to see an overview.</p>';
      return;
    }
    overview.innerHTML = `${forging(`Checking ${plural(rules.length, "file")} with pySigma`)}${skeleton.stats(4)}${skeleton.card(4)}`;
    try {
      const { analysis } = await state.analysis();
      if (my !== token) return;
      const s = analysis.summary;
      overview.innerHTML = `
        <div class="stats">
          <div class="stat"><div class="stat__label">Rules</div><div class="stat__value">${s.rules}</div><div class="stat__hint">in ${plural(s.files, "file")}</div></div>
          <div class="stat"><div class="stat__label">Valid</div><div class="stat__value stat__value--ok">${s.valid}</div><div class="stat__hint">parsed by pySigma</div></div>
          <div class="stat"><div class="stat__label">Errors</div><div class="stat__value ${s.errors ? "stat__value--bad" : ""}">${s.errors}</div><div class="stat__hint">cannot be converted</div></div>
          <div class="stat"><div class="stat__label">With issues</div><div class="stat__value ${s.with_issues ? "stat__value--warn" : ""}">${s.with_issues}</div><div class="stat__hint">validator findings</div></div>
          <div class="stat"><div class="stat__label">Correlations</div><div class="stat__value stat__value--accent">${s.correlations || 0}</div><div class="stat__hint">meta rules</div></div>
        </div>
        <div class="grid grid--2">
          <div class="card"><div class="card__head"><h3 class="card__title">Levels</h3></div><div class="card__body">${barList(s.levels, s.valid)}</div></div>
          <div class="card"><div class="card__head"><h3 class="card__title">Log sources</h3></div><div class="card__body">${barList(s.categories, s.valid)}</div></div>
        </div>
        <div class="row mt-5">
          <a class="btn btn--primary" href="/convert" data-link>${icons.play} Convert rules</a>
          <a class="btn" href="/coverage" data-link>${icons.grid} See ATT&amp;CK coverage</a>
          <a class="btn" href="/rules" data-link>Review rules</a>
        </div>`;
      animateBars(overview);
    } catch (err) {
      if (my !== token) return;
      overview.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    }
  }

  const off = store.onChange(refresh);
  refresh();
  return { destroy: off };
}
