import { api } from "../api.js";
import { fileChips } from "../shared.js";
import { $, debounce, download, emptyState, esc, forging, icons, logo, plural, skeleton, toast } from "../ui.js";
import { b64File, renderYaraScan, yaraStore } from "./yarakit.js";

const TEMPLATE = `rule New_Rule
{
    meta:
        description = "What this rule finds"
        author = "Your name"
        date = "${new Date().toISOString().slice(0, 10)}"
    strings:
        $a = "suspicious text" ascii wide nocase
        $b = { 4D 5A 90 00 }
    condition:
        any of them
}
`;

let scanFiles = [];
let lastScan = null;

export async function yaraView(root) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">YARA</div>
          <h1>Write, check and run YARA rules</h1>
          <p>Keep YARA rules next to your Sigma rules. Check them with the real YARA engine, then scan files you drop here or whole folders from the Hunt page.</p>
        </div>
        <div class="page-head__side" id="yaraStatus"></div>
      </div>
      <div class="card yara">
        <div class="yara__head">
          <div class="yara__tabs" id="yList" role="tablist" aria-label="YARA rule files"></div>
          <div class="yara__tools">
            <button class="btn btn--sm" type="button" id="yNew">${icons.file} New</button>
            <button class="btn btn--sm" type="button" id="yImport">${icons.upload} Import</button>
            <button class="btn btn--sm btn--primary" type="button" id="ySamples">${icons.spark} Load samples</button>
          </div>
          <input class="hidden-input" type="file" id="yInput" accept=".yar,.yara,.txt" multiple>
        </div>
        <div class="editor__bar">
          <input class="input editor__name" id="yName" aria-label="File name" spellcheck="false">
          <span class="muted" id="yaraCount"></span>
          <div class="spacer"></div>
          <button class="btn btn--sm" type="button" id="yDownload">${icons.download} Download</button>
          <button class="btn btn--sm btn--ghost" type="button" id="yDelete">${icons.trash} Delete</button>
          <button class="btn btn--sm btn--primary" type="button" id="ySave">${icons.file} Save</button>
        </div>
        <div class="editor__area yara__area">
          <pre class="editor__gutter" id="yGutter" aria-hidden="true"></pre>
          <textarea class="editor__text" id="yText" spellcheck="false" autocapitalize="off" autocomplete="off" wrap="off" aria-label="YARA rule"></textarea>
        </div>
        <div class="editor__status" id="yCheck"></div>
      </div>
      <h2 class="section-title mt-5">Scan files</h2>
      <div class="card setup setup--stack">
        <div class="setup__grid">
          <label class="dropzone dropzone--row" id="yDrop" for="yScanInput">
            ${logo(40, "dropzone__logo")}
            <span class="dropzone__body"><span class="dropzone__title">Drop files to scan</span><span class="dropzone__text">Any file type, up to 64 MB in total</span></span>
            <input class="hidden-input" type="file" id="yScanInput" multiple>
          </label>
          <ul class="filechips filechips--box" id="yFileList"></ul>
        </div>
        <div class="setup__bar">
          <button class="btn btn--sm" type="button" id="ySampleFiles">${icons.spark} Sample files</button>
          <button class="btn btn--sm btn--ghost" type="button" id="yClearFiles">${icons.trash} Clear</button>
          <a class="btn btn--sm" href="/hunt" data-link>${icons.folder} Scan a folder on this machine</a>
          <div class="spacer"></div>
          <button class="btn btn--primary" type="button" id="yScan">${icons.play} Scan with all rules</button>
        </div>
      </div>
      <div id="yOut" class="mt-5"></div>
    </section>`;

  let files = yaraStore.all();
  let current = files[0]?.name || "";
  const text = $("#yText", root);
  const nameInput = $("#yName", root);
  const out = $("#yOut", root);

  const status = await api.yara.status().catch(() => ({ available: false, message: "Server offline" }));
  $("#yaraStatus", root).innerHTML = status.available
    ? `<span class="badge badge--ok">YARA ${esc(status.version)}</span>`
    : `<span class="badge badge--bad" title="${esc(status.message || "")}">YARA not installed</span>`;

  function paintGutter() {
    const lines = text.value.split("\n").length;
    let g = "";
    for (let i = 1; i <= lines; i += 1) g += `${i}\n`;
    $("#yGutter", root).textContent = g;
    $("#yGutter", root).scrollTop = text.scrollTop;
  }
  text.addEventListener("scroll", () => ($("#yGutter", root).scrollTop = text.scrollTop));

  function paintList() {
    $("#yaraCount", root).textContent = plural(files.length, "file");
    const ruleCount = (f) => (f.content.match(/^\s*(?:private\s+|global\s+)*rule\s+\w+/gm) || []).length;
    $("#yList", root).innerHTML = files.length
      ? files.map((f) => `<button class="ytab ${f.name === current ? "is-active" : ""}" type="button" role="tab" aria-selected="${f.name === current}" data-open="${esc(f.name)}"><span class="ytab__name">${esc(f.name)}</span><span class="ytab__count">${ruleCount(f)}</span></button>`).join("") + (current ? "" : '<span class="ytab is-active is-new"><span class="ytab__name">unsaved</span></span>')
      : '<span class="muted yara__empty">No YARA files yet. Press New or Load samples.</span>';
  }

  function open(name) {
    const f = files.find((x) => x.name === name);
    current = f ? f.name : "";
    nameInput.value = f ? f.name : "new_rule.yar";
    text.value = f ? f.content : TEMPLATE;
    paintList();
    paintGutter();
    check();
  }

  async function check() {
    const box = $("#yCheck", root);
    if (!text.value.trim()) {
      box.innerHTML = "";
      return;
    }
    if (!status.available) {
      box.innerHTML = `<span class="badge badge--bad">not checked</span><span>${esc(status.message || "Install yara-python to check rules")}</span>`;
      return;
    }
    try {
      const res = await api.yara.check([{ name: nameInput.value || "rule.yar", content: text.value }]);
      const f = res.files[0];
      box.innerHTML = f.ok
        ? `<span class="badge badge--ok">valid</span><span>${esc(plural(f.rules.length, "rule"))}: ${f.rules.map((r) => `<span class="mono">${esc(r.name)}</span> (${esc(plural(r.strings, "string"))})`).join(", ")}</span>`
        : `<span class="badge badge--bad">error</span><span>${f.line ? `line ${f.line}: ` : ""}${esc(f.error)}</span>`;
    } catch (err) {
      box.innerHTML = `<span class="badge badge--bad">error</span><span>${esc(err.message)}</span>`;
    }
  }
  const later = debounce(check, 450);
  text.addEventListener("input", () => {
    paintGutter();
    later();
  });
  text.addEventListener("keydown", (e) => {
    if (e.key === "Tab" && !e.shiftKey) {
      e.preventDefault();
      text.setRangeText("    ", text.selectionStart, text.selectionEnd, "end");
      text.dispatchEvent(new Event("input"));
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      save();
    }
  });

  function cleanName() {
    const n = (nameInput.value.trim() || "new_rule.yar").replace(/[\\/]+/g, "_");
    return /\.(yar|yara)$/i.test(n) ? n : `${n}.yar`;
  }

  function save() {
    const name = cleanName();
    if (current && current !== name) files = yaraStore.remove(current);
    files = yaraStore.upsert({ name, content: text.value });
    current = name;
    nameInput.value = name;
    paintList();
    toast(`Saved ${name}`, "ok");
  }

  $("#ySave", root).addEventListener("click", save);
  $("#yNew", root).addEventListener("click", () => {
    current = "";
    nameInput.value = `rule_${files.length + 1}.yar`;
    text.value = TEMPLATE;
    paintList();
    paintGutter();
    check();
  });
  $("#yDelete", root).addEventListener("click", () => {
    if (!current) return;
    files = yaraStore.remove(current);
    toast(`Deleted ${current}`, "ok");
    open(files[0]?.name || "");
  });
  $("#yDownload", root).addEventListener("click", () => download(cleanName(), text.value));
  $("#yImport", root).addEventListener("click", () => $("#yInput", root).click());
  $("#yInput", root).addEventListener("change", async (e) => {
    const list = Array.from(e.target.files || []);
    for (const f of list) files = yaraStore.upsert({ name: f.name.replace(/\.txt$/i, ".yar"), content: await f.text() });
    e.target.value = "";
    toast(`Imported ${plural(list.length, "file")}`, "ok");
    open(list.length ? list[list.length - 1].name.replace(/\.txt$/i, ".yar") : current);
  });
  $("#ySamples", root).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const res = await yaraStore.loadSamples();
      files = res.list;
      toast(`Loaded ${plural(res.list.length, "YARA file")}`, "ok");
      open(files[0]?.name || "");
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });
  $("#yList", root).addEventListener("click", (e) => {
    const btn = e.target.closest("[data-open]");
    if (btn) open(btn.dataset.open);
  });

  function paintFiles() {
    $("#yFileList", root).innerHTML = fileChips(scanFiles, "No files yet");
  }
  function addScan(list) {
    Array.from(list || []).forEach((f) => {
      scanFiles = scanFiles.filter((x) => x.name !== f.name);
      scanFiles.push(f);
    });
    paintFiles();
  }
  const drop = $("#yDrop", root);
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.add("is-over"))));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.remove("is-over"))));
  drop.addEventListener("drop", (e) => addScan(e.dataTransfer.files));
  $("#yScanInput", root).addEventListener("change", (e) => {
    addScan(e.target.files);
    e.target.value = "";
  });
  $("#yFileList", root).addEventListener("click", (e) => {
    const btn = e.target.closest("[data-drop]");
    if (!btn) return;
    scanFiles.splice(Number(btn.dataset.drop), 1);
    paintFiles();
  });
  $("#yClearFiles", root).addEventListener("click", () => {
    scanFiles = [];
    paintFiles();
  });
  $("#ySampleFiles", root).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const data = await api.yara.samples();
      addScan(data.files.map(b64File));
      toast(`Loaded ${plural(data.files.length, "sample file")}`, "ok");
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });
  $("#yScan", root).addEventListener("click", async (e) => {
    if (!files.length) {
      toast("Save or load a YARA rule first", "bad");
      return;
    }
    if (!scanFiles.length) {
      toast("Add files to scan", "bad");
      return;
    }
    const btn = e.currentTarget;
    btn.disabled = true;
    out.innerHTML = `${forging(`Scanning ${plural(scanFiles.length, "file")} with ${plural(files.length, "rule file")}`)}${skeleton.stats(3)}${skeleton.rows(4)}`;
    try {
      lastScan = await api.yara.scan(files, scanFiles);
      renderYaraScan(out, lastScan, "Files scanned");
    } catch (err) {
      out.innerHTML = `<div class="card"><div class="notice notice--bad">${esc(err.message)}</div></div>`;
    } finally {
      btn.disabled = false;
    }
  });

  paintFiles();
  open(current);
  if (lastScan) renderYaraScan(out, lastScan, "Files scanned");
  else out.innerHTML = `<div class="card">${emptyState("Nothing scanned yet", "Load the sample rules and sample files, then press Scan with all rules.")}</div>`;
  return null;
}
