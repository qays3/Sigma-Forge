import { api } from "../api.js";
import { readJson, writeJson } from "../shared.js";
import { store } from "../store.js";
import { $, $$, esc, icons, logo, openDrawer, plural, toast } from "../ui.js";
import { ctiDrawer, importSiemDrawer } from "./tools.js";
import { yaraStore } from "./yarakit.js";

const KIND = {
  sigma: { ext: /\.ya?ml$/i, accept: ".yml,.yaml", label: "Sigma", files: ".yml or .yaml", git: "sigma-forge-git", paste: "pasted_rule.yml", fix: (n) => (/\.ya?ml$/i.test(n) ? n : `${n}.yml`) },
  yara: { ext: /\.(yar|yara|txt)$/i, accept: ".yar,.yara,.txt", label: "YARA", files: ".yar, .yara or .txt", git: "sigma-forge-git-yara", paste: "pasted_rule.yar", fix: (n) => n.replace(/\.txt$/i, ".yar").replace(/^(?!.*\.(yar|yara)$)(.+)$/i, "$2.yar") },
};

function readEntry(entry, ext, prefix = "") {
  return new Promise((resolve) => {
    if (entry.isFile) {
      entry.file(async (file) => (ext.test(file.name) ? resolve([{ name: `${prefix}${file.name}`, content: await file.text() }]) : resolve([])), () => resolve([]));
      return;
    }
    if (entry.isDirectory) {
      const reader = entry.createReader();
      const all = [];
      const batch = () => reader.readEntries(async (entries) => {
        if (!entries.length) {
          resolve((await Promise.all(all.map((e) => readEntry(e, ext, `${prefix}${entry.name}/`)))).flat());
          return;
        }
        all.push(...entries);
        batch();
      }, () => resolve([]));
      batch();
      return;
    }
    resolve([]);
  });
}

async function readList(list, ext) {
  return Promise.all(Array.from(list).filter((f) => ext.test(f.name)).map(async (f) => ({ name: f.webkitRelativePath || f.name, content: await f.text() })));
}

async function readDrop(dt, ext) {
  const entries = Array.from(dt.items || []).map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null)).filter(Boolean);
  if (entries.length) return (await Promise.all(entries.map((e) => readEntry(e, ext)))).flat();
  return readList(dt.files, ext);
}

export function addRulesDrawer(kind, onDone) {
  const k = KIND[kind];
  const sigma = kind === "sigma";
  const save = async (files, scope = "") => {
    if (!files.length) {
      toast(`No ${k.files} files found`, "bad");
      return 0;
    }
    if (sigma) {
      const removed = scope ? await store.removeWhere((r) => r.name.startsWith(scope)) : 0;
      const added = await store.add(files);
      toast(removed ? `Synced ${plural(files.length, "rule")}, replaced ${removed} old` : added ? `Added ${plural(added, "file")}` : "Those files are already in the workspace", added || removed ? "ok" : "info");
      onDone?.(files[files.length - 1]?.name);
      return added;
    }
    if (scope) yaraStore.all().filter((f) => f.name.startsWith(scope)).forEach((f) => yaraStore.remove(f.name));
    files.forEach((f) => yaraStore.upsert({ name: k.fix(f.name), content: f.content }));
    toast(`Added ${plural(files.length, "YARA file")}`, "ok");
    onDone?.(k.fix(files[files.length - 1].name));
    return files.length;
  };

  openDrawer(`Add ${k.label} rules`, `
    <div class="tabs" role="tablist" id="arTabs">
      <button class="tab is-active" type="button" data-ar="files">Files</button>
      <button class="tab" type="button" data-ar="paste">Paste</button>
      <button class="tab" type="button" data-ar="git">GitHub</button>
      <button class="tab" type="button" data-ar="more">More</button>
    </div>
    <div data-arp="files">
      <div class="dropzone" id="arDrop" tabindex="0" role="button" aria-label="Drop ${k.label} files or folders here">
        ${logo(56, "dropzone__logo")}
        <div class="dropzone__title">Drop ${esc(k.files)} files or folders here</div>
        <div class="dropzone__text">Folders keep their structure, so files show grouped in the file list.</div>
        <div class="dropzone__actions">
          <button class="btn btn--sm" type="button" id="arPickFiles">${icons.file} Choose files</button>
          <button class="btn btn--sm" type="button" id="arPickFolder">${icons.folder} Choose folder</button>
        </div>
      </div>
      <input class="hidden-input" type="file" id="arFiles" accept="${k.accept}" multiple>
      <input class="hidden-input" type="file" id="arFolder" webkitdirectory directory multiple>
    </div>
    <div data-arp="paste" hidden>
      <label class="field"><span class="field__label">File name (use folder/name to put it in a folder)</span><input class="input mono" id="arName" value="${esc(k.paste)}" spellcheck="false"></label>
      <label class="field"><span class="field__label">${k.label} rule</span><textarea class="textarea mono" id="arBody" rows="12" spellcheck="false"></textarea></label>
      <button class="btn btn--primary" type="button" id="arPaste">${icons.upload} Add</button>
    </div>
    <div data-arp="git" hidden>
      <p class="muted">Pull ${k.label} rules from a public GitHub repository. Paste owner/repo or a link to a folder. Saved sources can be synced again later.</p>
      <label class="field"><span class="field__label">Repository</span><input class="input mono" id="arRepo" placeholder="${sigma ? "SigmaHQ/sigma" : "Neo23x0/signature-base"} or a github.com link" spellcheck="false"></label>
      <div class="grid grid--2">
        <label class="field"><span class="field__label">Branch or tag (optional)</span><input class="input mono" id="arRef" placeholder="main" spellcheck="false"></label>
        <label class="field"><span class="field__label">Folder (optional)</span><input class="input mono" id="arPath" placeholder="${sigma ? "rules/windows" : "yara"}" spellcheck="false"></label>
      </div>
      <div class="row"><button class="btn btn--primary" type="button" id="arGit">${icons.download} Fetch rules</button><span class="muted" id="arGitMsg"></span></div>
      <div id="arSources" class="mt-4"></div>
    </div>
    <div data-arp="more" hidden>
      <div class="ar__more">
        <button class="btn" type="button" id="arSamples">${icons.spark} Load samples</button>
        ${sigma ? `<button class="btn btn--ghost" type="button" id="arBroken" title="Rules with errors on purpose">Load error samples</button>
        <button class="btn" type="button" id="arSiem">${icons.upload} From a SIEM export</button>
        <button class="btn" type="button" id="arCti">${icons.download} From CTI feeds</button>` : ""}
        <a class="btn" href="/library" data-link id="arLib">${icons.download} ${sigma ? "SigmaHQ" : "YARA Forge"} library</a>
      </div>
    </div>`, (panel) => {
    $("#arTabs", panel).addEventListener("click", (e) => {
      const t = e.target.closest("[data-ar]");
      if (!t) return;
      $$("#arTabs .tab", panel).forEach((x) => x.classList.toggle("is-active", x === t));
      $$("[data-arp]", panel).forEach((p) => (p.hidden = p.dataset.arp !== t.dataset.ar));
    });
    const drop = $("#arDrop", panel);
    $("#arPickFiles", panel).addEventListener("click", (e) => {
      e.stopPropagation();
      $("#arFiles", panel).click();
    });
    $("#arPickFolder", panel).addEventListener("click", (e) => {
      e.stopPropagation();
      $("#arFolder", panel).click();
    });
    drop.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        $("#arFiles", panel).click();
      }
    });
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.add("is-over"))));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove("is-over")));
    drop.addEventListener("drop", async (e) => {
      e.preventDefault();
      await save(await readDrop(e.dataTransfer, k.ext));
    });
    ["#arFiles", "#arFolder"].forEach((id) => $(id, panel).addEventListener("change", async (e) => {
      await save(await readList(e.target.files, k.ext));
      e.target.value = "";
    }));
    $("#arPaste", panel).addEventListener("click", async () => {
      const content = $("#arBody", panel).value;
      if (!content.trim()) {
        toast(`Paste a ${k.label} rule first`, "bad");
        return;
      }
      const name = ($("#arName", panel).value.trim() || k.paste).replace(/\\+/g, "/").split("/").filter((p) => p && p !== "." && p !== "..").join("/");
      await save([{ name: k.fix(name), content }]);
      $("#arBody", panel).value = "";
    });

    const sources = () => readJson(k.git, []);
    const paintSources = () => {
      const list = sources();
      $("#arSources", panel).innerHTML = list.length
        ? `<div class="field__label">Saved sources</div><div class="card"><ul class="list">${list.map((s, i) => `<li class="list__item"><div class="list__main"><div class="list__title mono">${esc(s.repo)}${s.path ? `/${esc(s.path)}` : ""}</div><div class="list__meta">${esc(s.ref || "default branch")} · ${esc(plural(s.count || 0, "rule"))}${s.synced ? ` · synced ${esc(new Date(s.synced).toLocaleString())}` : ""}</div></div><button class="btn btn--sm" type="button" data-sync="${i}">${icons.download} Sync</button><button class="icon-btn" type="button" data-del="${i}" aria-label="Remove source">${icons.trash}</button></li>`).join("")}</ul></div>`
        : "";
    };
    const pull = async (repo, ref, path, btn) => {
      btn.disabled = true;
      $("#arGitMsg", panel).textContent = "Downloading from GitHub";
      try {
        const res = await api.gitFetch(repo, ref, path, kind);
        const full = `${res.owner}/${res.repo}`;
        const scope = res.path ? `${res.prefix}${res.path}/` : res.prefix;
        await save(res.rules, scope);
        const list = sources().filter((s) => !(s.repo === full && (s.path || "") === (res.path || "")));
        list.unshift({ repo: full, ref: ref || "", path: res.path || "", count: res.rules.length, synced: Date.now() });
        writeJson(k.git, list.slice(0, 20));
        paintSources();
        $("#arGitMsg", panel).textContent = `${plural(res.rules.length, "rule")} from ${full} (${res.ref})${res.truncated ? ", limit reached" : ""}`;
      } catch (err) {
        $("#arGitMsg", panel).textContent = "";
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
    };
    $("#arGit", panel).addEventListener("click", (e) => {
      const repo = $("#arRepo", panel).value.trim();
      if (!repo) {
        toast("Type a repository first", "bad");
        return;
      }
      pull(repo, $("#arRef", panel).value.trim(), $("#arPath", panel).value.trim(), e.currentTarget);
    });
    $("#arSources", panel).addEventListener("click", (e) => {
      const s = e.target.closest("[data-sync]");
      const d = e.target.closest("[data-del]");
      const list = sources();
      if (s && list[Number(s.dataset.sync)]) {
        const src = list[Number(s.dataset.sync)];
        pull(src.repo, src.ref, src.path, s);
      }
      if (d) {
        list.splice(Number(d.dataset.del), 1);
        writeJson(k.git, list);
        paintSources();
      }
    });
    paintSources();

    const samples = async (btn, broken) => {
      btn.disabled = true;
      try {
        if (sigma) {
          const data = await api.samples();
          const group = (r) => (r.name.startsWith("broken/") ? "broken" : "ok");
          await save(data.rules.filter((r) => (broken ? group(r) === "broken" : group(r) !== "broken")).map((r) => ({ name: `sample/${r.name}`, content: r.content })));
        } else {
          const res = await yaraStore.loadSamples();
          toast(`Loaded ${plural(res.list.length, "YARA file")}`, "ok");
          onDone?.(res.list[0]?.name);
        }
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
    };
    $("#arSamples", panel).addEventListener("click", (e) => samples(e.currentTarget, false));
    $("#arBroken", panel)?.addEventListener("click", (e) => samples(e.currentTarget, true));
    $("#arSiem", panel)?.addEventListener("click", () => importSiemDrawer());
    $("#arCti", panel)?.addEventListener("click", () => ctiDrawer(() => onDone?.()));
    $("#arLib", panel).addEventListener("click", () => {
      try {
        localStorage.setItem("sigma-forge-library-source", kind);
      } catch {}
    });
  });
}
