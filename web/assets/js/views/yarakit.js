import { api } from "../api.js";
import { readJson, size, writeJson } from "../shared.js";
import { esc, openDrawer, plural, toast } from "../ui.js";

const KEY = "sigma-forge-yara";

export const yaraStore = {
  all() {
    const list = readJson(KEY, []);
    return Array.isArray(list) ? list : [];
  },
  save(list) {
    if (!writeJson(KEY, list)) toast("Browser storage is full. Remove some YARA files.", "bad");
  },
  upsert(file) {
    const list = this.all().filter((f) => f.name !== file.name);
    list.push(file);
    list.sort((a, b) => a.name.localeCompare(b.name));
    this.save(list);
    return list;
  },
  remove(name) {
    const list = this.all().filter((f) => f.name !== name);
    this.save(list);
    return list;
  },
  async loadSamples() {
    const data = await api.yara.samples();
    let list = this.all();
    data.rules.forEach((r) => {
      list = list.filter((f) => f.name !== r.name);
      list.push({ name: r.name, content: r.content });
    });
    list.sort((a, b) => a.name.localeCompare(b.name));
    this.save(list);
    return { list, files: data.files || [] };
  },
};

export function b64File(f) {
  const bin = atob(f.data);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  return new File([bytes], f.name, { type: "application/octet-stream" });
}

export function renderYaraScan(out, res, label = "Files scanned") {
  const files = res.files || [];
  const s = res.summary || {};
  const scanned = s.scanned ?? s.files ?? files.length;
  const matched = files.filter((f) => f.matches?.length);
  const errors = res.errors || files.filter((f) => f.error).map((f) => ({ path: f.name, error: f.error }));
  out.innerHTML = `
    <div class="stats">
      <div class="stat"><div class="stat__label">${esc(label)}</div><div class="stat__value stat__value--accent">${scanned}</div><div class="stat__hint">${s.seconds !== undefined ? `in ${s.seconds}s` : "uploaded"}</div></div>
      <div class="stat"><div class="stat__label">Files matched</div><div class="stat__value ${matched.length ? "stat__value--bad" : "stat__value--ok"}">${matched.length}</div><div class="stat__hint">${esc(plural(s.matches ?? matched.reduce((n, f) => n + f.matches.length, 0), "rule hit"))}</div></div>
      <div class="stat"><div class="stat__label">Errors</div><div class="stat__value ${errors.length ? "stat__value--warn" : ""}">${errors.length}</div><div class="stat__hint">${res.truncated ? esc(res.truncated) : "no access or timeouts"}</div></div>
    </div>
    ${(res.missing || []).length ? `<div class="notice notice--warn">Not found: ${res.missing.map((m) => `<span class="mono">${esc(m)}</span>`).join(", ")}</div>` : ""}
    ${res.skipped && (res.skipped.too_big || res.skipped.no_access) ? `<div class="notice notice--info">Skipped ${res.skipped.too_big || 0} files over the size limit and ${res.skipped.no_access || 0} with no access.</div>` : ""}
    <div class="card mt-4">
      <div class="card__head"><span class="card__title">Matches</span><span class="card__sub">${esc(plural(matched.length, "file"))}</span></div>
      ${matched.length
        ? `<ul class="list">${matched
            .map(
              (f, i) => `<li class="list__item"><div class="list__main"><div class="list__title mono yara__path" title="${esc(f.name)}">${esc(f.name)}</div><div class="list__meta">${esc(size(f.size || 0))}</div></div><div class="tags">${f.matches.map((m) => `<span class="badge badge--bad">${esc(m.rule)}</span>`).join("")}</div><button class="btn btn--sm" type="button" data-yhit="${i}">Details</button></li>`
            )
            .join("")}</ul>`
        : '<div class="card__body"><div class="notice notice--ok">No rule matched any file.</div></div>'}
    </div>
    ${errors.length ? `<details class="card mt-4"><summary class="card__head"><span class="card__title">Errors</span><span class="card__sub">${errors.length}</span></summary><ul class="list">${errors.slice(0, 100).map((e) => `<li class="list__item"><div class="list__main"><div class="list__title mono">${esc(e.path)}</div><div class="list__meta">${esc(e.error)}</div></div></li>`).join("")}</ul></details>` : ""}`;
  out.onclick = (e) => {
    const btn = e.target.closest("[data-yhit]");
    if (btn) showHit(matched[Number(btn.dataset.yhit)]);
  };
}

function showHit(f) {
  const body = `
    <dl class="meta"><dt>File</dt><dd class="mono">${esc(f.name)}</dd><dt>Size</dt><dd>${esc(size(f.size || 0))}</dd><dt>Rules</dt><dd>${f.matches.length}</dd></dl>
    ${f.matches
      .map(
        (m) => `<h3 class="section-title">${esc(m.rule)} ${m.tags.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</h3>
        <div class="card">
          ${Object.keys(m.meta || {}).length ? `<dl class="meta card__body">${Object.entries(m.meta).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>` : ""}
          ${m.strings.length
            ? `<table class="table table--compact"><thead><tr><th>String</th><th>Offset</th><th>Text</th><th>Hex</th></tr></thead><tbody>${m.strings
                .map((st) => `<tr><td class="mono">${esc(st.id)}</td><td class="mono">0x${st.offset.toString(16)}</td><td class="mono yara__text">${esc(st.text)}</td><td class="mono yara__hex">${esc(st.hex)}</td></tr>`)
                .join("")}</tbody></table>${m.string_hits > m.strings.length ? `<p class="muted card__body">Showing ${m.strings.length} of ${m.string_hits} string hits.</p>` : ""}`
            : '<p class="muted card__body">Matched by condition only, no string hits.</p>'}
        </div>`
      )
      .join("")}`;
  openDrawer(f.name.split(/[\\/]/).pop(), body);
}
