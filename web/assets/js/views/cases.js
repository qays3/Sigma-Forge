import { api } from "../api.js";
import { cases } from "../localdata.js";
import { openInEditor, readJson, writeJson } from "../shared.js";
import { state } from "../state.js";
import { $, $$, downloadBlob, emptyState, esc, icons, levelBadge, plural, toast } from "../ui.js";

const STATUS = [["open", "Open"], ["investigating", "Investigating"], ["closed", "Closed"]];
const SEV = ["low", "medium", "high", "critical"];
const FOCUS = "sigma-forge-case-focus";

function now() {
  return new Date().toISOString().slice(0, 16).replace("T", " ");
}

export async function casesView(root) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Cases</div>
          <h1>Cases</h1>
          <p>Group hits from a test or a hunt into a case, track who looks at it, write notes and export a report. Cases stay in this browser.</p>
        </div>
        <button class="btn btn--primary" type="button" id="csNew">${icons.file} New case</button>
      </div>
      <div class="cases">
        <aside class="cases__side">
          <div class="seg seg--full" id="csSeg"><button class="seg__btn is-active" type="button" data-s="">All</button>${STATUS.map(([k, l]) => `<button class="seg__btn" type="button" data-s="${k}">${l}</button>`).join("")}</div>
          <ul class="list cases__list mt-4" id="csList"></ul>
        </aside>
        <div class="cases__main" id="csMain"></div>
      </div>
    </section>`;
  let filter = "";
  let currentId = readJson(FOCUS, "") || cases.all()[0]?.id || "";
  writeJson(FOCUS, "");

  const paintList = () => {
    const all = cases.all();
    const list = all.filter((c) => !filter || c.status === filter);
    $("#csList", root).innerHTML = list.length
      ? list.map((c) => `<li class="list__item cases__item ${c.id === currentId ? "is-active" : ""}" data-id="${esc(c.id)}"><div class="list__main"><div class="list__title">${esc(c.title)}</div><div class="list__meta">${esc(c.status)} · ${esc(plural(c.hits.length, "hit"))} · ${esc(c.updated || "")}</div></div>${levelBadge(c.severity)}</li>`).join("")
      : `<li class="list__item muted">${all.length ? "No cases with this status." : "No cases yet."}</li>`;
  };

  const paintMain = () => {
    const c = cases.get(currentId);
    const main = $("#csMain", root);
    if (!c) {
      main.innerHTML = `<div class="card">${emptyState("No case open", "Create a case from a test or hunt result with Create case, or start an empty one.")}</div>`;
      return;
    }
    main.innerHTML = `
      <div class="card">
        <div class="card__body">
          <input class="input case__title" id="cTitle" value="${esc(c.title)}" aria-label="Case title">
          <div class="case__meta mt-4">
            <label class="field"><span class="field__label">Status</span><select class="select" id="cStatus">${STATUS.map(([k, l]) => `<option value="${k}" ${k === c.status ? "selected" : ""}>${l}</option>`).join("")}</select></label>
            <label class="field"><span class="field__label">Severity</span><select class="select" id="cSev">${SEV.map((s) => `<option ${s === c.severity ? "selected" : ""}>${s}</option>`).join("")}</select></label>
            <label class="field"><span class="field__label">Owner</span><input class="input" id="cOwner" value="${esc(c.owner || "")}" placeholder="Not set"></label>
          </div>
          <label class="field"><span class="field__label">Summary</span><textarea class="textarea case__sum" id="cSum" rows="3" placeholder="What happened">${esc(c.summary || "")}</textarea></label>
          <div class="row"><span class="muted">Created ${esc(c.created || "")} · ${esc(plural(c.hosts.length, "host"))}${c.techniques.length ? ` · ${esc(c.techniques.slice(0, 6).join(", "))}` : ""}</span><div class="spacer"></div>
            <button class="btn btn--sm btn--ghost btn--danger" type="button" id="cDel">${icons.trash} Delete</button>
            <button class="btn btn--sm" type="button" id="cReport">${icons.download} Report</button>
            <button class="btn btn--sm btn--primary" type="button" id="cSave">Save</button>
          </div>
        </div>
      </div>
      <div class="card mt-4">
        <div class="card__head"><span class="card__title">Hits</span><span class="card__sub">${esc(plural(c.hits.length, "hit"))}</span></div>
        ${c.hits.length ? `<ul class="tline case__hits">${c.hits.slice(0, 300).map((h, i) => `<li class="tline__item tline__item--${esc(h.level || "none")}"><span class="tline__time">${esc((h.ts || "").slice(11, 19) || "no time")}</span><span class="tline__dot" aria-hidden="true"></span><div class="tline__body"><div class="tline__title"><span>${esc(h.rule)}</span>${levelBadge(h.level)}<button class="link-btn" type="button" data-rule="${i}">Open rule</button></div><div class="tline__meta"><span class="chip">${esc(h.host || "unknown host")}</span>${h.user ? `<span class="muted">${esc(h.user)}</span>` : ""}<span class="muted mono">${esc((h.ts || "").slice(0, 10))}</span></div>${h.summary ? `<div class="tline__sum">${esc(h.summary)}</div>` : ""}</div></li>`).join("")}</ul>` : '<div class="card__body"><p class="muted">No hits in this case.</p></div>'}
      </div>
      ${steps(c).length ? `<div class="card mt-4"><div class="card__head"><span class="card__title">Response steps</span><span class="card__sub">from the rules that fired</span></div><div class="card__body">${steps(c).map(([rule, list]) => `<div class="field__label">${esc(rule)}</div><ol class="rsp__steps">${list.map((x) => `<li>${esc(x)}</li>`).join("")}</ol>`).join("")}</div></div>` : ""}
      <div class="card mt-4">
        <div class="card__head"><span class="card__title">Notes</span></div>
        <div class="card__body">
          <ul class="case__notes">${(c.notes || []).map((n) => `<li><span class="mono muted">${esc(n.time)}</span><p>${esc(n.text)}</p></li>`).join("") || '<li class="muted">No notes yet.</li>'}</ul>
          <div class="row mt-4"><input class="input toolbar__grow" id="cNote" placeholder="Add a note: what you checked, what you found"><button class="btn" type="button" id="cAddNote">Add note</button></div>
        </div>
      </div>`;
    const read = () => ({ ...cases.get(currentId), title: $("#cTitle", main).value.trim() || "Case", status: $("#cStatus", main).value, severity: $("#cSev", main).value, owner: $("#cOwner", main).value.trim(), summary: $("#cSum", main).value.trim() });
    $("#cSave", main).addEventListener("click", () => {
      const before = cases.get(currentId);
      const next = read();
      if (before.status !== next.status) next.notes = [...(next.notes || []), { time: now(), text: `Status changed to ${next.status}.` }];
      cases.save(next);
      toast("Case saved", "ok");
      paintList();
      paintMain();
    });
    $("#cAddNote", main).addEventListener("click", () => {
      const text = $("#cNote", main).value.trim();
      if (!text) return;
      const c2 = read();
      c2.notes = [...(c2.notes || []), { time: now(), text }];
      cases.save(c2);
      paintList();
      paintMain();
    });
    $("#cNote", main).addEventListener("keydown", (e) => {
      if (e.key === "Enter") $("#cAddNote", main).click();
    });
    $("#cDel", main).addEventListener("click", () => {
      if ($("#cDel", main).dataset.sure !== "1") {
        $("#cDel", main).dataset.sure = "1";
        $("#cDel", main).textContent = "Click again to delete";
        return;
      }
      cases.remove(currentId);
      currentId = cases.all()[0]?.id || "";
      paintList();
      paintMain();
    });
    $("#cReport", main).addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        const { blob, filename } = await api.caseReport(read());
        downloadBlob(filename, blob);
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
    });
    main.addEventListener("click", async (e) => {
      const b = e.target.closest("[data-rule]");
      if (!b) return;
      const h = c.hits[Number(b.dataset.rule)];
      const rules = await state.rules();
      const f = state.fileFor(h.key || "", rules);
      if (f) openInEditor(f.name, f.content, f.id);
      else toast("This rule is no longer in the workspace", "bad");
    });
  };

  paintList();
  paintMain();
  $("#csList", root).addEventListener("click", (e) => {
    const li = e.target.closest("[data-id]");
    if (!li) return;
    currentId = li.dataset.id;
    paintList();
    paintMain();
  });
  $("#csSeg", root).addEventListener("click", (e) => {
    const b = e.target.closest("[data-s]");
    if (!b) return;
    filter = b.dataset.s;
    $$("#csSeg [data-s]", root).forEach((x) => x.classList.toggle("is-active", x === b));
    paintList();
  });
  $("#csNew", root).addEventListener("click", () => {
    const c = cases.save({ title: `Case ${now()}`, notes: [{ time: now(), text: "Case opened." }] });
    currentId = c.id;
    paintList();
    paintMain();
    $("#cTitle", root)?.select();
  });
  return null;
}

function steps(c) {
  const seen = new Map();
  (c.hits || []).forEach((h) => {
    if ((h.response || []).length && !seen.has(h.rule)) seen.set(h.rule, h.response);
  });
  return [...seen.entries()];
}
