import { api } from "../api.js";
import { state } from "../state.js";
import { store } from "../store.js";
import { $, $$, debounce, esc, icons, plural, toast } from "../ui.js";

const OP_LABEL = {
  equals: "is", contains: "contains", startswith: "starts with", endswith: "ends with", re: "regex", cidr: "in IP range",
  gt: "greater than", gte: "at least", lt: "less than", lte: "at most", exists: "exists", windash: "contains (any dash)", base64offset: "base64 contains",
};
let taxonomyCache = null;

async function taxonomy() {
  if (!taxonomyCache) taxonomyCache = await api.taxonomy();
  return taxonomyCache;
}

function itemRow(fields, it = {}) {
  return `<div class="wz__item" data-item>
    <input class="input mono" data-k="field" list="wzFields" placeholder="Field" value="${esc(it.field || "")}" aria-label="Field" spellcheck="false">
    <select class="select" data-k="op" aria-label="Match">${Object.entries(OP_LABEL).map(([k, v]) => `<option value="${k}" ${k === (it.op || "contains") ? "selected" : ""}>${esc(v)}</option>`).join("")}</select>
    <textarea class="textarea mono" data-k="values" rows="1" placeholder="Values, one per line" aria-label="Values" spellcheck="false">${esc((it.values || []).join("\n"))}</textarea>
    <label class="check wz__all" title="Every value must match"><input type="checkbox" data-k="all" ${it.all ? "checked" : ""}> all</label>
    <button class="btn btn--sm btn--ghost" type="button" data-rmitem aria-label="Remove">${icons.trash}</button>
  </div>`;
}

function groupBox(kind, idx, fields, g = {}) {
  const label = kind === "sel" ? `Match group ${idx + 1}` : `Exclude group ${idx + 1}`;
  return `<div class="wz__group wz__group--${kind}" data-group="${kind}">
    <div class="wz__ghead"><span class="field__label">${label}</span><input class="input input--sm" data-k="name" placeholder="${kind === "sel" ? "name, like img" : "name, like main_admin"}" value="${esc(g.name || "")}" aria-label="Group name"><div class="spacer"></div><button class="btn btn--sm btn--ghost" type="button" data-rmgroup aria-label="Remove group">${icons.trash}</button></div>
    <div data-items>${(g.items && g.items.length ? g.items : [{}]).map((it) => itemRow(fields, it)).join("")}</div>
    <button class="link-btn" type="button" data-additem>Add a field</button>
  </div>`;
}

export async function wizardPane(host, onOpen) {
  host.innerHTML = '<div class="skeleton sk-title"></div><div class="skeleton sk-block"></div>';
  let tax;
  try {
    tax = await taxonomy();
  } catch (err) {
    host.innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
    return;
  }
  const sources = tax.logsources;
  host.innerHTML = `
    <p class="muted">Answer a few questions. The rule is written for you as you type.</p>
    <div class="wz">
      <div class="wz__form">
        <label class="field"><span class="field__label">1. What log has the activity?</span><select class="select" id="wzLs">${sources.map((s, i) => `<option value="${i}">${esc(s.label)}</option>`).join("")}</select></label>
        <label class="field"><span class="field__label">2. Name the behavior</span><input class="input" id="wzTitle" placeholder="Certutil Downloads A File"></label>
        <div class="grid grid--2">
          <label class="field"><span class="field__label">Level</span><select class="select" id="wzLevel">${tax.levels.map((l) => `<option ${l === "medium" ? "selected" : ""}>${l}</option>`).join("")}</select></label>
          <label class="field"><span class="field__label">ATT&amp;CK techniques</span><input class="input mono" id="wzTech" placeholder="T1105, T1218"></label>
        </div>
        <div class="field__label">3. What must be true? <span class="muted">Fields in one group must all match.</span></div>
        <div class="row wz__join"><label class="check"><input type="radio" name="wzJoin" value="all" checked> All groups</label><label class="check"><input type="radio" name="wzJoin" value="any"> Any group</label></div>
        <div id="wzSels"></div>
        <button class="btn btn--sm" type="button" id="wzAddSel">Add match group</button>
        <div class="field__label mt-4">4. What is normal and should be left out?</div>
        <div id="wzFilts"></div>
        <button class="btn btn--sm" type="button" id="wzAddFilt">Add exclude group</button>
        <label class="field mt-4"><span class="field__label">Known false positives</span><input class="input" id="wzFp" placeholder="Admin scripts, software updates"></label>
        <label class="field"><span class="field__label">Description</span><input class="input" id="wzDesc" placeholder="Detects ..."></label>
        <datalist id="wzFields"></datalist>
      </div>
      <div class="wz__preview">
        <div class="row"><span class="field__label">Rule</span><span class="muted mono" id="wzName"></span></div>
        <div id="wzErr"></div>
        <pre class="code code--tall" id="wzYaml">Pick fields and values</pre>
        <div class="row mt-4"><div class="spacer"></div><button class="btn btn--primary" type="button" id="wzOpen">${icons.file} Open in editor</button></div>
      </div>
    </div>`;
  let last = null;
  const fields = () => sources[Number($("#wzLs", host).value)].fields;
  const paintFields = () => {
    $("#wzFields", host).innerHTML = fields().map((f) => `<option value="${esc(f)}">`).join("");
  };
  const readGroups = (kind) =>
    $$(`[data-group=${kind}]`, host).map((g) => ({
      name: $("[data-k=name]", g).value.trim(),
      items: $$("[data-item]", g).map((it) => ({
        field: $("[data-k=field]", it).value.trim(),
        op: $("[data-k=op]", it).value,
        values: $("[data-k=values]", it).value.split("\n").map((x) => x.trim()).filter(Boolean),
        all: $("[data-k=all]", it).checked,
      })),
    }));
  const spec = () => {
    const s = sources[Number($("#wzLs", host).value)];
    return {
      title: $("#wzTitle", host).value.trim(),
      logsource: { product: s.product || "", category: s.category || "", service: s.service || "" },
      level: $("#wzLevel", host).value,
      techniques: $("#wzTech", host).value.split(/[\s,;]+/).filter(Boolean),
      join: $("input[name=wzJoin]:checked", host).value,
      selections: readGroups("sel"),
      filters: readGroups("filt"),
      falsepositives: $("#wzFp", host).value.split(",").map((x) => x.trim()).filter(Boolean),
      description: $("#wzDesc", host).value.trim(),
    };
  };
  const build = debounce(async () => {
    try {
      last = await api.wizard(spec());
      $("#wzYaml", host).textContent = last.yaml;
      $("#wzName", host).textContent = last.name;
      $("#wzErr", host).innerHTML = last.errors.map((e) => `<div class="notice notice--bad">${esc(e)}</div>`).join("");
    } catch (err) {
      last = null;
      $("#wzYaml", host).textContent = err.message;
      $("#wzName", host).textContent = "";
      $("#wzErr", host).innerHTML = "";
    }
  }, 250);
  const addGroup = (kind, g) => {
    const wrap = $(kind === "sel" ? "#wzSels" : "#wzFilts", host);
    wrap.insertAdjacentHTML("beforeend", groupBox(kind, $$(`[data-group=${kind}]`, host).length, fields(), g));
  };
  paintFields();
  const first = fields();
  addGroup("sel", { name: "", items: [{ field: first.includes("Image") ? "Image" : first[0], op: "endswith", values: [] }] });
  $("#wzLs", host).addEventListener("change", () => {
    paintFields();
    build();
  });
  $("#wzAddSel", host).addEventListener("click", () => addGroup("sel"));
  $("#wzAddFilt", host).addEventListener("click", () => {
    addGroup("filt");
    build();
  });
  host.addEventListener("input", build);
  host.addEventListener("change", build);
  host.addEventListener("click", (e) => {
    const add = e.target.closest("[data-additem]");
    if (add) {
      $("[data-items]", add.closest("[data-group]")).insertAdjacentHTML("beforeend", itemRow(fields()));
      return;
    }
    const rmi = e.target.closest("[data-rmitem]");
    if (rmi) {
      const g = rmi.closest("[data-group]");
      if ($$("[data-item]", g).length > 1) rmi.closest("[data-item]").remove();
      else g.remove();
      build();
      return;
    }
    const rmg = e.target.closest("[data-rmgroup]");
    if (rmg) {
      rmg.closest("[data-group]").remove();
      build();
      return;
    }
    if (e.target.closest("#wzOpen")) {
      if (!last || last.errors.length) {
        toast("Fix the rule first", "bad");
        return;
      }
      onOpen(last.name, last.yaml);
    }
  });
}

export async function correlationPane(host, onOpen) {
  const rules = (await state.rules()).filter((r) => /^\s*detection\s*:/m.test(r.content) && !/^\s*correlation\s*:/m.test(r.content));
  if (!rules.length) {
    host.innerHTML = '<p class="muted">Add detection rules to the workspace first. A correlation links two or more of them.</p>';
    return;
  }
  const titleOf = (r) => ((r.content.match(/^title:\s*(.+)$/m) || [])[1] || r.name).replace(/^['"]|['"]$/g, "");
  host.innerHTML = `
    <p class="muted">Raise one alert when rules fire many times, on many values, or close together in time.</p>
    <div class="wz">
      <div class="wz__form">
        <div class="field__label">1. Pick the rules</div>
        <input class="input" type="search" id="crFilter" placeholder="Filter rules" aria-label="Filter rules">
        <div class="cr__list" id="crList">${rules.map((r) => `<label class="check cr__item" data-t="${esc(`${titleOf(r)} ${r.name}`.toLowerCase())}"><input type="checkbox" data-rid="${esc(r.id)}"><span class="cr__t"><span>${esc(titleOf(r))}</span><span class="muted mono cr__p">${esc(r.name)}</span></span></label>`).join("")}</div>
        <label class="field mt-4"><span class="field__label">2. When to alert</span><select class="select" id="crType">
          <option value="event_count">The same rule fires many times</option>
          <option value="value_count">Many different values of one field</option>
          <option value="temporal">All picked rules fire, any order</option>
          <option value="temporal_ordered">All picked rules fire, in this order</option>
        </select></label>
        <div class="grid grid--2">
          <label class="field"><span class="field__label">Within</span><input class="input mono" id="crSpan" value="10m" placeholder="30s, 10m, 1h"></label>
          <label class="field"><span class="field__label">Group by</span><input class="input mono" id="crGroup" value="Computer" placeholder="Computer, User"></label>
        </div>
        <div class="grid grid--2" id="crCountRow">
          <label class="field"><span class="field__label">Count</span><span class="cr__count"><select class="select" id="crOp"><option value="gte">at least</option><option value="gt">more than</option><option value="lte">at most</option></select><input class="input" id="crCount" type="number" min="1" value="5"></span></label>
          <label class="field" id="crFieldWrap" hidden><span class="field__label">Field to count</span><input class="input mono" id="crField" placeholder="TargetUserName"></label>
        </div>
        <div class="grid grid--2">
          <label class="field"><span class="field__label">Title</span><input class="input" id="crTitle" placeholder="Leave empty for a default"></label>
          <label class="field"><span class="field__label">Level</span><select class="select" id="crLevel"><option>medium</option><option selected>high</option><option>critical</option></select></label>
        </div>
      </div>
      <div class="wz__preview">
        <div class="row"><span class="field__label">Correlation</span><span class="muted" id="crPicked">0 rules</span></div>
        <div id="crErr"></div>
        <pre class="code code--tall" id="crYaml">Pick rules</pre>
        <div id="crNote"></div>
        <div class="row mt-4"><div class="spacer"></div><button class="btn" type="button" id="crOpen">${icons.file} Open in editor</button><button class="btn btn--primary" type="button" id="crSave">${icons.file} Save to workspace</button></div>
      </div>
    </div>`;
  let order = [];
  let last = null;
  const picked = () => order.map((id) => rules.find((r) => r.id === id)).filter(Boolean);
  const spec = () => ({
    type: $("#crType", host).value,
    timespan: $("#crSpan", host).value.trim(),
    group_by: $("#crGroup", host).value.split(",").map((x) => x.trim()).filter(Boolean),
    op: $("#crOp", host).value,
    count: Number($("#crCount", host).value || 1),
    field: $("#crField", host).value.trim(),
    title: $("#crTitle", host).value.trim(),
    level: $("#crLevel", host).value,
  });
  const build = debounce(async () => {
    const t = $("#crType", host).value;
    $("#crCountRow", host).hidden = t.startsWith("temporal");
    $("#crFieldWrap", host).hidden = t !== "value_count";
    $("#crPicked", host).textContent = plural(order.length, "rule");
    if (!order.length) {
      last = null;
      $("#crYaml", host).textContent = "Pick rules";
      return;
    }
    try {
      last = await api.correlation(spec(), picked());
      $("#crYaml", host).textContent = last.yaml;
      $("#crErr", host).innerHTML = last.errors.map((e) => `<div class="notice notice--bad">${esc(e)}</div>`).join("");
      $("#crNote", host).innerHTML = last.updated.length ? `<p class="muted mt-4">${esc(plural(last.updated.length, "rule"))} will get a <span class="mono">name:</span> so the correlation can point to ${last.updated.length === 1 ? "it" : "them"}.</p>` : "";
    } catch (err) {
      last = null;
      $("#crYaml", host).textContent = err.message;
      $("#crErr", host).innerHTML = "";
      $("#crNote", host).innerHTML = "";
    }
  }, 250);
  const applyUpdates = async () => {
    for (const u of last.updated) {
      const r = rules.find((x) => x.name === u.name);
      if (r) await store.replace(r.id, { name: r.name, content: u.content });
    }
  };
  $("#crFilter", host).addEventListener("input", (e) => {
    const q = e.target.value.trim().toLowerCase();
    $$("#crList [data-t]", host).forEach((l) => (l.hidden = q && !l.dataset.t.includes(q)));
  });
  host.addEventListener("change", (e) => {
    const box = e.target.closest("[data-rid]");
    if (box) {
      order = box.checked ? [...order, box.dataset.rid] : order.filter((x) => x !== box.dataset.rid);
    }
    build();
  });
  host.addEventListener("input", (e) => {
    if (!e.target.closest("#crFilter")) build();
  });
  host.addEventListener("click", async (e) => {
    const save = e.target.closest("#crSave");
    const open = e.target.closest("#crOpen");
    if (!save && !open) return;
    if (!last || last.errors.length) {
      toast("Fix the correlation first", "bad");
      return;
    }
    await applyUpdates();
    if (save) {
      await store.add([{ name: `correlations/${last.name}`, content: last.yaml }]);
      toast(`Saved correlations/${last.name}`, "ok");
      return;
    }
    onOpen(`correlations/${last.name}`, last.yaml);
  });
  build();
}
