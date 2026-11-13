import { api } from "../api.js";
import { unitTests } from "../localdata.js";
import { pretty } from "../shared.js";
import { $, $$, esc, icons, plural, toast } from "../ui.js";

const LEVEL_CLASS = { error: "bad", warn: "warn", info: "" };

function parseEvents(text) {
  const t = text.trim();
  if (!t) return [];
  if (t.startsWith("[")) {
    const arr = JSON.parse(t);
    return Array.isArray(arr) ? arr.filter((x) => x && typeof x === "object" && !Array.isArray(x)) : [];
  }
  try {
    const one = JSON.parse(t);
    return one && typeof one === "object" ? [one] : [];
  } catch {
    return t.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => JSON.parse(l));
  }
}

function caseLabel(ev) {
  for (const k of ["CommandLine", "Image", "TargetFilename", "QueryName", "TargetObject", "ScriptBlockText", "EventID"]) {
    if (k in ev) return `${k}: ${String(ev[k]).slice(0, 90)}`;
  }
  const k = Object.keys(ev)[0];
  return k ? `${k}: ${String(ev[k]).slice(0, 90)}` : "event";
}

export function testsPane(host, getFile, onChange = () => {}) {
  let results = null;
  const paint = () => {
    onChange();
    const f = getFile();
    const cases = unitTests.get(f.name);
    const res = results && results.name === f.name ? results : null;
    const row = (kind, ev, i) => {
      const r = res?.cases.find((c) => c.kind === kind && c.index === i);
      const mark = r ? `<span class="badge badge--${r.ok ? "ok" : "bad"}">${r.ok ? "pass" : "fail"}</span>` : '<span class="badge">not run</span>';
      return `<li class="list__item ut__row"><div class="list__main"><div class="list__title mono">${esc(caseLabel(ev))}</div><details class="ut__raw"><summary>Event</summary><pre class="code">${esc(pretty(ev))}</pre></details></div>${mark}<button class="btn btn--sm btn--ghost" type="button" data-rm="${kind}:${i}" aria-label="Remove">${icons.trash}</button></li>`;
    };
    const total = cases.match.length + cases.nomatch.length;
    host.innerHTML = `
      <p class="muted">Keep events that this rule must catch and events it must leave alone. Run them after every change. The CLI runs the same tests from <span class="mono">${esc(f.name.split("/").pop().replace(/\.ya?ml$/i, ""))}.tests.json</span>.</p>
      <div class="row ut__bar">
        ${res ? `<span class="badge badge--${res.failed || res.status !== "ok" ? "bad" : "ok"}">${res.passed} passed, ${res.failed} failed</span>` : `<span class="muted">${esc(plural(total, "test"))}</span>`}
        <div class="spacer"></div>
        <button class="btn btn--sm" type="button" data-act="export" ${total ? "" : "disabled"}>${icons.download} tests.json</button>
        <button class="btn btn--sm btn--primary" type="button" data-act="run" ${total ? "" : "disabled"}>${icons.play} Run tests</button>
      </div>
      ${res?.message ? `<div class="notice notice--bad mt-4">${esc(res.message)}</div>` : ""}
      <div class="field__label mt-4">Should match <span class="tab__count">${cases.match.length}</span></div>
      <ul class="list ut__list">${cases.match.map((e, i) => row("match", e, i)).join("") || '<li class="list__item muted">None yet. Use Save as test on a matching event, or add one below.</li>'}</ul>
      <div class="field__label mt-4">Should not match <span class="tab__count">${cases.nomatch.length}</span></div>
      <ul class="list ut__list">${cases.nomatch.map((e, i) => row("nomatch", e, i)).join("") || '<li class="list__item muted">None yet. Add normal activity that looks close.</li>'}</ul>
      <div class="ut__add mt-4">
        <div class="row"><select class="select select--sm" id="utKind" aria-label="Kind"><option value="match">Should match</option><option value="nomatch">Should not match</option></select><div class="spacer"></div><button class="link-btn" type="button" data-act="gen">Make a matching event from the rule</button></div>
        <textarea class="textarea mono mt-4" id="utText" rows="5" spellcheck="false" placeholder='{"Image": "C:\\\\Windows\\\\System32\\\\whoami.exe", "CommandLine": "whoami /priv"}'></textarea>
        <div class="row mt-4"><span class="muted">One JSON object, an array, or JSON lines</span><div class="spacer"></div><button class="btn btn--sm" type="button" data-act="add">Add</button></div>
      </div>`;
  };
  host.addEventListener("click", async (e) => {
    const f = getFile();
    const rm = e.target.closest("[data-rm]");
    if (rm) {
      const [kind, i] = rm.dataset.rm.split(":");
      const cur = unitTests.get(f.name);
      cur[kind].splice(Number(i), 1);
      unitTests.set(f.name, cur);
      results = null;
      paint();
      return;
    }
    const act = e.target.closest("[data-act]")?.dataset.act;
    if (!act) return;
    if (act === "add") {
      let evs;
      try {
        evs = parseEvents($("#utText", host).value);
      } catch (err) {
        toast(`Not valid JSON: ${err.message}`, "bad");
        return;
      }
      if (!evs.length) {
        toast("Paste an event first", "bad");
        return;
      }
      const kind = $("#utKind", host).value;
      evs.forEach((ev) => unitTests.add(f.name, kind, ev));
      results = null;
      paint();
      $("#utKind", host).value = kind;
      return;
    }
    if (act === "gen") {
      try {
        const res = await api.generateEvents([f]);
        const line = (res.jsonl || "").split("\n").find((l) => l.trim());
        const ev = line ? JSON.parse(line) : null;
        if (!ev) {
          toast("Could not make an event for this rule", "bad");
          return;
        }
        const clean = { ...ev };
        delete clean._generated_for;
        delete clean.logsource;
        $("#utText", host).value = JSON.stringify(clean, null, 2);
        $("#utKind", host).value = "match";
      } catch (err) {
        toast(err.message, "bad");
      }
      return;
    }
    if (act === "export") {
      const cur = unitTests.get(f.name);
      const blob = new Blob([JSON.stringify({ match: cur.match, nomatch: cur.nomatch }, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `${f.name.split("/").pop().replace(/\.ya?ml$/i, "")}.tests.json`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      return;
    }
    if (act === "run") {
      const btn = e.target.closest("[data-act]");
      btn.disabled = true;
      try {
        const cur = unitTests.get(f.name);
        const res = await api.unitTests([f], { [f.name]: { match: cur.match, nomatch: cur.nomatch } });
        unitTests.saveRun(res);
        results = res.rules[0] || null;
        paint();
        toast(res.failed ? `${res.failed} failed` : "All tests passed", res.failed ? "bad" : "ok");
      } catch (err) {
        toast(err.message, "bad");
        btn.disabled = false;
      }
    }
  });
  return { paint };
}

export function sigmahqPane(host, getFile, onFix) {
  const run = async () => {
    const f = getFile();
    if (!f.content.trim()) {
      host.innerHTML = '<p class="muted">Start typing a Sigma rule.</p>';
      return;
    }
    host.innerHTML = '<div class="skeleton sk-title"></div><div class="skeleton sk-line"></div><div class="skeleton sk-line sk-line--md"></div>';
    let res;
    try {
      res = (await api.sigmahq([f])).rules[0];
    } catch (err) {
      host.innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
      return;
    }
    const order = { error: 0, warn: 1, info: 2 };
    const checks = [...res.checks].sort((a, b) => order[a.level] - order[b.level]);
    host.innerHTML = `
      <p class="muted">Checks from the SigmaHQ contribution guide: file name, fields, order, style and tags. Pass them before you open a pull request to SigmaHQ.</p>
      <div class="row shq__head"><span class="shq__score shq__score--${res.errors ? "bad" : res.warnings ? "warn" : "ok"}">${res.score}</span><div><div class="list__title">${res.errors ? "Not ready yet" : res.warnings ? "Almost ready" : "Ready for SigmaHQ"}</div><div class="muted">${esc(plural(res.errors, "error"))}, ${esc(plural(res.warnings, "warning"))}</div></div><div class="spacer"></div><button class="btn btn--sm" type="button" data-shq="fix">${icons.spark} Fix style</button></div>
      ${res.suggested_name ? `<div class="notice notice--warn mt-4 shq__rename"><span>Rename to <span class="mono">${esc(res.suggested_name)}</span></span><button class="btn btn--sm" type="button" data-shq="rename" data-name="${esc(res.suggested_name)}">Use this name</button></div>` : ""}
      <ul class="list mt-4">${checks.map((c) => `<li class="list__item"><span class="badge badge--${LEVEL_CLASS[c.level]}">${esc(c.level)}</span><div class="list__main">${esc(c.text)}</div></li>`).join("") || '<li class="list__item">Nothing to fix.</li>'}</ul>`;
  };
  host.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-shq]");
    if (!b) return;
    const f = getFile();
    if (b.dataset.shq === "rename") {
      const dir = f.name.includes("/") ? f.name.slice(0, f.name.lastIndexOf("/") + 1) : "";
      onFix({ name: dir + b.dataset.name });
      run();
      return;
    }
    b.disabled = true;
    try {
      const res = await api.sigmahqFix(f.content, f.name);
      if (!res.changes.length) toast("Style is already fine", "ok");
      else {
        onFix({ content: res.content, note: "before SigmaHQ style fix" });
        toast(res.changes.join(". "), "ok", 5200);
      }
      run();
    } catch (err) {
      toast(err.message, "bad");
      b.disabled = false;
    }
  });
  return { run };
}

export function responsePane(host, getFile, onApply) {
  const read = () => {
    const m = getFile().content.match(/^response\s*:\s*\n((?:[ \t]+-.*\n?|[ \t]*\n)+)/m);
    if (!m) return [];
    return m[1].split("\n").map((l) => l.replace(/^\s*-\s*/, "").trim().replace(/^['"]|['"]$/g, "")).filter(Boolean);
  };
  const paint = (steps = read()) => {
    host.innerHTML = `
      <p class="muted">What the analyst does when this rule fires. The steps are saved in the rule as <span class="mono">response:</span> and show up in test results, cases and hunt reports.</p>
      <ol class="rsp__list" id="rspList">${steps.map((s, i) => `<li class="rsp__item"><input class="input" data-i="${i}" value="${esc(s)}" aria-label="Step ${i + 1}"><button class="btn btn--sm btn--ghost" type="button" data-rm="${i}" aria-label="Remove">${icons.trash}</button></li>`).join("")}</ol>
      ${steps.length ? "" : '<p class="muted">No steps yet.</p>'}
      <div class="row mt-4"><button class="btn btn--sm" type="button" data-rsp="add">Add a step</button><button class="btn btn--sm" type="button" data-rsp="suggest">${icons.spark} Suggest from ATT&amp;CK</button><div class="spacer"></div><button class="btn btn--sm btn--primary" type="button" data-rsp="save">Put in the rule</button></div>`;
  };
  const current = () => $$("#rspList [data-i]", host).map((i) => i.value.trim()).filter(Boolean);
  host.addEventListener("click", async (e) => {
    const rm = e.target.closest("[data-rm]");
    if (rm) {
      const s = current();
      s.splice(Number(rm.dataset.rm), 1);
      paint(s);
      return;
    }
    const act = e.target.closest("[data-rsp]")?.dataset.rsp;
    if (act === "add") {
      paint([...current(), ""]);
      $$("#rspList [data-i]", host).pop()?.focus();
    }
    if (act === "suggest") {
      try {
        const res = await api.response(getFile().content);
        const have = current();
        paint([...have, ...res.steps.filter((s) => !have.includes(s))]);
      } catch (err) {
        toast(err.message, "bad");
      }
    }
    if (act === "save") {
      try {
        const res = await api.response(getFile().content, current());
        onApply(res.content);
        toast("Steps added to the rule. Save it to keep them.", "ok");
      } catch (err) {
        toast(err.message, "bad");
      }
    }
  });
  return { paint };
}
