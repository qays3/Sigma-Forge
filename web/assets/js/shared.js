import { navigate } from "./router.js";
import { esc } from "./ui.js";

const INCOMING_KEY = "sigma-forge-incoming";
const HISTORY_KEY = "sigma-forge-history";
const HISTORY_MAX = 30;

export function readJson(key, fallback = null) {
  try {
    const value = JSON.parse(localStorage.getItem(key));
    return value ?? fallback;
  } catch {
    return fallback;
  }
}

export function writeJson(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export function openInEditor(name, content, openedId = "") {
  writeJson(INCOMING_KEY, { name, content, openedId });
  navigate("/editor", { draft: Date.now() });
}

export function takeIncoming() {
  const value = readJson(INCOMING_KEY);
  try {
    localStorage.removeItem(INCOMING_KEY);
  } catch {
    return value;
  }
  return value;
}

export function readHistory(name) {
  const all = readJson(HISTORY_KEY, {});
  return Array.isArray(all[name]) ? all[name] : [];
}

export function pushHistory(name, content, note = "") {
  const all = readJson(HISTORY_KEY, {});
  const list = Array.isArray(all[name]) ? all[name] : [];
  if (list.length && list[0].content === content) return list;
  list.unshift({ t: Date.now(), content, note });
  all[name] = list.slice(0, HISTORY_MAX);
  if (!writeJson(HISTORY_KEY, all)) {
    const names = Object.keys(all).sort((a, b) => (all[a][0]?.t || 0) - (all[b][0]?.t || 0));
    while (names.length > 1) {
      delete all[names.shift()];
      if (writeJson(HISTORY_KEY, all)) break;
    }
  }
  return all[name] || [];
}

export function clearHistory(name) {
  const all = readJson(HISTORY_KEY, {});
  delete all[name];
  writeJson(HISTORY_KEY, all);
}

export function lineDiff(before, after) {
  const a = before.split("\n");
  const b = after.split("\n");
  if (a.length * b.length > 4000000) {
    return [...a.map((t) => ({ op: "del", text: t })), ...b.map((t) => ({ op: "add", text: t }))];
  }
  const n = a.length;
  const m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ op: "same", text: a[i] });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ op: "del", text: a[i] });
      i += 1;
    } else {
      out.push({ op: "add", text: b[j] });
      j += 1;
    }
  }
  while (i < n) out.push({ op: "del", text: a[i++] });
  while (j < m) out.push({ op: "add", text: b[j++] });
  return out;
}

export function diffHtml(rows, context = 3) {
  const keep = new Set();
  rows.forEach((r, i) => {
    if (r.op === "same") return;
    for (let k = Math.max(0, i - context); k <= Math.min(rows.length - 1, i + context); k += 1) keep.add(k);
  });
  if (!keep.size) return '<p class="muted">No changes.</p>';
  let last = -1;
  let out = "";
  rows.forEach((r, i) => {
    if (!keep.has(i)) return;
    if (last !== -1 && i !== last + 1) out += '<div class="diff__line diff__line--gap">...</div>';
    const sign = r.op === "add" ? "+" : r.op === "del" ? "-" : " ";
    out += `<div class="diff__line diff__line--${r.op}"><span class="diff__sign">${sign}</span>${esc(r.text) || " "}</div>`;
    last = i;
  });
  return `<div class="diff">${out}</div>`;
}

export function diffStats(rows) {
  return { added: rows.filter((r) => r.op === "add").length, removed: rows.filter((r) => r.op === "del").length };
}

export function gradeClass(grade) {
  return { A: "ok", B: "ok", C: "warn", D: "warn", F: "bad" }[grade] || "";
}

export function qualityBadge(q) {
  if (!q) return "";
  return `<span class="badge badge--${gradeClass(q.grade)}" title="Quality score ${q.score} of 100">${esc(q.grade)} ${q.score}</span>`;
}

export function qualityList(q) {
  if (!q) return "";
  return `<div class="quality">
    <div class="quality__head"><span class="quality__grade quality__grade--${gradeClass(q.grade)}">${esc(q.grade)}</span><div class="quality__main"><div class="quality__score">${q.score}<span>/100</span></div><div class="meter"><span class="meter__fill meter__fill--${gradeClass(q.grade)}" data-width="${q.score}"></span></div></div></div>
    <ul class="quality__list">${q.checks
      .map((c) => `<li class="quality__item ${c.ok ? "is-ok" : "is-miss"}"><span class="quality__mark">${c.ok ? "+" : "-"}</span><span class="quality__label">${esc(c.label)}</span><span class="quality__pts">${c.points}/${c.max}</span></li>`)
      .join("")}</ul>
  </div>`;
}

export function paintMeters(root) {
  root.querySelectorAll("[data-width]").forEach((el) => el.style.setProperty("width", `${Math.max(0, Math.min(100, Number(el.dataset.width) || 0))}%`));
}

export function fmtTime(t) {
  const d = new Date(t);
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function size(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

export function pretty(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

export function fileSlug(text) {
  return String(text || "rule").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "rule";
}

export function fileChips(files, empty = "") {
  if (!files.length) return empty ? `<li class="filechips__empty">${esc(empty)}</li>` : "";
  return files
    .map((f, i) => `<li class="filechip"><span class="filechip__name" title="${esc(f.name)}">${esc(f.name)}</span><span class="filechip__size">${esc(size(f.size))}</span><button class="filechip__x" type="button" data-drop="${i}" aria-label="Remove ${esc(f.name)}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg></button></li>`)
    .join("");
}

export function ruleTechniques(rules) {
  const out = new Set();
  rules.forEach((r) => {
    (r.content || "").replace(/attack\.(t\d{4}(?:\.\d{3})?)\b/gi, (_, t) => out.add(t.toUpperCase()));
  });
  return [...out].sort();
}
