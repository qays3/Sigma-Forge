import { readJson, writeJson } from "./shared.js";

const TESTS = "sigma-forge-tests";
const FEEDBACK = "sigma-forge-feedback";
const STATS = "sigma-forge-stats";
const CASES = "sigma-forge-cases";
const MAX_FP_EVENTS = 40;
const PREFERRED = ["Image", "ParentImage", "OriginalFileName", "User", "ParentUser", "CommandLine", "ParentCommandLine", "TargetFilename", "TargetObject", "QueryName", "DestinationHostname", "DestinationIp", "ServiceName", "ImageLoaded", "Computer", "SubjectUserName", "TargetUserName", "IpAddress", "WorkstationName"];

export function fileOf(key) {
  const k = String(key || "");
  const i = k.lastIndexOf("#");
  return i >= 0 ? k.slice(0, i) : k;
}

function flat(obj, prefix = "", out = {}) {
  if (obj && typeof obj === "object" && !Array.isArray(obj)) {
    const attrs = obj["#attributes"];
    if (attrs && attrs.Name !== undefined && "#text" in obj) {
      out[attrs.Name] = obj["#text"];
      return out;
    }
    Object.entries(obj).forEach(([k, v]) => {
      if (k === "#attributes" || k === "xmlns") return;
      if (k === "#text") {
        if (prefix) out[prefix.split(".").pop()] = v;
        return;
      }
      if (v && typeof v === "object" && !Array.isArray(v)) flat(v, prefix ? `${prefix}.${k}` : k, out);
      else if (Array.isArray(v)) out[k] = v.filter((x) => typeof x !== "object").join(" ");
      else out[k] = v;
    });
  }
  return out;
}

export function flatEvent(ev) {
  const root = ev?.Event && typeof ev.Event === "object" ? ev.Event : ev;
  const out = flat(root);
  if (root?.EventData?.Data && Array.isArray(root.EventData.Data)) {
    root.EventData.Data.forEach((d) => {
      if (d?.["#attributes"]?.Name) out[d["#attributes"].Name] = d["#text"];
    });
  }
  return out;
}

function eventHash(ev) {
  const text = JSON.stringify(ev);
  let h = 0;
  for (let i = 0; i < text.length; i += 1) h = (Math.imul(31, h) + text.charCodeAt(i)) | 0;
  return `e${(h >>> 0).toString(16)}`;
}

export const unitTests = {
  all() {
    return readJson(TESTS, {});
  },
  get(name) {
    const t = this.all()[name];
    return { match: Array.isArray(t?.match) ? t.match : [], nomatch: Array.isArray(t?.nomatch) ? t.nomatch : [], last: t?.last || null };
  },
  set(name, cases) {
    const all = this.all();
    if (!cases.match.length && !cases.nomatch.length) delete all[name];
    else all[name] = { match: cases.match, nomatch: cases.nomatch, last: cases.last || null };
    writeJson(TESTS, all);
  },
  add(name, kind, event) {
    const cur = this.get(name);
    const ev = flatEvent(event);
    if (!cur[kind].some((e) => JSON.stringify(e) === JSON.stringify(ev))) cur[kind].push(ev);
    this.set(name, cur);
    return cur;
  },
  saveRun(res) {
    const all = this.all();
    (res.rules || []).forEach((r) => {
      if (all[r.name]) all[r.name].last = { t: Date.now(), passed: r.passed, failed: r.failed, status: r.status };
    });
    writeJson(TESTS, all);
  },
  rename(from, to) {
    const all = this.all();
    if (!all[from] || from === to) return;
    all[to] = all[from];
    delete all[from];
    writeJson(TESTS, all);
  },
  count(name) {
    const t = this.get(name);
    return t.match.length + t.nomatch.length;
  },
};

export const feedback = {
  all() {
    return readJson(FEEDBACK, {});
  },
  forRule(file) {
    const r = this.all()[file] || { tp: 0, fp: 0, marks: {}, fpEvents: [] };
    r.marks = r.marks || {};
    r.fpEvents = r.fpEvents || [];
    return r;
  },
  verdict(file, event) {
    return this.forRule(file).marks[eventHash(event)] || "";
  },
  mark(file, event, verdict) {
    const all = this.all();
    const r = this.forRule(file);
    const h = eventHash(event);
    const prev = r.marks[h];
    if (prev === verdict) return r;
    if (prev) r[prev] = Math.max(0, (r[prev] || 0) - 1);
    if (prev === "fp") r.fpEvents = r.fpEvents.filter((e) => e.h !== h);
    r.marks[h] = verdict;
    r[verdict] = (r[verdict] || 0) + 1;
    if (verdict === "fp") r.fpEvents = [{ h, v: flatEvent(event) }, ...r.fpEvents].slice(0, MAX_FP_EVENTS);
    r.updated = Date.now();
    all[file] = r;
    writeJson(FEEDBACK, all);
    return r;
  },
  precision(file) {
    const r = this.forRule(file);
    const total = (r.tp || 0) + (r.fp || 0);
    return total ? { value: Math.round(((r.tp || 0) * 100) / total), tp: r.tp || 0, fp: r.fp || 0, total } : null;
  },
  suggestFilters(file, limit = 4) {
    const events = this.forRule(file).fpEvents.map((e) => e.v);
    if (!events.length) return [];
    const counts = new Map();
    events.forEach((ev) => {
      Object.entries(ev).forEach(([k, v]) => {
        if (v === null || v === undefined || v === "" || typeof v === "object") return;
        const s = String(v);
        if (s.length > 200 || /^(\d{4}-\d{2}-\d{2}|\{?[0-9a-f-]{36}\}?$|\d+$)/i.test(s)) return;
        const key = `${k}\u0000${s}`;
        counts.set(key, (counts.get(key) || 0) + 1);
      });
    });
    const rank = (f) => {
      const i = PREFERRED.indexOf(f);
      return i < 0 ? 99 : i;
    };
    return [...counts.entries()]
      .map(([key, count]) => {
        const [field, value] = key.split("\u0000");
        return { field, value, count, share: count / events.length };
      })
      .filter((x) => x.share >= 0.5 && !/time|guid|recordid|^pid$|hash/i.test(x.field) && !/Id$|^id$/.test(x.field))
      .sort((a, b) => b.count - a.count || rank(a.field) - rank(b.field))
      .slice(0, limit);
  },
};

export const ruleStats = {
  all() {
    return readJson(STATS, {});
  },
  record(res) {
    const all = this.all();
    const now = Date.now();
    (res.results || []).forEach((r) => {
      if (r.status !== "ok") return;
      const file = fileOf(r.key);
      const s = all[file] || { runs: 0, total_hits: 0, fired_runs: 0 };
      s.title = r.title;
      s.runs += 1;
      s.last_run = now;
      s.last_hits = r.hits;
      s.total_hits += r.hits;
      if (r.hits) {
        s.fired_runs += 1;
        s.last_fired = now;
      }
      s.noise = r.noise?.level || (r.hits ? s.noise : "");
      all[file] = s;
    });
    writeJson(STATS, all);
  },
};

function uid() {
  return `c${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
}

export const cases = {
  all() {
    const list = readJson(CASES, []);
    return Array.isArray(list) ? list : [];
  },
  get(id) {
    return this.all().find((c) => c.id === id) || null;
  },
  save(item) {
    const list = this.all();
    const now = new Date().toISOString().slice(0, 16).replace("T", " ");
    const c = { status: "open", severity: "medium", owner: "", summary: "", hits: [], notes: [], ...item, updated: now };
    if (!c.id) {
      c.id = uid();
      c.created = now;
    }
    c.hosts = [...new Set(c.hits.map((h) => h.host).filter(Boolean))];
    c.techniques = [...new Set([...(c.techniques || []), ...c.hits.flatMap((h) => h.techniques || [])])];
    const i = list.findIndex((x) => x.id === c.id);
    if (i >= 0) list[i] = c;
    else list.unshift(c);
    writeJson(CASES, list);
    return c;
  },
  remove(id) {
    writeJson(CASES, this.all().filter((c) => c.id !== id));
  },
  hitsFrom(res, keys = null) {
    const items = res.timeline?.items || [];
    const byKey = new Map((res.results || []).map((r) => [r.key, r]));
    return items
      .filter((it) => !keys || keys.includes(it.key))
      .slice(0, 500)
      .map((it) => ({ ts: it.ts, host: it.host, user: it.user || "", rule: it.rule, level: it.level, summary: it.summary || "", key: it.key, techniques: byKey.get(it.key)?.techniques || [] }));
  },
};
