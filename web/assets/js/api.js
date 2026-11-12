async function request(path, options = {}) {
  const init = { headers: { Accept: "application/json" }, ...options };
  if (init.body && typeof init.body !== "string") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    throw new Error("Cannot reach the Sigma Forge server. Is it running?");
  }
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { detail: text };
  }
  if (!res.ok) {
    const detail = data?.detail;
    const message = Array.isArray(detail) ? detail.map((d) => d.msg).join("; ") : detail || `Request failed (${res.status})`;
    throw new Error(message);
  }
  return data;
}

import { allowlist } from "./allowlist.js";

const strip = (rules) => rules.map((r) => ({ name: r.name, content: r.content }));
const allow = () => allowlist.active();

async function upload(path, form) {
  let res;
  try {
    res = await fetch(path, { method: "POST", body: form, headers: { Accept: "application/json" } });
  } catch {
    throw new Error("Cannot reach the Sigma Forge server. Is it running?");
  }
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { detail: text };
  }
  if (!res.ok) {
    const detail = data?.detail;
    throw new Error(Array.isArray(detail) ? detail.map((d) => d.msg).join("; ") : detail || `Request failed (${res.status})`);
  }
  return data;
}

async function fetchFile(path, body, fallback) {
  let res;
  try {
    res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch {
    throw new Error("Cannot reach the Sigma Forge server. Is it running?");
  }
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      message = (await res.json()).detail || message;
    } catch {
      message = res.statusText || message;
    }
    throw new Error(message);
  }
  const match = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
  return { blob: await res.blob(), filename: match ? match[1] : fallback };
}

async function fetchZip(path, body) {
  let res;
  try {
    res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch {
    throw new Error("Cannot reach the Sigma Forge server. Is it running?");
  }
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      message = (await res.json()).detail || message;
    } catch {
      message = res.statusText || message;
    }
    throw new Error(message);
  }
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/);
  let summary = null;
  try {
    summary = JSON.parse(res.headers.get("X-Export-Summary") || "null");
  } catch {
    summary = null;
  }
  return { blob: await res.blob(), filename: match ? match[1] : "sigma-forge.zip", summary };
}

function query(params) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") q.set(k, v);
  });
  return q.toString();
}

export const api = {
  health: () => request("/api/health"),
  targets: () => request("/api/targets"),
  attack: () => request("/api/attack"),
  samples: () => request("/api/samples"),
  analyze: (rules) => request("/api/analyze", { method: "POST", body: { rules: strip(rules) } }),
  convert: (rules, target, format, options, mapping = {}) => request("/api/convert", { method: "POST", body: { rules: strip(rules), target, format, options, field_mapping: mapping, allowlist: allow() } }),
  compare: (rules, targets, options, mapping = {}) => request("/api/compare", { method: "POST", body: { rules: strip(rules), targets, options, field_mapping: mapping, allowlist: allow() } }),
  packages: () => request("/api/export/packages"),
  exportZip: (rules, target, format, options, mapping, pkg, name) => fetchZip("/api/export", { rules: strip(rules), target, format, options, field_mapping: mapping, package: pkg, name, allowlist: allow() }),
  fields: (rules) => request("/api/fields", { method: "POST", body: { rules: strip(rules) } }),
  gaps: (rules) => request("/api/coverage/gaps", { method: "POST", body: { rules: strip(rules) } }),
  sampleLogs: (set = "") => request(`/api/samples/logs${set ? `?set=${encodeURIComponent(set)}` : ""}`),
  generateEvents: (rules) => request("/api/generate-events", { method: "POST", body: { rules: strip(rules) } }),
  ruleGen: (event, logsource, fields, title = "") => request("/api/rulegen", { method: "POST", body: { event, logsource, fields, title } }),
  addFilter: (content, title, filters) => request("/api/rules/add-filter", { method: "POST", body: { content, title, filters } }),
  queryLanguages: () => request("/api/querygen/languages"),
  queryGen: (query, language, title = "", level = "medium") => request("/api/querygen", { method: "POST", body: { query, language, title, level } }),
  groups: () => request("/api/groups"),
  atomic: (tid) => request(`/api/atomic/${encodeURIComponent(tid)}`),
  report: (rules, title, group, collected) => fetchFile("/api/report", { rules: strip(rules), title, group, collected }, "sigma-forge-report.html"),
  deployKinds: () => request("/api/deploy/kinds"),
  deploy: (rules, kind, target, settings, options, mapping, dryRun) => request("/api/deploy", { method: "POST", body: { rules: strip(rules), kind, target, settings, options, field_mapping: mapping, dry_run: dryRun, allowlist: allow() } }),
  gitFetch: (repo, ref, path) => request("/api/git/fetch", { method: "POST", body: { repo, ref, path } }),
  yara: {
    status: () => request("/api/yara/status"),
    samples: () => request("/api/samples/yara"),
    check: (rules) => request("/api/yara/check", { method: "POST", body: { rules: strip(rules) } }),
    scan(rules, files) {
      const form = new FormData();
      form.append("rules", JSON.stringify(strip(rules)));
      files.forEach((f) => form.append("files", f, f.name));
      return upload("/api/yara/scan", form);
    },
  },
  hunt: {
    status: () => request("/api/hunt/status"),
    events: (rules, channels, hours, maxEvents, mode, mapping = {}) => request("/api/hunt/events", { method: "POST", body: { rules: strip(rules), channels, hours, max_events: maxEvents, mode, field_mapping: mapping, allowlist: allow() } }),
    processes: (rules, pids = []) => request("/api/hunt/processes", { method: "POST", body: { rules: strip(rules), pids } }),
    report: (result, title, scope) => fetchFile("/api/hunt/report", { result, title, scope }, "hunt-report.html"),
    schedule: () => request("/api/hunt/schedule"),
    saveSchedule: (body) => request("/api/hunt/schedule", { method: "POST", body: { ...body, rules: body.rules ? strip(body.rules) : null } }),
    runSchedule: () => request("/api/hunt/schedule/run", { method: "POST" }),
    testWebhook: () => request("/api/hunt/schedule/test", { method: "POST" }),
    yara: (rules, paths, recursive, maxFiles, maxSizeMb, extensions) => request("/api/hunt/yara", { method: "POST", body: { rules: strip(rules), paths, recursive, max_files: maxFiles, max_size_mb: maxSizeMb, extensions } }),
  },
  test(rules, files, mode, mapping = {}) {
    const form = new FormData();
    form.append("rules", JSON.stringify(strip(rules)));
    form.append("mode", mode);
    form.append("field_mapping", JSON.stringify(mapping));
    form.append("allowlist", JSON.stringify(allow()));
    files.forEach((f) => form.append("files", f, f.name));
    return upload("/api/test", form);
  },
  purple(rules, techniques, files, mode, mapping = {}) {
    const form = new FormData();
    form.append("rules", JSON.stringify(strip(rules)));
    form.append("techniques", JSON.stringify(techniques));
    form.append("mode", mode);
    form.append("field_mapping", JSON.stringify(mapping));
    form.append("allowlist", JSON.stringify(allow()));
    files.forEach((f) => form.append("files", f, f.name));
    return upload("/api/purple", form);
  },
  config: () => request("/api/config"),
  iocRules: (text, name) => request("/api/rules/ioc", { method: "POST", body: { text, name } }),
  explain: (rules) => request("/api/rules/explain", { method: "POST", body: { rules: strip(rules) } }),
  autofix: (content, name = "") => request("/api/rules/autofix", { method: "POST", body: { content, name } }),
  libraryUpdates: (rules) => request("/api/library/updates", { method: "POST", body: { rules: strip(rules) } }),
  library: {
    status: () => request("/api/library/status"),
    sync: () => request("/api/library/sync", { method: "POST" }),
    upload(file) {
      const form = new FormData();
      form.append("file", file, file.name);
      return upload("/api/library/upload", form);
    },
    search: (params) => request(`/api/library/search?${query(params)}`),
    rules: (paths) => request("/api/library/rules", { method: "POST", body: { paths } }),
  },
  coverage: (rules, group = "", collected = null) => request("/api/coverage", { method: "POST", body: { rules: strip(rules), group, collected } }),
  navigator: (rules, name, colors) => request("/api/coverage/navigator", { method: "POST", body: { rules: strip(rules), name, colors } }),
};
