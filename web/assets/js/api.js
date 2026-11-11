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

const strip = (rules) => rules.map((r) => ({ name: r.name, content: r.content }));

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
  convert: (rules, target, format, options, mapping = {}) => request("/api/convert", { method: "POST", body: { rules: strip(rules), target, format, options, field_mapping: mapping } }),
  compare: (rules, targets, options, mapping = {}) => request("/api/compare", { method: "POST", body: { rules: strip(rules), targets, options, field_mapping: mapping } }),
  packages: () => request("/api/export/packages"),
  exportZip: (rules, target, format, options, mapping, pkg, name) => fetchZip("/api/export", { rules: strip(rules), target, format, options, field_mapping: mapping, package: pkg, name }),
  fields: (rules) => request("/api/fields", { method: "POST", body: { rules: strip(rules) } }),
  gaps: (rules) => request("/api/coverage/gaps", { method: "POST", body: { rules: strip(rules) } }),
  sampleLogs: () => request("/api/samples/logs"),
  test(rules, files, mode, mapping = {}) {
    const form = new FormData();
    form.append("rules", JSON.stringify(strip(rules)));
    form.append("mode", mode);
    form.append("field_mapping", JSON.stringify(mapping));
    files.forEach((f) => form.append("files", f, f.name));
    return upload("/api/test", form);
  },
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
  coverage: (rules) => request("/api/coverage", { method: "POST", body: { rules: strip(rules) } }),
  navigator: (rules, name, colors) => request("/api/coverage/navigator", { method: "POST", body: { rules: strip(rules), name, colors } }),
};
