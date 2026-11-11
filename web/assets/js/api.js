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

export const api = {
  health: () => request("/api/health"),
  targets: () => request("/api/targets"),
  attack: () => request("/api/attack"),
  samples: () => request("/api/samples"),
  analyze: (rules) => request("/api/analyze", { method: "POST", body: { rules: strip(rules) } }),
  convert: (rules, target, format, options) => request("/api/convert", { method: "POST", body: { rules: strip(rules), target, format, options } }),
  coverage: (rules) => request("/api/coverage", { method: "POST", body: { rules: strip(rules) } }),
  navigator: (rules, name, colors) => request("/api/coverage/navigator", { method: "POST", body: { rules: strip(rules), name, colors } }),
};
