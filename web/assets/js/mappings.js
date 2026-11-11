const KEY = "sigma-forge-mappings";

function read() {
  try {
    const data = JSON.parse(localStorage.getItem(KEY));
    if (data && Array.isArray(data.profiles)) return data;
  } catch {
    return { profiles: [], active: "" };
  }
  return { profiles: [], active: "" };
}

function write(data) {
  try {
    localStorage.setItem(KEY, JSON.stringify(data));
  } catch {
    return;
  }
}

function uid() {
  return `m${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;
}

export const mappings = {
  all() {
    return read().profiles;
  },

  get(id) {
    return read().profiles.find((p) => p.id === id) || null;
  },

  activeId() {
    const data = read();
    return data.profiles.some((p) => p.id === data.active) ? data.active : "";
  },

  active() {
    const id = this.activeId();
    return id ? this.get(id) : null;
  },

  activeMap() {
    return this.active()?.map || {};
  },

  setActive(id) {
    const data = read();
    data.active = id || "";
    write(data);
  },

  save(profile) {
    const data = read();
    const item = { id: profile.id || uid(), name: profile.name || "Untitled mapping", map: profile.map || {}, updated: Date.now() };
    const i = data.profiles.findIndex((p) => p.id === item.id);
    if (i >= 0) data.profiles[i] = item;
    else data.profiles.push(item);
    write(data);
    return item;
  },

  remove(id) {
    const data = read();
    data.profiles = data.profiles.filter((p) => p.id !== id);
    if (data.active === id) data.active = "";
    write(data);
  },

  parse(text) {
    const trimmed = text.trim();
    if (!trimmed) return {};
    if (trimmed.startsWith("{")) {
      const data = JSON.parse(trimmed);
      const map = data.map && typeof data.map === "object" ? data.map : data.fieldmappings && typeof data.fieldmappings === "object" ? data.fieldmappings : data;
      const out = {};
      Object.entries(map).forEach(([k, v]) => {
        const value = Array.isArray(v) ? v[0] : v;
        if (typeof value === "string" && value.trim()) out[k.trim()] = value.trim();
      });
      return out;
    }
    const out = {};
    trimmed.split(/\r?\n/).forEach((line) => {
      const clean = line.replace(/#.*$/, "").trim();
      if (!clean) return;
      const parts = clean.split(/\s*(?:,|;|\t|:|=>|->)\s*/);
      if (parts.length >= 2 && parts[0] && parts[1]) out[parts[0]] = parts[1];
    });
    return out;
  },
};

export function mappingOptions(selected) {
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const list = mappings.all();
  return `<option value="">No field mapping</option>${list.map((p) => `<option value="${esc(p.id)}" ${p.id === selected ? "selected" : ""}>${esc(p.name)} (${Object.keys(p.map).length})</option>`).join("")}`;
}
