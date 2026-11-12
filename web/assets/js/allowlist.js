const KEY = "sigma-forge-allowlist";

function read() {
  try {
    const data = JSON.parse(localStorage.getItem(KEY));
    if (data && Array.isArray(data.entries)) return { enabled: data.enabled !== false, entries: data.entries };
  } catch {
    return { enabled: true, entries: [] };
  }
  return { enabled: true, entries: [] };
}

function write(data) {
  try {
    localStorage.setItem(KEY, JSON.stringify(data));
  } catch {
    return false;
  }
  return true;
}

export const allowlist = {
  get: read,
  save: write,
  active() {
    const data = read();
    return data.enabled ? data.entries.filter((e) => e.field && e.value) : [];
  },
};
