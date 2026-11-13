const DB_NAME = "sigma-forge";
const DB_VERSION = 1;
const STORE = "rules";

let dbPromise = null;
let memory = null;
let remote = false;
let remoteVersion = -1;
let reviewStates = {};
const listeners = new Set();

async function api(method, path, body) {
  const res = await fetch(path, { method, headers: { "Content-Type": "application/json", Accept: "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}

async function pull() {
  const data = await api("GET", "/api/team/rules");
  remoteVersion = data.version;
  reviewStates = data.reviews || {};
  memory = (data.rules || []).map((r) => ({ id: r.id, name: r.name, content: r.content, size: r.size, added: r.added, by: r.by, updated: r.updated }));
  return memory;
}

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve) => {
    if (!("indexedDB" in window)) {
      resolve(null);
      return;
    }
    let req;
    try {
      req = indexedDB.open(DB_NAME, DB_VERSION);
    } catch {
      resolve(null);
      return;
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: "id" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
  });
  return dbPromise;
}

function tx(db, mode) {
  return db.transaction(STORE, mode).objectStore(STORE);
}

function wrap(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function hash(text) {
  if (crypto?.subtle) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  let h = 0;
  for (let i = 0; i < text.length; i += 1) h = (Math.imul(31, h) + text.charCodeAt(i)) | 0;
  return `h${(h >>> 0).toString(16)}`;
}

function emit() {
  listeners.forEach((fn) => fn());
}

export const store = {
  useRemote() {
    remote = true;
    memory = null;
    const refresh = async () => {
      try {
        const before = remoteVersion;
        await pull();
        if (remoteVersion !== before) emit();
      } catch {
        return;
      }
    };
    setInterval(refresh, 30000);
    window.addEventListener("focus", refresh);
  },

  isRemote() {
    return remote;
  },

  review(name) {
    return reviewStates[name] || { status: "none" };
  },

  async refresh() {
    if (!remote) return this.all();
    await pull();
    emit();
    return memory;
  },

  onChange(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },

  async all() {
    if (memory) return memory;
    if (remote) return pull();
    const db = await openDb();
    if (!db) {
      memory = [];
      return memory;
    }
    const items = await wrap(tx(db, "readonly").getAll());
    const byContent = new Map();
    const dropped = [];
    for (const item of items.sort((a, b) => (b.added || 0) - (a.added || 0))) {
      if (byContent.has(item.content)) dropped.push(item.id);
      else byContent.set(item.content, item);
    }
    if (dropped.length) {
      const os = tx(db, "readwrite");
      await Promise.all(dropped.map((id) => wrap(os.delete(id))));
    }
    memory = Array.from(byContent.values()).sort((a, b) => a.name.localeCompare(b.name));
    return memory;
  },

  async add(files) {
    if (remote) {
      const res = await api("POST", "/api/team/rules", { files: files.map((f) => ({ name: f.name, content: f.content })) });
      await pull();
      emit();
      return res.added;
    }
    const current = await this.all();
    const byId = new Map(current.map((r) => [r.id, r]));
    const byContent = new Map(current.map((r) => [r.content, r]));
    const replaced = [];
    let added = 0;
    for (const file of files) {
      const id = await hash(`${file.name}\n${file.content}`);
      if (byId.has(id)) continue;
      const same = byContent.get(file.content);
      if (same) {
        byId.delete(same.id);
        replaced.push(same.id);
      }
      const item = { id, name: file.name, content: file.content, size: file.content.length, added: Date.now() };
      byId.set(id, item);
      byContent.set(file.content, item);
      if (!same) added += 1;
    }
    const items = Array.from(byId.values()).sort((a, b) => a.name.localeCompare(b.name));
    const db = await openDb();
    if (db) {
      const os = tx(db, "readwrite");
      await Promise.all([...replaced.map((rid) => wrap(os.delete(rid))), ...items.map((item) => wrap(os.put(item)))]);
    }
    memory = items;
    emit();
    return added;
  },

  async replace(oldId, file) {
    if (remote) {
      const item = await api("PUT", "/api/team/rules", { old_id: oldId || "", name: file.name, content: file.content });
      await pull();
      emit();
      return memory.find((r) => r.id === item.id) || null;
    }
    const db = await openDb();
    if (oldId) {
      if (db) await wrap(tx(db, "readwrite").delete(oldId));
      memory = (memory || []).filter((r) => r.id !== oldId);
    }
    await this.add([file]);
    const items = await this.all();
    return items.find((r) => r.name === file.name && r.content === file.content) || null;
  },

  async remove(id) {
    if (remote) {
      await api("POST", "/api/team/rules/remove", { ids: [id] });
      await pull();
      emit();
      return;
    }
    const db = await openDb();
    if (db) await wrap(tx(db, "readwrite").delete(id));
    memory = (memory || []).filter((r) => r.id !== id);
    emit();
  },

  async removeWhere(test) {
    const items = await this.all();
    const gone = items.filter(test);
    if (!gone.length) return 0;
    if (remote) {
      await api("POST", "/api/team/rules/remove", { ids: gone.map((r) => r.id) });
      await pull();
      emit();
      return gone.length;
    }
    const db = await openDb();
    if (db) {
      const os = tx(db, "readwrite");
      await Promise.all(gone.map((r) => wrap(os.delete(r.id))));
    }
    const ids = new Set(gone.map((r) => r.id));
    memory = items.filter((r) => !ids.has(r.id));
    emit();
    return gone.length;
  },

  async clear() {
    if (remote) {
      await api("POST", "/api/team/rules/clear");
      await pull();
      emit();
      return;
    }
    const db = await openDb();
    if (db) await wrap(tx(db, "readwrite").clear());
    memory = [];
    emit();
  },
};
