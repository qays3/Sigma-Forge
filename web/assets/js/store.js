const DB_NAME = "sigma-forge";
const DB_VERSION = 1;
const STORE = "rules";

let dbPromise = null;
let memory = null;
const listeners = new Set();

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
  onChange(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },

  async all() {
    if (memory) return memory;
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

  async remove(id) {
    const db = await openDb();
    if (db) await wrap(tx(db, "readwrite").delete(id));
    memory = (memory || []).filter((r) => r.id !== id);
    emit();
  },

  async clear() {
    const db = await openDb();
    if (db) await wrap(tx(db, "readwrite").clear());
    memory = [];
    emit();
  },
};
