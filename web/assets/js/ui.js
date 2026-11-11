const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

export function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ESCAPES[ch]);
}

export function html(strings, ...values) {
  return strings.reduce((out, str, i) => {
    const value = i < values.length ? values[i] : "";
    const text = Array.isArray(value) ? value.join("") : value instanceof SafeHTML ? value.value : esc(value);
    return out + str + text;
  }, "");
}

class SafeHTML {
  constructor(value) {
    this.value = value;
  }
}

export function raw(value) {
  return new SafeHTML(value);
}

export function $(selector, root = document) {
  return root.querySelector(selector);
}

export function $$(selector, root = document) {
  return Array.from(root.querySelectorAll(selector));
}

export const icons = {
  upload: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V4M6 10l6-6 6 6M4 20h16"/></svg>',
  copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg>',
  download: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v12M6 10l6 6 6-6M4 20h16"/></svg>',
  trash: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>',
  play: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 4l13 8-13 8z"/></svg>',
  folder: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
  file: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/></svg>',
  spark: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6"/></svg>',
  external: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></svg>',
  grid: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>',
};

export function levelBadge(level) {
  if (!level) return '<span class="badge">none</span>';
  return `<span class="badge badge--${esc(level)}">${esc(level)}</span>`;
}

export function toast(message, kind = "info", timeout = 3200) {
  const box = $("#toasts");
  const node = document.createElement("div");
  node.className = `toast${kind === "bad" ? " toast--bad" : kind === "ok" ? " toast--ok" : ""}`;
  node.textContent = message;
  box.appendChild(node);
  setTimeout(() => {
    node.classList.add("is-leaving");
    setTimeout(() => node.remove(), 260);
  }, timeout);
}

export async function copyText(text, label = "Copied to clipboard") {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  toast(label, "ok");
}

export function download(filename, text, type = "text/plain") {
  const blob = new Blob([text], { type: `${type};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

let lastFocus = null;

export function openDrawer(title, bodyHtml, onReady) {
  const drawer = $("#drawer");
  lastFocus = document.activeElement;
  $("#drawerTitle").textContent = title;
  $("#drawerBody").innerHTML = bodyHtml;
  drawer.classList.add("is-open");
  drawer.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  const closeBtn = drawer.querySelector(".drawer__head [data-close]");
  closeBtn?.focus();
  if (onReady) onReady($("#drawerBody"));
}

export function setDrawerBody(bodyHtml, onReady) {
  $("#drawerBody").innerHTML = bodyHtml;
  if (onReady) onReady($("#drawerBody"));
}

export function closeDrawer() {
  const drawer = $("#drawer");
  if (!drawer.classList.contains("is-open")) return;
  drawer.classList.remove("is-open");
  drawer.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
  if (lastFocus && document.contains(lastFocus)) lastFocus.focus();
}

export function initDrawer() {
  const drawer = $("#drawer");
  drawer.addEventListener("click", (e) => {
    if (e.target.closest("[data-close]")) closeDrawer();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
  });
}

export const skeleton = {
  stats(count = 4) {
    return `<div class="stats">${Array.from({ length: count }, () => '<div class="skeleton sk-stat"></div>').join("")}</div>`;
  },
  card(lines = 4) {
    return `<div class="card"><div class="card__body"><div class="skeleton sk-title"></div>${Array.from({ length: lines }, (_, i) => `<div class="skeleton sk-line ${i % 3 === 2 ? "sk-line--sm" : i % 2 ? "sk-line--md" : ""}"></div>`).join("")}</div></div>`;
  },
  blocks(count = 3) {
    return Array.from({ length: count }, () => '<div class="skeleton sk-block"></div>').join("");
  },
  rows(count = 8) {
    return Array.from({ length: count }, () => '<div class="skeleton sk-row"></div>').join("");
  },
  matrix(cols = 8, cells = 10) {
    const col = `<div class="matrix__col"><div class="skeleton sk-head"></div>${Array.from({ length: cells }, () => '<div class="skeleton sk-cell"></div>').join("")}</div>`;
    return `<div class="matrix-wrap"><div class="matrix">${Array.from({ length: cols }, () => col).join("")}</div></div>`;
  },
};

export const LOGO_GIF = "/assets/img/logo.gif";

export function logo(size = 48, cls = "") {
  return `<img class="logo-anim ${cls}" src="${LOGO_GIF}" alt="" width="${size}" height="${size}" loading="lazy">`;
}

export function forging(text = "Forging") {
  return `<div class="forging" role="status" aria-live="polite">${logo(44, "forging__logo")}<div class="forging__body"><div class="forging__text">${esc(text)}</div><div class="forging__bar"><span></span></div></div></div>`;
}

export function emptyState(title, text, actionHtml = "") {
  return `<div class="empty">${logo(96, "empty__logo")}<h3>${esc(title)}</h3><p>${esc(text)}</p>${actionHtml}</div>`;
}

export function hideSplash() {
  const splash = document.getElementById("splash");
  if (!splash || splash.classList.contains("is-done")) return;
  splash.classList.add("is-done");
  setTimeout(() => splash.remove(), 600);
}

export function splashText(text) {
  const el = document.getElementById("splashText");
  if (el) el.textContent = text;
}

export function debounce(fn, wait = 200) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

export function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}
