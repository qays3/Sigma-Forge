import { $$, closeDrawer } from "./ui.js";

const routes = new Map();
let current = null;
let outlet = null;

export function route(path, name, view) {
  routes.set(path, { name, view });
}

function match(pathname) {
  const clean = pathname.replace(/\/+$/, "") || "/";
  return routes.get(clean) || routes.get("*");
}

async function render() {
  const entry = match(location.pathname);
  if (!entry) return;
  if (current?.destroy) current.destroy();
  closeDrawer();
  $$(".nav__link").forEach((a) => {
    const active = a.dataset.route === entry.name;
    a.classList.toggle("is-active", active);
    if (active) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  document.getElementById("mainNav")?.classList.remove("is-open");
  document.getElementById("navToggle")?.setAttribute("aria-expanded", "false");
  const fresh = outlet.cloneNode(false);
  outlet.replaceWith(fresh);
  outlet = fresh;
  outlet.dataset.route = entry.name;
  current = (await entry.view(outlet, routeState())) || null;
  document.title = entry.name === "workspace" ? "Sigma Forge" : `${entry.name === "yara" ? "YARA" : entry.name[0].toUpperCase() + entry.name.slice(1)} | Sigma Forge`;
  window.scrollTo({ top: 0 });
}

function cleanPath(path) {
  return (path.split(/[?#]/)[0].replace(/\/+$/, "")) || "/";
}

export function routeState() {
  return { ...(history.state || {}) };
}

export function trackState(patch) {
  const next = { ...(history.state || {}), ...patch };
  Object.keys(next).forEach((k) => next[k] === undefined && delete next[k]);
  history.replaceState(next, "", location.pathname);
}

export function navigate(path, state = {}) {
  const target = cleanPath(path);
  if (target === location.pathname && !Object.keys(state).length) return;
  history.pushState(state, "", target);
  render();
}

export function startRouter(target) {
  outlet = target;
  document.addEventListener("click", (e) => {
    const link = e.target.closest("a[data-link]");
    if (!link || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    navigate(link.getAttribute("href"));
  });
  window.addEventListener("popstate", render);
  if (location.search || location.hash) history.replaceState(history.state || {}, "", cleanPath(location.pathname));
  render();
}
