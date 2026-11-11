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
  outlet.innerHTML = "";
  const params = new URLSearchParams(location.search);
  current = (await entry.view(outlet, params)) || null;
  document.title = entry.name === "workspace" ? "Sigma Forge" : `${entry.name[0].toUpperCase()}${entry.name.slice(1)} | Sigma Forge`;
  window.scrollTo({ top: 0 });
}

export function navigate(path) {
  if (path === location.pathname + location.search) return;
  history.pushState({}, "", path);
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
  render();
}
