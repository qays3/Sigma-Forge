import { $, esc, logo, toast } from "./ui.js";

export const teamState = { auth: false, user: null, requireReview: false, setup: false, roles: [] };

export function patchFetch() {
  const raw = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    const same = url.startsWith("/") || url.startsWith(location.origin);
    if (same) {
      const headers = new Headers(init.headers || (typeof input !== "string" ? input.headers : undefined));
      headers.set("X-Sigma-Forge", "1");
      init = { ...init, headers, credentials: "same-origin" };
    }
    const res = await raw(input, init);
    if (same && res.status === 401 && teamState.auth && !url.includes("/api/auth/")) {
      toast("Your session ended. Sign in again.", "bad");
      setTimeout(() => location.reload(), 900);
    }
    return res;
  };
}

async function post(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}

export async function loadTeam() {
  try {
    const res = await fetch("/api/auth/me", { headers: { Accept: "application/json" } });
    const me = await res.json();
    Object.assign(teamState, { auth: !!me.auth, user: me.user, requireReview: !!me.require_review, setup: !!me.setup_needed, roles: me.roles || [] });
  } catch {
    teamState.auth = false;
  }
  return teamState;
}

export function can(action) {
  if (!teamState.auth) return true;
  const role = teamState.user?.role || "viewer";
  if (action === "admin") return role === "admin";
  if (action === "review") return role === "admin" || role === "reviewer";
  if (action === "write") return role !== "viewer";
  return true;
}

export function showLogin(main) {
  const setup = teamState.setup;
  document.documentElement.setAttribute("data-locked", "1");
  main.innerHTML = `
    <section class="login">
      <form class="card login__card" id="loginForm" autocomplete="on">
        <div class="login__brand">${logo(56, "login__logo")}<div><div class="login__title">Sigma <span>Forge</span></div><div class="muted">${setup ? "Create the first admin account" : "Sign in to your team"}</div></div></div>
        ${setup ? '<div class="notice mt-4">Team mode is on and there are no users yet. The account you make now is the admin.</div>' : ""}
        <label class="field mt-4"><span class="field__label">User name</span><input class="input" name="username" id="lgUser" autocomplete="username" required maxlength="40" autofocus></label>
        <label class="field"><span class="field__label">Password</span><input class="input" name="password" id="lgPass" type="password" autocomplete="${setup ? "new-password" : "current-password"}" required></label>
        ${setup ? '<p class="muted">At least 10 characters with upper and lower case letters and a number.</p>' : ""}
        <div id="lgErr"></div>
        <button class="btn btn--primary login__btn" type="submit" id="lgGo">${setup ? "Create admin and sign in" : "Sign in"}</button>
      </form>
    </section>`;
  $("#loginForm", main).addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#lgGo", main);
    btn.disabled = true;
    $("#lgErr", main).innerHTML = "";
    try {
      await post(setup ? "/api/auth/setup" : "/api/auth/login", { username: $("#lgUser", main).value, password: $("#lgPass", main).value });
      location.reload();
    } catch (err) {
      $("#lgErr", main).innerHTML = `<div class="notice notice--bad mt-4">${esc(err.message)}</div>`;
      btn.disabled = false;
    }
  });
}

export function paintUserBox() {
  const box = $("#userBox");
  const nav = $("#teamNav");
  if (!teamState.auth || !teamState.user) {
    if (box) box.hidden = true;
    if (nav) nav.hidden = true;
    return;
  }
  nav.hidden = false;
  $("#navTeamAdmin").hidden = teamState.user.role !== "admin";
  box.hidden = false;
  box.innerHTML = `<span class="user-box__avatar" aria-hidden="true">${esc(teamState.user.username.slice(0, 2).toUpperCase())}</span><span class="user-box__text"><span class="user-box__name">${esc(teamState.user.username)}</span><span class="user-box__role">${esc(teamState.user.role)}</span></span><button class="icon-btn" type="button" id="logoutBtn" title="Sign out" aria-label="Sign out"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10"/></svg></button>`;
  $("#logoutBtn").addEventListener("click", async () => {
    await post("/api/auth/logout").catch(() => null);
    location.reload();
  });
}

export const teamApi = {
  post,
  async get(path) {
    const res = await fetch(path, { headers: { Accept: "application/json" } });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
    return data;
  },
  async send(method, path, body) {
    const res = await fetch(path, { method, headers: { "Content-Type": "application/json", Accept: "application/json" }, body: body ? JSON.stringify(body) : undefined });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
    return data;
  },
};
