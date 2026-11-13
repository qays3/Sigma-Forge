import { can, teamApi, teamState } from "../team.js";
import { $, download, emptyState, esc, skeleton, toast } from "../ui.js";

export async function teamView(root) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Users</div>
          <h1>Users and audit log</h1>
          <p>Add people, set what they can do, and see who changed what. Viewers can look and run checks. Editors change rules, cases and run fire checks. Reviewers also approve changes. Admins also manage users.</p>
        </div>
      </div>
      <div id="tmBody">${skeleton.rows(5)}</div>
    </section>`;
  const body = $("#tmBody", root);
  if (!teamState.auth || !can("admin")) {
    body.innerHTML = `<div class="card">${emptyState(teamState.auth ? "Admins only" : "Team mode is off", teamState.auth ? "Ask an admin to manage users." : "Start Sigma Forge with SIGMA_FORGE_AUTH=1 to add users.")}</div>`;
    return null;
  }
  const roles = teamState.roles.length ? teamState.roles : ["viewer", "editor", "reviewer", "admin"];
  body.innerHTML = `
    <div class="grid grid--2 tm__grid">
      <div class="card">
        <div class="card__head"><span class="card__title">Users</span></div>
        <div class="card__body card__body--flush"><table class="table tm__users"><thead><tr><th>User</th><th>Role</th><th>Last sign in</th><th></th></tr></thead><tbody id="tmUsers"></tbody></table></div>
      </div>
      <div class="card">
        <div class="card__head"><span class="card__title">Add a user</span></div>
        <form class="card__body" id="tmAdd" autocomplete="off">
          <label class="field"><span class="field__label">User name</span><input class="input" id="tmName" maxlength="40" required></label>
          <label class="field"><span class="field__label">First password</span><input class="input" id="tmPass" type="password" autocomplete="new-password" required></label>
          <label class="field"><span class="field__label">Role</span><select class="select" id="tmRole">${roles.map((r) => `<option ${r === "editor" ? "selected" : ""}>${r}</option>`).join("")}</select></label>
          <p class="muted">At least 10 characters with upper and lower case letters and a number. Give it to them in person.</p>
          <button class="btn btn--primary" type="submit">Add user</button>
        </form>
      </div>
    </div>
    <div class="card mt-5">
      <div class="card__head tm__head"><span class="card__title">Audit log</span><div class="spacer"></div><input class="input input--sm" id="tmFilter" placeholder="Filter by user or action"><button class="btn btn--sm" type="button" id="tmCsv">CSV</button></div>
      <div class="card__body card__body--flush"><table class="table table--compact tm__audit"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead><tbody id="tmAudit"></tbody></table></div>
    </div>`;
  let audit = [];
  const loadUsers = async () => {
    const data = await teamApi.get("/api/team/users");
    $("#tmUsers", body).innerHTML = data.users
      .map((u) => `<tr data-u="${esc(u.username)}"><td data-label="User"><span><span class="mono">${esc(u.username)}</span>${u.disabled ? ' <span class="badge badge--bad">off</span>' : ""}${u.username === teamState.user.username ? ' <span class="badge">you</span>' : ""}</span></td>
        <td data-label="Role"><select class="select select--sm" data-role>${roles.map((r) => `<option ${r === u.role ? "selected" : ""}>${r}</option>`).join("")}</select></td>
        <td class="muted" data-label="Last sign in">${esc(u.last_login || "never")}</td>
        <td class="tm__acts"><button class="btn btn--sm" type="button" data-act="toggle">${u.disabled ? "Turn on" : "Turn off"}</button><button class="btn btn--sm" type="button" data-act="reset">Reset password</button>${u.username === teamState.user.username ? "" : '<button class="btn btn--sm btn--ghost btn--danger" type="button" data-act="delete">Delete</button>'}</td></tr>`)
      .join("");
  };
  const paintAudit = () => {
    const q = $("#tmFilter", body).value.trim().toLowerCase();
    const list = audit.filter((e) => !q || `${e.user} ${e.action} ${e.detail}`.toLowerCase().includes(q)).slice(0, 400);
    $("#tmAudit", body).innerHTML = list.map((e) => `<tr><td class="mono" data-label="Time">${esc(e.time)}</td><td class="mono" data-label="User">${esc(e.user)}</td><td data-label="Action">${esc(e.action)}${e.status >= 400 ? ` <span class="badge badge--bad">${e.status}</span>` : ""}</td><td class="muted" data-label="Detail">${esc(e.detail)}</td><td class="mono muted" data-label="IP">${esc(e.ip)}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">No entries.</td></tr>';
  };
  const loadAudit = async () => {
    audit = (await teamApi.get("/api/team/audit?limit=2000")).entries;
    paintAudit();
  };
  try {
    await Promise.all([loadUsers(), loadAudit()]);
  } catch (err) {
    body.innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
    return null;
  }
  $("#tmAdd", body).addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await teamApi.post("/api/team/users", { username: $("#tmName", body).value, password: $("#tmPass", body).value, role: $("#tmRole", body).value });
      $("#tmName", body).value = "";
      $("#tmPass", body).value = "";
      toast("User added", "ok");
      await Promise.all([loadUsers(), loadAudit()]);
    } catch (err) {
      toast(err.message, "bad");
    }
  });
  $("#tmUsers", body).addEventListener("change", async (e) => {
    const sel = e.target.closest("[data-role]");
    if (!sel) return;
    const name = sel.closest("[data-u]").dataset.u;
    try {
      await teamApi.send("PUT", `/api/team/users/${encodeURIComponent(name)}`, { role: sel.value });
      toast(`${name} is now ${sel.value}`, "ok");
      await loadAudit();
    } catch (err) {
      toast(err.message, "bad");
      await loadUsers();
    }
  });
  $("#tmUsers", body).addEventListener("click", async (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const name = b.closest("[data-u]").dataset.u;
    try {
      if (b.dataset.act === "toggle") {
        await teamApi.send("PUT", `/api/team/users/${encodeURIComponent(name)}`, { disabled: b.textContent.trim() === "Turn off" });
      } else if (b.dataset.act === "reset") {
        const tr = b.closest("tr");
        if (!tr.nextElementSibling?.classList.contains("tm__reset")) {
          tr.insertAdjacentHTML("afterend", `<tr class="tm__reset"><td colspan="4"><form class="row" data-reset="${esc(name)}"><input class="input toolbar__grow" type="password" placeholder="New password for ${esc(name)}" autocomplete="new-password" required><button class="btn btn--sm btn--primary" type="submit">Set password</button></form></td></tr>`);
        }
        return;
      } else if (b.dataset.act === "delete") {
        if (b.dataset.sure !== "1") {
          b.dataset.sure = "1";
          b.textContent = "Click again";
          return;
        }
        await teamApi.send("DELETE", `/api/team/users/${encodeURIComponent(name)}`);
      }
      await Promise.all([loadUsers(), loadAudit()]);
    } catch (err) {
      toast(err.message, "bad");
    }
  });
  $("#tmUsers", body).addEventListener("submit", async (e) => {
    const f = e.target.closest("[data-reset]");
    if (!f) return;
    e.preventDefault();
    try {
      await teamApi.send("PUT", `/api/team/users/${encodeURIComponent(f.dataset.reset)}`, { password: $("input", f).value });
      toast("Password set. Their old sessions are signed out.", "ok");
      await Promise.all([loadUsers(), loadAudit()]);
    } catch (err) {
      toast(err.message, "bad");
    }
  });
  $("#tmFilter", body).addEventListener("input", paintAudit);
  $("#tmCsv", body).addEventListener("click", () => {
    const cell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    download("sigma-forge-audit.csv", ["time,user,action,detail,ip,status", ...audit.map((e) => [e.time, e.user, e.action, e.detail, e.ip, e.status].map(cell).join(","))].join("\n"), "text/csv");
  });

  return null;
}
