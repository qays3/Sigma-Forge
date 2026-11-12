import { api } from "../api.js";
import { mappings } from "../mappings.js";
import { navigate, trackState } from "../router.js";
import { suggestMappingDrawer } from "./tools.js";
import { state } from "../state.js";
import { allowlist } from "../allowlist.js";
import { $, $$, download, esc, icons, openDrawer, plural, toast } from "../ui.js";

const MATCHES = [["equals", "is"], ["endswith", "ends with"], ["startswith", "starts with"], ["contains", "contains"]];

function allowCard(root) {
  const box = $("#allowCard", root);
  const data = allowlist.get();
  const row = (e, i) => `<tr data-i="${i}">
      <td><input class="input mono input--cell" data-k="field" value="${esc(e.field || "")}" placeholder="User" spellcheck="false"></td>
      <td><select class="select select--cell" data-k="match">${MATCHES.map(([k, l]) => `<option value="${k}" ${k === (e.match || "equals") ? "selected" : ""}>${l}</option>`).join("")}</select></td>
      <td><input class="input mono input--cell" data-k="value" value="${esc(e.value || "")}" placeholder="CORP\\svc_backup" spellcheck="false"></td>
      <td><input class="input mono input--cell" data-k="scope" value="${esc(e.scope || "")}" placeholder="all rules" spellcheck="false"></td>
      <td><input class="input input--cell" data-k="note" value="${esc(e.note || "")}" placeholder="why it is safe"></td>
      <td><button class="icon-btn" type="button" data-del="${i}" aria-label="Remove">${icons.trash}</button></td>
    </tr>`;
  box.innerHTML = `
    <div class="card__head">
      <label class="check mb-0"><input type="checkbox" id="allowOn" ${data.enabled ? "checked" : ""}> <span>Use the allow list</span></label>
      <span class="card__sub">${data.entries.length} ${data.entries.length === 1 ? "entry" : "entries"}</span>
      <div class="spacer"></div>
      <button class="btn btn--sm" type="button" id="allowAdd">${icons.spark} Add entry</button>
    </div>
    <div class="card__body">
      <p class="muted">Known good values in your own setup: admin tools, service accounts, scanners. Each entry is added to every matching rule as a filter when you convert, compare, export, deploy, test or hunt. The rule files themselves are not changed. Scope limits an entry to rules whose log source has these words, for example <span class="mono">process_creation</span> or <span class="mono">windows security</span>.</p>
      ${data.entries.length ? `<table class="table table--compact allow__table"><thead><tr><th>Field</th><th>Match</th><th>Value</th><th>Scope</th><th>Note</th><th></th></tr></thead><tbody>${data.entries.map(row).join("")}</tbody></table>` : '<p class="muted">No entries yet.</p>'}
    </div>`;
  const save = () => {
    const entries = $$("tr[data-i]", box).map((tr) => {
      const e = {};
      $$("[data-k]", tr).forEach((el) => (e[el.dataset.k] = el.value.trim()));
      return e;
    });
    allowlist.save({ enabled: $("#allowOn", box).checked, entries });
  };
  box.oninput = save;
  box.onchange = save;
  box.onclick = (ev) => {
    if (ev.target.closest("#allowAdd")) {
      save();
      const d = allowlist.get();
      d.entries.push({ field: "", match: "equals", value: "", scope: "", note: "" });
      allowlist.save(d);
      allowCard(root);
      $$("tr[data-i] [data-k=field]", box).pop()?.focus();
      return;
    }
    const del = ev.target.closest("[data-del]");
    if (del) {
      const d = allowlist.get();
      d.entries.splice(Number(del.dataset.del), 1);
      allowlist.save(d);
      allowCard(root);
      toast("Entry removed", "ok");
    }
  };
}

const PRESETS = {
  ecs: {
    name: "Elastic ECS (process and network)",
    map: {
      Image: "process.executable",
      CommandLine: "process.command_line",
      ParentImage: "process.parent.executable",
      ParentCommandLine: "process.parent.command_line",
      OriginalFileName: "process.pe.original_file_name",
      User: "user.name",
      ProcessId: "process.pid",
      CurrentDirectory: "process.working_directory",
      Hashes: "process.hash.sha256",
      DestinationIp: "destination.ip",
      DestinationPort: "destination.port",
      DestinationHostname: "destination.domain",
      SourceIp: "source.ip",
      SourcePort: "source.port",
      QueryName: "dns.question.name",
      TargetFilename: "file.path",
      TargetObject: "registry.path",
      Details: "registry.data.strings",
      Computer: "host.name",
    },
  },
  wazuh: {
    name: "Wazuh Windows event data",
    map: {
      Image: "win.eventdata.image",
      CommandLine: "win.eventdata.commandLine",
      ParentImage: "win.eventdata.parentImage",
      ParentCommandLine: "win.eventdata.parentCommandLine",
      OriginalFileName: "win.eventdata.originalFileName",
      User: "win.eventdata.user",
      TargetFilename: "win.eventdata.targetFilename",
      TargetObject: "win.eventdata.targetObject",
      DestinationIp: "win.eventdata.destinationIp",
      EventID: "win.system.eventID",
      Channel: "win.system.channel",
      Computer: "win.system.computer",
    },
  },
  cim: {
    name: "Splunk CIM Endpoint",
    map: {
      Image: "process_path",
      CommandLine: "process",
      ParentImage: "parent_process_path",
      ParentCommandLine: "parent_process",
      OriginalFileName: "original_file_name",
      User: "user",
      ProcessId: "process_id",
      ParentProcessId: "parent_process_id",
      Computer: "dest",
      DestinationIp: "dest_ip",
      DestinationPort: "dest_port",
      SourceIp: "src_ip",
      TargetFilename: "file_path",
      TargetObject: "registry_path",
    },
  },
};

function blank() {
  return { id: "", name: "New mapping", map: {} };
}

export async function mappingsView(root, route) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Mappings</div>
          <h1>Custom field mapping</h1>
          <p>Rename Sigma fields to the names in your own data. The active profile is used by Convert, Compare, Test, the editor and exports.</p>
        </div>
      </div>
      <div class="grid grid--side maps">
        <div>
          <div class="card">
            <div class="card__head"><span class="card__title">Profiles</span><div class="spacer"></div><button class="btn btn--sm" type="button" id="mapNew">${icons.spark} New</button></div>
            <ul class="list" id="mapList"></ul>
          </div>
          <div class="card mt-4">
            <div class="card__head"><span class="card__title">Suggest from my logs</span></div>
            <div class="card__body"><p class="muted">Drop a sample of your logs and get a mapping built from the field names and values.</p><button class="btn btn--sm btn--primary" type="button" id="mapSuggest">${icons.spark} Suggest a mapping</button></div>
          </div>
          <div class="card mt-4">
            <div class="card__head"><span class="card__title">Start from a preset</span></div>
            <ul class="list">${Object.entries(PRESETS)
              .map(([k, p]) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(p.name)}</div><div class="list__meta">${esc(plural(Object.keys(p.map).length, "field"))}</div></div><button class="btn btn--sm" type="button" data-preset="${k}">Use</button></li>`)
              .join("")}</ul>
          </div>
        </div>
        <div class="card" id="mapEditor"></div>
      </div>
      <h2 class="section-title mt-5" id="allow">Allow list</h2>
      <div class="card allow" id="allowCard"></div>
    </section>`;

  $("#mapSuggest", root).addEventListener("click", async () => {
    const rules = await state.rules();
    if (!rules.length) {
      toast("Add rules to the workspace first", "bad");
      return;
    }
    suggestMappingDrawer(rules, (saved) => navigate("/mappings", { profile: saved.id }));
  });
  let current = mappings.get(route.profile) || mappings.active() || mappings.all()[0] || blank();
  let rows = [];

  function toRows(map) {
    rows = Object.entries(map).map(([from, to]) => ({ from, to }));
    if (!rows.length) rows.push({ from: "", to: "" });
  }

  function collect() {
    const map = {};
    rows.forEach((r) => {
      const from = r.from.trim();
      const to = r.to.trim();
      if (from && to) map[from] = to;
    });
    return map;
  }

  function paintList() {
    const list = mappings.all();
    const active = mappings.activeId();
    $("#mapList", root).innerHTML = list.length
      ? list
          .map(
            (p) => `<li class="list__item ${p.id === current.id ? "is-current" : ""}">
              <div class="list__main"><div class="list__title">${esc(p.name)}</div><div class="list__meta">${esc(plural(Object.keys(p.map).length, "field"))}</div></div>
              ${p.id === active ? '<span class="badge badge--ok">active</span>' : ""}
              <button class="btn btn--sm" type="button" data-open="${esc(p.id)}">Edit</button>
            </li>`
          )
          .join("")
      : `<li class="list__item"><span class="muted">No profiles yet. Make one or start from a preset.</span></li>`;
  }

  function paintRows() {
    $("#mapRows", root).innerHTML = rows
      .map(
        (r, i) => `<div class="maps__row">
          <input class="input mono" data-i="${i}" data-k="from" value="${esc(r.from)}" placeholder="Sigma field" aria-label="Sigma field" spellcheck="false">
          <span class="maps__arrow" aria-hidden="true">→</span>
          <input class="input mono" data-i="${i}" data-k="to" value="${esc(r.to)}" placeholder="Your field" aria-label="Your field" spellcheck="false">
          <button class="icon-btn" type="button" data-del="${i}" aria-label="Remove row"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
        </div>`
      )
      .join("");
    $("#mapCount", root).textContent = plural(Object.keys(collect()).length, "field");
  }

  function paintEditor() {
    const active = current.id && current.id === mappings.activeId();
    $("#mapEditor", root).innerHTML = `
      <div class="card__head">
        <input class="input maps__name" id="mapName" value="${esc(current.name)}" aria-label="Profile name">
        <span class="card__sub" id="mapCount"></span>
      </div>
      <div class="card__body">
        <div class="row maps__tools">
          <button class="btn btn--sm" type="button" id="mapAddRow">${icons.spark} Add row</button>
          <button class="btn btn--sm" type="button" id="mapFill">${icons.file} Add fields from workspace</button>
          <button class="btn btn--sm" type="button" id="mapImport">${icons.upload} Import</button>
          <button class="btn btn--sm" type="button" id="mapExport">${icons.download} Export</button>
        </div>
        <div class="maps__head"><span>Sigma field</span><span></span><span>Field in your data</span><span></span></div>
        <div id="mapRows"></div>
        <div class="row mt-4">
          <button class="btn btn--primary" type="button" id="mapSave">Save</button>
          <button class="btn" type="button" id="mapActive">${active ? "Turn off" : "Save and use"}</button>
          <div class="spacer"></div>
          ${current.id ? `<button class="btn btn--danger btn--sm" type="button" id="mapDelete">${icons.trash} Delete</button>` : ""}
        </div>
      </div>`;
    paintRows();
  }

  function open(profile) {
    current = profile;
    toRows(profile.map);
    trackState({ profile: profile.id || undefined });
    paintList();
    paintEditor();
  }

  function save(activate) {
    const map = collect();
    current = mappings.save({ ...current, name: $("#mapName", root).value.trim() || "Untitled mapping", map });
    if (activate === true) mappings.setActive(current.id);
    if (activate === false) mappings.setActive("");
    open(current);
    return current;
  }

  root.addEventListener("input", (e) => {
    const input = e.target.closest("[data-i]");
    if (!input) return;
    rows[Number(input.dataset.i)][input.dataset.k] = input.value;
    $("#mapCount", root).textContent = plural(Object.keys(collect()).length, "field");
  });

  root.addEventListener("click", async (e) => {
    const t = e.target;
    const openBtn = t.closest("[data-open]");
    if (openBtn) {
      open(mappings.get(openBtn.dataset.open) || blank());
      return;
    }
    const preset = t.closest("[data-preset]");
    if (preset) {
      const p = PRESETS[preset.dataset.preset];
      open({ id: "", name: p.name, map: { ...p.map } });
      toast("Preset loaded. Save it to keep it.", "ok");
      return;
    }
    const del = t.closest("[data-del]");
    if (del) {
      rows.splice(Number(del.dataset.del), 1);
      if (!rows.length) rows.push({ from: "", to: "" });
      paintRows();
      return;
    }
    if (t.closest("#mapNew")) open(blank());
    else if (t.closest("#mapAddRow")) {
      rows.push({ from: "", to: "" });
      paintRows();
      $$("#mapRows [data-k='from']", root).pop()?.focus();
    } else if (t.closest("#mapSave")) {
      save();
      toast("Mapping saved", "ok");
    } else if (t.closest("#mapActive")) {
      const isActive = current.id && current.id === mappings.activeId();
      save(!isActive);
      toast(isActive ? "Field mapping turned off" : `${current.name} is now active`, "ok");
    } else if (t.closest("#mapDelete")) {
      mappings.remove(current.id);
      toast("Mapping deleted", "ok");
      open(mappings.all()[0] || blank());
    } else if (t.closest("#mapExport")) {
      const map = collect();
      download(`${($("#mapName", root).value || "mapping").replace(/[^\w.-]+/g, "_")}.json`, JSON.stringify({ name: $("#mapName", root).value, map }, null, 2), "application/json");
    } else if (t.closest("#mapFill")) {
      await fillFromWorkspace();
    } else if (t.closest("#mapImport")) {
      importDialog();
    }
  });

  async function fillFromWorkspace() {
    const rules = await state.rules();
    if (!rules.length) {
      toast("The workspace is empty", "bad");
      return;
    }
    try {
      const { fields } = await api.fields(rules);
      const have = new Set(rows.map((r) => r.from.trim()).filter(Boolean));
      rows = rows.filter((r) => r.from.trim() || r.to.trim());
      let added = 0;
      fields.forEach((f) => {
        if (!have.has(f.name)) {
          rows.push({ from: f.name, to: "" });
          added += 1;
        }
      });
      if (!rows.length) rows.push({ from: "", to: "" });
      paintRows();
      toast(added ? `Added ${plural(added, "field")} from your rules. Fill in the names you use.` : "Every field in your rules is already listed", "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
  }

  function importDialog() {
    const body = `
      <p class="muted">Paste JSON (an object of Sigma field to your field), a pySigma fieldmappings block, or one mapping per line like <span class="mono">Image: process.executable</span> or <span class="mono">Image,process.executable</span>.</p>
      <textarea class="textarea" id="mapPaste" spellcheck="false"></textarea>
      <div class="row mt-4">
        <label class="btn" for="mapFile">${icons.upload} Pick a file</label>
        <input class="hidden-input" type="file" id="mapFile" accept=".json,.csv,.txt,.yml,.yaml">
        <div class="spacer"></div>
        <button class="btn btn--primary" type="button" id="mapDoImport">Import</button>
      </div>`;
    openDrawer("Import field mapping", body, (panel) => {
      $("#mapFile", panel).addEventListener("change", async (e) => {
        const file = e.target.files?.[0];
        if (file) $("#mapPaste", panel).value = await file.text();
      });
      $("#mapDoImport", panel).addEventListener("click", () => {
        try {
          const text = $("#mapPaste", panel).value.replace(/^\s*fieldmappings:\s*$/m, "");
          const map = mappings.parse(text.replace(/^\s{2,}/gm, ""));
          const count = Object.keys(map).length;
          if (!count) {
            toast("No mappings found in that text", "bad");
            return;
          }
          const merged = { ...collect(), ...map };
          toRows(merged);
          paintRows();
          document.querySelector("#drawer [data-close]")?.click();
          toast(`Imported ${plural(count, "mapping")}. Save to keep them.`, "ok");
        } catch (err) {
          toast(`Could not read that: ${err.message}`, "bad");
        }
      });
    });
  }

  toRows(current.map);
  paintList();
  paintEditor();
  allowCard(root);
  if (route?.section === "allow") $("#allow", root)?.scrollIntoView({ block: "start" });
  return null;
}
