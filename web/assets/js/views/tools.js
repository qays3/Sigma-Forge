import { api } from "../api.js";
import { mappings } from "../mappings.js";
import { navigate } from "../router.js";
import { store } from "../store.js";
import { fileChips, pretty, readJson, writeJson } from "../shared.js";
import { $, $$, copyText, download, esc, icons, levelBadge, logo, openDrawer, plural, setDrawerBody, toast } from "../ui.js";

const LOADING = '<div class="skeleton sk-title"></div><div class="skeleton sk-block"></div><div class="skeleton sk-line"></div>';

function dropzone(id, title, text, accept, multiple = true) {
  return `<label class="dropzone dropzone--row" for="${id}">
    ${logo(36, "dropzone__logo")}
    <span class="dropzone__body"><span class="dropzone__title">${esc(title)}</span><span class="dropzone__text">${esc(text)}</span></span>
    <input class="hidden-input" type="file" id="${id}" ${multiple ? "multiple" : ""} accept="${esc(accept)}">
  </label>`;
}

function bindDrop(panel, inputId, onFiles) {
  const input = $(`#${inputId}`, panel);
  const zone = input.closest(".dropzone");
  input.addEventListener("change", () => onFiles(Array.from(input.files || [])));
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("is-over");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("is-over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("is-over");
    onFiles(Array.from(e.dataTransfer.files || []));
  });
}

export async function sysmonDrawer(rules) {
  openDrawer("Logging setup", LOADING);
  let res;
  try {
    res = await api.sysmon(rules);
  } catch (err) {
    setDrawerBody(`<div class="notice notice--bad">${esc(err.message)}</div>`);
    return;
  }
  const types = res.types
    .map((t) => `<tr><td><span class="mono">${esc(t.event)}</span> <span class="muted">event ${t.id}</span></td><td>${t.rules}</td><td>${t.all ? '<span class="badge badge--warn">all events</span>' : t.conditions}</td><td class="muted">${t.all ? esc(`Needed by ${t.wide.slice(0, 2).join(", ")}${t.wide.length > 2 ? "..." : ""}`) : t.dropped.length ? esc(`Not in Sysmon: ${t.dropped.join(", ")}`) : ""}</td></tr>`)
    .join("");
  setDrawerBody(`
    <p class="muted">Turn on only the logs your rules read. The Sysmon config keeps the events your rules look at, so you collect less noise. The commands set the Windows audit policy and PowerShell logging.</p>
    ${res.xml ? `<div class="card mt-4"><div class="card__head"><span class="card__title">Sysmon config</span><span class="card__sub">${esc(plural(res.types.length, "event type"))}</span><div class="spacer"></div><button class="btn btn--sm" type="button" data-sx="copyxml">${icons.copy} Copy</button><button class="btn btn--sm btn--primary" type="button" data-sx="xml">${icons.download} sysmon-sigma-forge.xml</button></div>
      <div class="card__body card__body--flush table-wrap"><table class="table table--compact"><thead><tr><th>Event</th><th>Rules</th><th>Conditions</th><th>Note</th></tr></thead><tbody>${types}</tbody></table></div></div>` : '<div class="notice mt-4">None of these rules need Sysmon.</div>'}
    ${res.audit.length ? `<div class="card mt-4"><div class="card__head"><span class="card__title">Audit policy</span><span class="card__sub">${esc(plural(res.audit.length, "setting"))}</span></div><ul class="list">${res.audit.map((a) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(a.subcategory)}</div><div class="list__meta">${esc(a.why)} · events ${esc(a.ids.join(", "))}</div></div></li>`).join("")}</ul></div>` : ""}
    ${res.registry.length ? `<div class="card mt-4"><div class="card__head"><span class="card__title">Registry settings</span></div><ul class="list">${res.registry.map((r) => `<li class="list__item"><div class="list__main"><div class="list__title mono">${esc(r.name)} = ${esc(r.value)}</div><div class="list__meta mono">${esc(r.path)}</div><div class="list__meta">${esc(r.why)}</div></div></li>`).join("")}</ul></div>` : ""}
    ${res.script ? `<div class="card mt-4"><div class="card__head"><span class="card__title">Run as admin</span><div class="spacer"></div><button class="btn btn--sm" type="button" data-sx="copyscript">${icons.copy} Copy</button><button class="btn btn--sm" type="button" data-sx="script">${icons.download} .cmd</button></div><pre class="code">${esc(res.script)}</pre></div>` : ""}
    ${res.skipped.length ? `<details class="mt-4"><summary class="muted">${esc(plural(res.skipped.length, "rule"))} not covered here</summary><ul class="list">${res.skipped.slice(0, 200).map((s) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(s.title)}</div><div class="list__meta">${esc(s.reason)}</div></div></li>`).join("")}</ul></details>` : ""}`, (panel) => {
    panel.addEventListener("click", (e) => {
      const b = e.target.closest("[data-sx]");
      if (!b) return;
      const a = b.dataset.sx;
      if (a === "xml") download("sysmon-sigma-forge.xml", res.xml, "application/xml");
      if (a === "copyxml") copyText(res.xml, "Sysmon config copied");
      if (a === "script") download("sigma-forge-logging.cmd", `@echo off\r\n${res.script.replace(/\n/g, "\r\n")}\r\n`, "text/plain");
      if (a === "copyscript") copyText(res.script, "Commands copied");
    });
  });
}

const STATE_LABEL = { covered: ["Covered", "ok"], partial: ["Partly", "warn"], gap: ["Gap", "bad"] };

export function threatDrawer(rules) {
  openDrawer("Threat report to coverage", `
    <p class="muted">Paste a threat report, a blog post or an advisory. Sigma Forge finds the ATT&amp;CK techniques and the IOCs in it, shows which ones your rules cover and suggests SigmaHQ rules for the gaps.</p>
    <textarea class="textarea" id="trText" rows="10" placeholder="Paste the report text here"></textarea>
    <div class="row mt-4"><div class="spacer"></div><button class="btn btn--primary" type="button" id="trGo">${icons.spark} Read the report</button></div>
    <div id="trOut" class="mt-4"></div>`, (panel) => {
    let res = null;
    const paint = () => {
      const s = res.summary;
      const iocChips = Object.entries(res.iocs).filter(([, v]) => v.length).map(([k, v]) => `<span class="chip">${v.length} ${esc(k)}</span>`).join("");
      $("#trOut", panel).innerHTML = `
        <div class="stats stats--3">
          <div class="stat"><div class="stat__label">Techniques</div><div class="stat__value stat__value--accent">${s.techniques}</div><div class="stat__hint">${s.score}% covered</div></div>
          <div class="stat"><div class="stat__label">Gaps</div><div class="stat__value ${s.gap ? "stat__value--bad" : ""}">${s.gap}</div><div class="stat__hint">${s.partial} partly</div></div>
          <div class="stat"><div class="stat__label">IOCs</div><div class="stat__value">${res.ioc_total}</div><div class="stat__hint">${s.library_ready} with SigmaHQ rules</div></div>
        </div>
        <div class="row mt-4">${iocChips}<div class="spacer"></div>
          ${res.ioc_total ? `<button class="btn btn--sm" type="button" data-tr="ioc">${icons.file} Rules from the IOCs</button>` : ""}
          ${s.techniques ? `<button class="btn btn--sm" type="button" data-tr="purple">Test in Purple</button>` : ""}
        </div>
        <div class="card mt-4"><ul class="list">${res.techniques
          .map((t, i) => {
            const [label, cls] = STATE_LABEL[t.state];
            return `<li class="list__item tr__row"><div class="list__main"><div class="list__title"><span class="mono">${esc(t.id)}</span> ${esc(t.name || "Unknown technique")}</div><div class="list__meta">${esc(t.context)}</div>${t.rules.length ? `<div class="list__meta">Your rules: ${esc(t.rules.map((r) => r.title).slice(0, 3).join(", "))}</div>` : ""}${t.library.length ? `<div class="tr__lib">${t.library.map((l, j) => `<label class="check"><input type="checkbox" data-lib="${i}:${j}" ${t.state === "gap" && j < 2 ? "checked" : ""}> <span>${esc(l.title)}</span> ${levelBadge(l.level)}</label>`).join("")}</div>` : ""}</div><span class="badge badge--${cls}">${label}</span></li>`;
          })
          .join("") || '<li class="list__item muted">No techniques found.</li>'}</ul></div>
        ${res.techniques.some((t) => t.library.length) ? `<div class="row mt-4"><span class="muted">Ticked SigmaHQ rules go to your workspace.</span><div class="spacer"></div><button class="btn btn--primary" type="button" data-tr="add">${icons.file} Add ticked rules</button></div>` : res.summary.gap ? '<p class="muted mt-4">Sync the SigmaHQ library on the Library page to get rule suggestions for the gaps.</p>' : ""}`;
    };
    panel.addEventListener("click", async (e) => {
      if (e.target.closest("#trGo")) {
        const text = $("#trText", panel).value.trim();
        if (!text) {
          toast("Paste the report first", "bad");
          return;
        }
        $("#trOut", panel).innerHTML = LOADING;
        try {
          res = await api.threatReport(text, rules);
          paint();
        } catch (err) {
          $("#trOut", panel).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
        }
        return;
      }
      const b = e.target.closest("[data-tr]");
      if (!b || !res) return;
      if (b.dataset.tr === "purple") {
        const prefs = readJson("sigma-forge-purple", { techniques: [] });
        const ids = new Set([...(prefs.techniques || []), ...res.techniques.filter((t) => t.known).map((t) => t.id)]);
        writeJson("sigma-forge-purple", { ...prefs, techniques: [...ids] });
        navigate("/purple");
        return;
      }
      if (b.dataset.tr === "ioc") {
        b.disabled = true;
        try {
          const out = await api.iocRules(Object.values(res.iocs).flat().join("\n"), "threat report");
          const added = await store.add(out.sigma.map((r) => ({ name: `iocs/${r.name}`, content: r.content })));
          toast(`Added ${plural(added, "IOC rule")} to the workspace`, "ok");
        } catch (err) {
          toast(err.message, "bad");
        } finally {
          b.disabled = false;
        }
        return;
      }
      if (b.dataset.tr === "add") {
        const paths = $$("[data-lib]", panel).filter((x) => x.checked).map((x) => {
          const [i, j] = x.dataset.lib.split(":").map(Number);
          return res.techniques[i].library[j].path;
        });
        if (!paths.length) {
          toast("Tick at least one rule", "bad");
          return;
        }
        b.disabled = true;
        try {
          const got = await api.library.rules([...new Set(paths)]);
          const added = await store.add(got.rules.map((r) => ({ name: r.name, content: r.content })));
          toast(`Added ${plural(added, "rule")} from SigmaHQ`, "ok");
        } catch (err) {
          toast(err.message, "bad");
        } finally {
          b.disabled = false;
        }
      }
    });
  });
}

export function importSiemDrawer() {
  openDrawer("Import from a SIEM", `
    <p class="muted">Bring your existing detections into Sigma. Each search is turned into a Sigma rule with the same title, level and ATT&amp;CK tags.</p>
    <ul class="hint-list">
      <li><strong>Splunk</strong>: savedsearches.conf from an app's default or local folder.</li>
      <li><strong>Microsoft Sentinel</strong>: an analytics rules export (ARM template JSON) or the YAML rules from the Sentinel repo.</li>
      <li><strong>Elastic</strong>: the ndjson file from Security, Rules, Export.</li>
    </ul>
    ${dropzone("imInput", "Drop export files here", ".conf, .json, .yaml, .ndjson", ".conf,.json,.yaml,.yml,.ndjson,.txt")}
    <ul class="filechips mt-4" id="imFiles"></ul>
    <div class="row mt-4">
      <select class="select select--sm" id="imKind" aria-label="Kind"><option value="auto">Detect the format</option><option value="splunk">Splunk</option><option value="sentinel">Sentinel</option><option value="elastic">Elastic</option></select>
      <label class="check"><input type="checkbox" id="imDisabled"> Include disabled</label>
      <div class="spacer"></div>
      <button class="btn btn--primary" type="button" id="imGo" disabled>${icons.spark} Convert</button>
    </div>
    <div id="imOut" class="mt-4"></div>`, (panel) => {
    let files = [];
    let res = null;
    bindDrop(panel, "imInput", (list) => {
      list.forEach((f) => {
        files = files.filter((x) => x.name !== f.name);
        files.push(f);
      });
      $("#imFiles", panel).innerHTML = fileChips(files);
      $("#imGo", panel).disabled = !files.length;
    });
    panel.addEventListener("click", async (e) => {
      if (e.target.closest("#imGo")) {
        $("#imOut", panel).innerHTML = LOADING;
        try {
          res = await api.importSiem(files, $("#imKind", panel).value, $("#imDisabled", panel).checked);
        } catch (err) {
          $("#imOut", panel).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
          return;
        }
        $("#imOut", panel).innerHTML = `
          <div class="row"><span class="badge badge--ok">${res.converted} converted</span>${res.failed.length ? `<span class="badge badge--bad">${res.failed.length} failed</span>` : ""}${res.skipped ? `<span class="badge">${res.skipped} disabled skipped</span>` : ""}<span class="muted">of ${res.found}</span></div>
          ${res.errors.map((x) => `<div class="notice notice--bad mt-4">${esc(x.name)}: ${esc(x.error)}</div>`).join("")}
          <div class="card mt-4"><ul class="list">${res.rules.map((r, i) => `<li class="list__item"><label class="check"><input type="checkbox" data-im="${i}" ${r.error ? "" : "checked"}></label><div class="list__main"><div class="list__title">${esc(r.title)}</div><div class="list__meta"><span class="mono">${esc(r.name)}</span> · ${esc(r.kind)} · ${esc(r.language)}</div>${r.error ? `<div class="list__meta text-bad">${esc(r.error)}</div>` : ""}${r.warnings.length ? `<div class="list__meta">${esc(r.warnings[0])}</div>` : ""}</div>${levelBadge(r.level)}</li>`).join("")}
            ${res.failed.map((f) => `<li class="list__item"><div class="list__main"><div class="list__title">${esc(f.name)}</div><div class="list__meta">${esc(f.error)}</div><div class="list__meta mono">${esc(f.query.slice(0, 160))}</div></div><span class="badge badge--bad">failed</span></li>`).join("")}</ul></div>
          ${res.rules.length ? `<div class="row mt-4"><span class="muted">Check the fields and log sources after import.</span><div class="spacer"></div><button class="btn btn--primary" type="button" id="imAdd">${icons.file} Add ticked rules</button></div>` : ""}`;
        return;
      }
      if (e.target.closest("#imAdd") && res) {
        const picked = $$("[data-im]", panel).filter((b) => b.checked).map((b) => res.rules[Number(b.dataset.im)]);
        if (!picked.length) {
          toast("Tick at least one rule", "bad");
          return;
        }
        const added = await store.add(picked.map((r) => ({ name: `imported/${r.kind}/${r.name}`, content: r.content })));
        toast(`Added ${plural(added, "rule")} to the workspace`, "ok");
      }
    });
  });
}

const GH_KEY = "sigma-forge-github-push";

export function githubPushPanel(host, getRules) {
  const prefs = readJson(GH_KEY, { repo: "", base: "", folder: "rules/windows" });
  host.innerHTML = `
    <p class="muted">Send rules to a GitHub repository as a new branch with a pull request, ready for review. The token stays in this page and is never saved.</p>
    <div class="grid grid--2">
      <label class="field"><span class="field__label">Repository</span><input class="input mono" id="ghpRepo" placeholder="owner/detections" value="${esc(prefs.repo)}"></label>
      <label class="field"><span class="field__label">Folder in the repo</span><input class="input mono" id="ghpFolder" value="${esc(prefs.folder)}"></label>
      <label class="field"><span class="field__label">Base branch</span><input class="input mono" id="ghpBase" placeholder="default branch" value="${esc(prefs.base)}"></label>
      <label class="field"><span class="field__label">New branch</span><input class="input mono" id="ghpBranch" placeholder="sigma-forge/date-time"></label>
    </div>
    <label class="field"><span class="field__label">Token</span><input class="input mono" id="ghpToken" type="password" autocomplete="off" placeholder="Fine grained token with Contents and Pull requests: write"></label>
    <label class="field"><span class="field__label">Pull request title</span><input class="input" id="ghpTitle" placeholder="Add Sigma rules"></label>
    <div class="row"><span class="muted" id="ghpCount"></span><label class="check"><input type="checkbox" id="ghpDraft"> Draft</label><div class="spacer"></div><button class="btn btn--primary" type="button" id="ghpGo">${icons.push} Push and open PR</button></div>
    <div id="ghpOut" class="mt-4"></div>`;
  const paintCount = async () => {
    const rules = await getRules();
    $("#ghpCount", host).textContent = `${plural(rules.length, "rule")} will be sent`;
  };
  paintCount();
  $("#ghpGo", host).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const rules = await getRules();
    const body = {
      token: $("#ghpToken", host).value.trim(),
      repo: $("#ghpRepo", host).value.trim(),
      folder: $("#ghpFolder", host).value.trim(),
      base: $("#ghpBase", host).value.trim(),
      branch: $("#ghpBranch", host).value.trim(),
      title: $("#ghpTitle", host).value.trim(),
      draft: $("#ghpDraft", host).checked,
      rules,
    };
    if (!body.token || !body.repo) {
      toast("Add the repository and a token", "bad");
      return;
    }
    if (!rules.length) {
      toast("No rules to send", "bad");
      return;
    }
    writeJson(GH_KEY, { repo: body.repo, base: body.base, folder: body.folder });
    btn.disabled = true;
    $("#ghpOut", host).innerHTML = '<div class="skeleton sk-line"></div><div class="skeleton sk-line sk-line--md"></div>';
    try {
      const res = await api.githubPush(body);
      $("#ghpOut", host).innerHTML = `
        <div class="notice notice--ok">${res.changed ? `${esc(plural(res.changed, "file"))} pushed to <span class="mono">${esc(res.branch)}</span>.` : "Nothing changed. The files in the branch are the same."}</div>
        <div class="row mt-4">${res.pr_url ? `<a class="btn btn--primary" href="${esc(res.pr_url)}" target="_blank" rel="noopener noreferrer">${icons.external} Open pull request #${esc(res.pr_number)}</a>` : ""}<a class="btn" href="${esc(res.branch_url)}" target="_blank" rel="noopener noreferrer">${icons.external} Branch</a></div>
        <details class="mt-4"><summary class="muted">Files</summary><ul class="list">${res.files.map((f) => `<li class="list__item"><div class="list__main mono">${esc(f.path)}</div><span class="badge">${esc(f.action)}</span></li>`).join("")}</ul></details>`;
    } catch (err) {
      $("#ghpOut", host).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
    } finally {
      btn.disabled = false;
    }
  });
  return { paintCount };
}

const SIEM_KEY = "sigma-forge-siem-send";

export async function siemSendDrawer(files) {
  const prefs = readJson(SIEM_KEY, { target: "splunk_hec", url: "", index: "", sourcetype: "", host: "", port: 514, protocol: "udp", verify: true });
  openDrawer("Send events to a SIEM", `
    <p class="muted">Replay these logs into your SIEM to check that the real rules fire there too. Tokens are not saved.</p>
    <ul class="filechips">${files.map((f) => `<li class="filechip"><span class="filechip__name">${esc(f.name)}</span></li>`).join("")}</ul>
    <label class="field mt-4"><span class="field__label">Send to</span><select class="select" id="ssTarget">
      <option value="splunk_hec">Splunk HTTP Event Collector (HEC)</option>
      <option value="elastic">Elasticsearch bulk API</option>
      <option value="syslog">Syslog (Wazuh, QRadar, any collector)</option>
    </select></label>
    <div data-ss="http">
      <label class="field"><span class="field__label">URL</span><input class="input mono" id="ssUrl" value="${esc(prefs.url)}" placeholder="https://splunk.local:8088"></label>
      <label class="field"><span class="field__label" id="ssTokLabel">Token</span><input class="input mono" id="ssToken" type="password" autocomplete="off"></label>
      <div class="grid grid--2">
        <label class="field"><span class="field__label">Index</span><input class="input mono" id="ssIndex" value="${esc(prefs.index)}" placeholder="main"></label>
        <label class="field" data-ss="splunk"><span class="field__label">Sourcetype</span><input class="input mono" id="ssSt" value="${esc(prefs.sourcetype)}" placeholder="_json"></label>
      </div>
      <label class="check"><input type="checkbox" id="ssVerify" ${prefs.verify ? "checked" : ""}> Check the TLS certificate</label>
    </div>
    <div data-ss="syslog" hidden>
      <div class="grid grid--2">
        <label class="field"><span class="field__label">Host</span><input class="input mono" id="ssHost" value="${esc(prefs.host)}" placeholder="wazuh.local"></label>
        <label class="field"><span class="field__label">Port</span><input class="input" id="ssPort" type="number" value="${esc(prefs.port)}"></label>
      </div>
      <label class="field"><span class="field__label">Protocol</span><select class="select" id="ssProto"><option value="udp">UDP</option><option value="tcp" ${prefs.protocol === "tcp" ? "selected" : ""}>TCP</option></select></label>
    </div>
    <div class="row mt-4"><div class="spacer"></div><button class="btn" type="button" data-go="dry">Preview</button><button class="btn btn--primary" type="button" data-go="send">${icons.send} Send</button></div>
    <div id="ssOut" class="mt-4"></div>`, (panel) => {
    const sel = $("#ssTarget", panel);
    sel.value = prefs.target;
    const paint = () => {
      const t = sel.value;
      $("[data-ss=http]", panel).hidden = t === "syslog";
      $("[data-ss=syslog]", panel).hidden = t !== "syslog";
      $("[data-ss=splunk]", panel).hidden = t !== "splunk_hec";
      $("#ssTokLabel", panel).textContent = t === "elastic" ? "API key, or user:password" : "HEC token";
      $("#ssUrl", panel).placeholder = t === "elastic" ? "https://elastic.local:9200" : "https://splunk.local:8088";
    };
    paint();
    sel.addEventListener("change", paint);
    panel.addEventListener("click", async (e) => {
      const b = e.target.closest("[data-go]");
      if (!b) return;
      const fields = {
        target: sel.value,
        url: $("#ssUrl", panel).value.trim(),
        token: $("#ssToken", panel).value.trim(),
        index: $("#ssIndex", panel).value.trim(),
        sourcetype: $("#ssSt", panel).value.trim(),
        host: $("#ssHost", panel).value.trim(),
        port: $("#ssPort", panel).value || 514,
        protocol: $("#ssProto", panel).value,
        verify_tls: $("#ssVerify", panel).checked,
        dry_run: b.dataset.go === "dry",
      };
      writeJson(SIEM_KEY, { target: fields.target, url: fields.url, index: fields.index, sourcetype: fields.sourcetype, host: fields.host, port: fields.port, protocol: fields.protocol, verify: fields.verify_tls });
      b.disabled = true;
      $("#ssOut", panel).innerHTML = '<div class="skeleton sk-line"></div><div class="skeleton sk-block"></div>';
      try {
        const res = await api.siemSend(fields, files);
        $("#ssOut", panel).innerHTML = `
          ${res.dry_run ? `<div class="notice">${esc(plural(res.events, "event"))} ready. Nothing was sent.</div>` : `<div class="notice notice--${res.failed ? "warn" : "ok"}">${res.sent} sent, ${res.failed} failed in ${res.seconds}s.</div>`}
          ${res.errors.map((x) => `<div class="notice notice--bad mt-4">${esc(x)}</div>`).join("")}
          <div class="field__label mt-4">First events as sent</div>
          ${res.preview.map((p) => `<pre class="code">${esc(p.startsWith("{") ? pretty(JSON.parse(p)) : p)}</pre>`).join("")}`;
      } catch (err) {
        $("#ssOut", panel).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
      } finally {
        b.disabled = false;
      }
    });
  });
}

export function suggestMappingDrawer(rules, onSaved) {
  openDrawer("Suggest a mapping from my logs", `
    <p class="muted">Drop a sample of your own logs. Sigma Forge looks at the field names and the values, and matches them to the fields your rules use.</p>
    ${dropzone("smInput", "Drop log files here", ".evtx, .json, .jsonl or a .zip of them", ".evtx,.json,.jsonl,.ndjson,.zip")}
    <ul class="filechips mt-4" id="smFiles"></ul>
    <div class="row mt-4"><span class="muted">${esc(plural(rules.length, "rule"))} in the workspace</span><div class="spacer"></div><button class="btn btn--primary" type="button" id="smGo" disabled>${icons.spark} Suggest</button></div>
    <div id="smOut" class="mt-4"></div>`, (panel) => {
    let files = [];
    let res = null;
    bindDrop(panel, "smInput", (list) => {
      list.forEach((f) => {
        files = files.filter((x) => x.name !== f.name);
        files.push(f);
      });
      $("#smFiles", panel).innerHTML = fileChips(files);
      $("#smGo", panel).disabled = !files.length;
    });
    panel.addEventListener("click", async (e) => {
      if (e.target.closest("#smGo")) {
        $("#smOut", panel).innerHTML = LOADING;
        try {
          res = await api.suggestMapping(rules, files);
        } catch (err) {
          $("#smOut", panel).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
          return;
        }
        const missing = res.fields.filter((f) => !f.present);
        const good = (f) => f.suggestions.length && f.suggestions[0].score >= 0.6;
        const found = missing.map((f, i) => ({ f, i })).filter((x) => good(x.f));
        const none = missing.filter((f) => !good(f));
        $("#smOut", panel).innerHTML = `
          <div class="row"><span class="badge badge--ok">${res.fields.length - res.missing} already match</span><span class="badge badge--accent">${res.matched} suggested</span><span class="muted">${res.events} events, ${res.log_fields} log fields</span></div>
          ${found.length ? `<div class="card mt-4"><ul class="list">${found
            .map(({ f, i }) => `<li class="list__item sm__row"><div class="list__main"><div class="list__title mono">${esc(f.field)}</div><div class="list__meta">${esc(f.suggestions[0].why)}${f.suggestions[0].sample ? ` · <span class="mono">${esc(f.suggestions[0].sample)}</span>` : ""}</div></div><select class="select select--sm sm__pick" data-sm="${i}" aria-label="Your field for ${esc(f.field)}"><option value="">Leave as is</option>${f.suggestions.filter((s) => s.score >= 0.5).map((s) => `<option value="${esc(s.name)}" ${res.mapping[f.field] === s.name ? "selected" : ""}>${esc(s.name)} (${Math.round(s.score * 100)}%)</option>`).join("")}</select></li>`)
            .join("")}</ul></div>
            <div class="row mt-4"><input class="input toolbar__grow" id="smName" value="From my logs" aria-label="Profile name"><button class="btn btn--primary" type="button" id="smSave">${icons.file} Save as profile</button></div>` : missing.length ? "" : '<div class="notice notice--ok mt-4">Every field your rules use is already in these logs. No mapping needed.</div>'}
          ${none.length ? `<details class="mt-4"><summary class="muted">${esc(plural(none.length, "field"))} not found in these logs. Rules for other log sources use them.</summary><div class="chips mt-4">${none.map((f) => `<span class="chip mono">${esc(f.field)}</span>`).join("")}</div></details>` : ""}`;
        return;
      }
      if (e.target.closest("#smSave") && res) {
        const missing = res.fields.filter((f) => !f.present);
        const map = {};
        $$("[data-sm]", panel).forEach((s) => {
          if (s.value) map[missing[Number(s.dataset.sm)].field] = s.value;
        });
        if (!Object.keys(map).length) {
          toast("Pick at least one field", "bad");
          return;
        }
        const saved = mappings.save({ name: $("#smName", panel).value.trim() || "From my logs", map });
        mappings.setActive(saved.id);
        toast(`Saved ${saved.name} and turned it on`, "ok");
        onSaved?.(saved);
      }
    });
  });
}
