"use strict";
// AFW dashboard — reads only the authenticated controller API. No fixtures.
// Every value rendered is escaped: attacker-controlled strings (paths, signatures)
// reach this page through telemetry.

const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n, d = 2) => (n === null || n === undefined || Number.isNaN(n) ? "–" : Number(n).toFixed(d).replace(/\.?0+$/, "") || "0");
const tShort = (iso) => (iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "–");

let TOKEN = "";
try { TOKEN = localStorage.getItem("afw_token") || ""; } catch (_) { /* storage blocked */ }
let selected = null;
let overview = null;

// Token entry is an inline form (a prompt() dialog blocks automation and is easy to miss).
$("#token-btn").addEventListener("click", () => { const f = $("#token-form"); f.hidden = !f.hidden; if (!f.hidden) $("#token-input").focus(); });
$("#token-form").addEventListener("submit", (e) => {
  e.preventDefault();
  TOKEN = $("#token-input").value.trim();
  $("#token-input").value = "";
  try { localStorage.setItem("afw_token", TOKEN); } catch (_) { /* ignore */ }
  $("#token-form").hidden = true;
  loadRole().then(() => { refresh(); slow(); });
});

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json", ...(opts.headers || {}) } });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

// ------------------------------------------------------------ status mapping
const BAND = {
  none: ["var(--good)", "none"], low: ["var(--neutral)", "low"], elevated: ["var(--warning)", "elevated"],
  high: ["var(--serious)", "high"], critical: ["var(--critical)", "critical"],
};
const STATE = {
  enforced: "var(--good)", applied_unverified: "var(--warning)", applying: "var(--warning)", unknown: "var(--serious)",
  failed: "var(--critical)", rejected: "var(--critical)", pending_approval: "var(--warning)", validated: "var(--neutral)",
  expired: "var(--neutral)", expiring: "var(--neutral)", rolled_back: "var(--neutral)", rollback_pending: "var(--warning)",
};
const badge = (color, label) => `<span class="badge"><i style="background:${color}"></i>${esc(label)}</span>`;

// ------------------------------------------------------------ tooltip
const tip = $("#tooltip");
function showTip(e, html) { tip.innerHTML = html; tip.hidden = false; moveTip(e); }
function moveTip(e) { tip.style.left = `${Math.min(e.clientX + 14, innerWidth - 310)}px`; tip.style.top = `${e.clientY + 14}px`; }
function hideTip() { tip.hidden = true; }

// ------------------------------------------------------------ line chart
function lineChart(el, points, { key, label, yMax, refs = [], unit = "" }) {
  const W = 640, H = 200, L = 40, R = 10, T = 10, B = 24;
  if (!points.length) { el.innerHTML = `<div class="empty">No windows observed yet.</div>`; return; }
  const xs = points.map((p) => new Date(p.t).getTime());
  const x0 = xs[0], x1 = Math.max(xs[xs.length - 1], x0 + 1);
  const ys = points.map((p) => Number(p[key]) || 0);
  const top = yMax ?? Math.max(1, ...ys) * 1.15;
  const X = (t) => L + ((t - x0) / (x1 - x0)) * (W - L - R);
  const Y = (v) => T + (1 - v / top) * (H - T - B);
  const ticks = [0, top / 2, top];
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(label)}">`;
  for (const v of ticks) svg += `<line x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}" stroke="var(--grid)" stroke-width="1"/><text x="${L - 6}" y="${Y(v) + 4}" text-anchor="end">${fmt(v, 0)}</text>`;
  for (const r of refs) svg += `<line x1="${L}" x2="${W - R}" y1="${Y(r.v)}" y2="${Y(r.v)}" stroke="var(--muted)" stroke-dasharray="4 4" stroke-width="1"/><text x="${W - R}" y="${Y(r.v) - 4}" text-anchor="end">${esc(r.label)}</text>`;
  svg += `<line x1="${L}" x2="${W - R}" y1="${Y(0)}" y2="${Y(0)}" stroke="var(--axis)"/>`;
  svg += `<text x="${L}" y="${H - 6}">${tShort(points[0].t)}</text><text x="${W - R}" y="${H - 6}" text-anchor="end">${tShort(points[points.length - 1].t)}</text>`;
  const d = points.map((p, i) => `${i ? "L" : "M"}${X(xs[i]).toFixed(1)},${Y(ys[i]).toFixed(1)}`).join("");
  svg += `<path d="${d}" fill="none" stroke="var(--series-1)" stroke-width="2" stroke-linejoin="round"/>`;
  svg += `<line class="xh" x1="0" x2="0" y1="${T}" y2="${H - B}" stroke="var(--axis)" visibility="hidden"/><circle class="xd" r="4" fill="var(--series-1)" stroke="var(--surface-1)" stroke-width="2" visibility="hidden"/>`;
  svg += `<rect x="${L}" y="${T}" width="${W - L - R}" height="${H - T - B}" fill="transparent"/></svg>`;
  el.innerHTML = svg;
  const s = el.querySelector("svg"), xh = s.querySelector(".xh"), xd = s.querySelector(".xd");
  s.addEventListener("mousemove", (e) => {
    const box = s.getBoundingClientRect();
    const t = x0 + ((((e.clientX - box.left) / box.width) * W - L) / (W - L - R)) * (x1 - x0);
    let i = 0; for (let k = 1; k < xs.length; k++) if (Math.abs(xs[k] - t) < Math.abs(xs[i] - t)) i = k;
    xh.setAttribute("x1", X(xs[i])); xh.setAttribute("x2", X(xs[i])); xh.setAttribute("visibility", "visible");
    xd.setAttribute("cx", X(xs[i])); xd.setAttribute("cy", Y(ys[i])); xd.setAttribute("visibility", "visible");
    showTip(e, `<b>${tShort(points[i].t)}</b><br>${esc(label)}: ${fmt(ys[i], 1)}${unit}<br>sources: ${points[i].sources}`);
  });
  s.addEventListener("mouseleave", () => { xh.setAttribute("visibility", "hidden"); xd.setAttribute("visibility", "hidden"); hideTip(); });
}

// ------------------------------------------------------------ baseline vs current
async function renderBaseline() {
  const el = $("#baseline");
  if (!selected) { el.innerHTML = `<div class="empty">Select a source.</div>`; return; }
  let data;
  try { data = await api(`/api/sources/${selected}`); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  $("#detail-title").textContent = `Baseline vs current — ${selected}`;
  const last = data.series[data.series.length - 1];
  const feats = Object.keys(data.baseline);
  if (!last || !feats.length) { el.innerHTML = `<div class="empty">No profile or no recent windows for this source.</div>`; return; }
  const rowH = 26, L = 150, W = 640, R = 70;
  let svg = `<svg viewBox="0 0 ${W} ${feats.length * rowH + 10}" role="img" aria-label="Feature values against baseline">`;
  const rows = [];
  feats.forEach((f, i) => {
    const b = data.baseline[f], v = Number(last[f]);
    const log = b.log_scale, tr = (x) => (log ? Math.log1p(Math.max(0, x)) : x);
    const lo = Math.min(tr(b.q01), tr(v)), hi = Math.max(tr(b.q99) * 1.25, tr(v) * 1.05, lo + 1e-6);
    const X = (x) => L + ((tr(x) - lo) / (hi - lo)) * (W - L - R);
    const y = 8 + i * rowH;
    const out = v > b.q99 || v < b.q01;
    svg += `<text x="${L - 8}" y="${y + 12}" text-anchor="end" style="fill:var(--text-secondary)">${esc(f)}</text>`;
    svg += `<rect x="${X(b.q05)}" y="${y + 4}" width="${Math.max(2, X(b.q99) - X(b.q05))}" height="10" rx="4" fill="var(--band)"/>`;
    svg += `<line x1="${X(b.median)}" x2="${X(b.median)}" y1="${y + 1}" y2="${y + 17}" stroke="var(--text-secondary)" stroke-width="2"/>`;
    svg += `<circle cx="${X(v)}" cy="${y + 9}" r="5" fill="${out ? "var(--critical)" : "var(--series-1)"}" stroke="var(--surface-1)" stroke-width="2"/>`;
    svg += `<text x="${W - R + 8}" y="${y + 13}" style="fill:var(--text-primary)">${fmt(v)}${out ? " ⚠" : ""}</text>`;
    svg += `<rect class="hit" data-i="${i}" x="0" y="${y}" width="${W}" height="${rowH}" fill="transparent"/>`;
    rows.push(`<b>${esc(f)}</b> (${esc(b.unit)})<br>current: ${fmt(v, 3)}<br>median ${fmt(b.median, 3)} · q05 ${fmt(b.q05, 3)} · q99 ${fmt(b.q99, 3)}<br>${esc(b.description)}${out ? "<br><b>outside benign q01–q99</b>" : ""}`);
  });
  el.innerHTML = svg + "</svg>";
  el.querySelectorAll(".hit").forEach((r) => {
    r.addEventListener("mousemove", (e) => showTip(e, rows[Number(r.dataset.i)]));
    r.addEventListener("mouseleave", hideTip);
  });
}

// ------------------------------------------------------------ renderers
function renderTiles(o) {
  const r = o.resources, prof = o.profile;
  const iforest = o.models.find((m) => m.detector === "isolation_forest");
  const mv = iforest ? iforest.version.split("-") : null;
  const tiles = [
    ["Operating mode", o.mode, `strategy: ${o.strategy}`],
    ["Trusted profile", prof ? `v${prof.version}` : "none", prof ? `${prof.windows} windows · ${prof.sources} sources · ${prof.hash}` : "train & promote a profile"],
    ["ML model", mv ? mv.slice(0, 2).join("-") : "none", iforest ? `${mv[2] || ""} · thr ${fmt(iforest.threshold, 3)} · ${iforest.sha256}` : "no trusted model", true],
    ["Live sources", o.live_sources.length, `${o.live_sources.filter((s) => s.risk >= 45).length} elevated or higher`],
    ["Active policies", o.active_policies.length, `${o.pending_approval} pending approval`],
    ["Controller RSS", `${fmt(r.controller_rss_mb, 0)} MB`, `host avail ${r.system_mem_available_mb} MB · tick p50 ${fmt(r.tick_ms_p50, 1)} ms`],
  ];
  $("#tiles").innerHTML = tiles.map(([l, v, n, sm]) => `<div class="tile"><div class="label">${esc(l)}</div><div class="value${sm ? " sm" : ""}">${esc(v)}</div><div class="note">${esc(n)}</div></div>`).join("");
  const deg = o.telemetry_degraded;
  $("#chips").innerHTML = [
    `<span class="chip">mode <b>${esc(o.mode)}</b></span>`,
    `<span class="chip">strategy <b>${esc(o.strategy)}</b></span>`,
    `<span class="chip">${badge(deg ? "var(--critical)" : "var(--good)", deg ? "telemetry degraded — auto actions paused" : "telemetry healthy")}</span>`,
  ].join("");
}

function renderSources(o) {
  const tb = $("#sources tbody");
  if (!o.live_sources.length) { tb.innerHTML = `<tr><td colspan="5" class="empty">No active sources in the last 2 minutes.</td></tr>`; return; }
  tb.innerHTML = o.live_sources.map((s) => {
    const [c, l] = BAND[s.band] || BAND.none;
    const dets = s.detections.map((d) => `${esc(d.detector.replace("_", " "))}: ${fmt(d.score, 3)} / ${fmt(d.threshold, 3)}${d.anomalous ? " ⚠" : ""}`).join("<br>") || "–";
    return `<tr data-ip="${esc(s.source_ip)}" class="${s.source_ip === selected ? "sel" : ""}"><td class="mono">${esc(s.source_ip)}</td><td>${badge(c, `${fmt(s.risk, 1)} ${l}`)}</td><td>${esc(s.categories.join(", ") || "–")}</td><td class="num">${s.requests}</td><td class="mono">${dets}</td></tr>`;
  }).join("");
  tb.querySelectorAll("tr[data-ip]").forEach((tr) => tr.addEventListener("click", () => { selected = tr.dataset.ip; renderSources(o); renderBaseline(); }));
}

async function renderPolicies() {
  let ps;
  try { ps = await api("/api/policies?limit=60"); } catch (_) { return; }
  const tb = $("#policies tbody");
  if (!ps.length) { tb.innerHTML = `<tr><td colspan="8" class="empty">No policy decisions yet.</td></tr>`; return; }
  tb.innerHTML = ps.map((p) => {
    const t = p.intent.target;
    const target = t.source_ip || t.route || `${t.country_code} ${t.direction}${t.simulated ? " (SIMULATED)" : ""}`;
    const v = p.verification || {};
    const ver = Object.keys(v).length ? Object.entries(v).map(([k, x]) => `${esc(k)}=${esc(x)}`).join("<br>") : "–";
    return `<tr><td>${tShort(p.updated_at)}</td><td>${esc(p.intent.kind)}${p.intent.rate_profile ? ` (${esc(p.intent.rate_profile)})` : ""}</td><td class="mono">${esc(target)}</td>
      <td>${badge(STATE[p.state] || "var(--neutral)", p.state)}</td><td>${esc(p.intent.origin)} / ${esc(p.mode_at_creation)}</td>
      <td class="mono">${ver}</td><td>${p.expires_at ? tShort(p.expires_at) : "–"}</td>
      <td class="acts"><button type="button" data-explain="${esc(p.policy_id)}">Explain</button>${canOperate() && p.state === "pending_approval" ? ` <button type="button" class="primary" data-act="approve" data-id="${esc(p.policy_id)}">Approve</button> <button type="button" data-act="reject" data-id="${esc(p.policy_id)}">Reject</button>` : ""}${canOperate() && ["enforced", "applied_unverified", "applying"].includes(p.state) ? ` <button type="button" data-act="revoke" data-id="${esc(p.policy_id)}">Revoke</button>` : ""}</td></tr>`;
  }).join("");
  tb.querySelectorAll("[data-explain]").forEach((b) => b.addEventListener("click", () => explain(b.dataset.explain)));
  tb.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", () => policyAction(b.dataset.id, b.dataset.act)));
}

async function explain(id) {
  let x;
  try { x = await api(`/api/policies/${id}/explain`); } catch (e) { toast(e.message, true); return; }
  $("#explain-card").hidden = false;
  $("#explain-id").textContent = id;
  const w = x.what_happened, m = x.model_and_profile, r = x.response, en = x.enforcement, lg = x.legitimate_traffic;
  const kv = (o) => `<dl class="kv">${Object.entries(o || {}).map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(typeof v === "object" ? JSON.stringify(v) : v)}</dd>`).join("")}</dl>`;
  $("#explain").innerHTML = `
    <div class="grid2">
      <div><h3>What happened</h3>${w ? kv(w) : `<div class="empty">Operator/MCP request — no AI assessment.</div>`}
        <h3>Why it was suspicious</h3>${x.why_suspicious.map((e) => `<div class="ev"><b>${esc(e.category)}</b> · ${esc(e.code)} · +${fmt(e.points, 1)}<br>${esc(e.detail)}</div>`).join("") || `<div class="empty">–</div>`}</div>
      <div><h3>Model &amp; profile</h3>${m ? kv(m) : `<div class="empty">–</div>`}
        <h3>Feature attributions (occlusion)</h3>${x.contributing_features.map((d) => `<div class="ev"><b>${esc(d.detector)}</b> score ${fmt(d.score, 3)} ≥ ${fmt(d.threshold, 3)} (benign pct ${fmt(d.benign_percentile, 0)})<br>${d.contributions.map((c) => `${esc(c.feature)} = ${fmt(c.value, 3)} vs median ${fmt(c.baseline_median, 3)} (z ${fmt(c.robust_z, 1)}, Δscore ${fmt(c.score_delta, 3)})`).join("<br>")}</div>`).join("") || `<div class="empty">–</div>`}</div>
    </div>
    <div class="grid2">
      <div><h3>Response selected</h3>${kv(r)}</div>
      <div><h3>Enforcement</h3>${kv({ state: en.state, verification: en.verification, effective_at: en.effective_at, expires_at: en.expires_at })}
        <h3>Legitimate traffic</h3>${kv(lg)}</div>
    </div>`;
  $("#explain-card").scrollIntoView({ behavior: "smooth" });
}

async function renderAdaptation() {
  let a;
  try { a = await api("/api/adaptation"); } catch (_) { return; }
  const mon = a.monitor;
  const reports = a.drift_reports.slice(0, 5).map((d) => `<div class="ev"><b>${tShort(d.detected_at)}</b> · ${esc(d.signals.join(", "))} · <b>${esc(d.assessment)}</b> (${d.distinct_sources} sources)<br><span class="mono">${esc(JSON.stringify(d.details))}</span></div>`).join("");
  const evals = a.evaluations.slice(0, 3).map((e) => `<div class="ev"><b>Candidate profile v${e.candidate_profile_version}</b> — ${badge(e.passed ? "var(--neutral)" : "var(--critical)", e.passed ? "validation-FPR gate passed" : "gate failed")}<br>${e.checks.map((c) => `<span class="check">${c.passed ? "✔" : "✘"} ${esc(c.name)} ${c.value !== null ? `= ${fmt(c.value, 4)}` : ""}${c.limit !== null ? ` (limit ${fmt(c.limit, 4)})` : ""}</span>`).join("<br>")}</div>`).join("");
  const caveat = `<div class="sub" style="margin-top:6px">“Passed” here is the bootstrap validation-FPR gate only — <b>not</b> a generalization or sensitivity qualification. On unseen users and the predeclared selection gates (P6/P7/A3, <code>RESULTS.md</code>) no candidate has qualified; none is promoted.</div>`;
  $("#adaptation").innerHTML = `${mon ? `<dl class="kv"><dt>shadow windows accepted</dt><dd>${mon.accepted_windows}</dd><dt>rejected (reputation gate)</dt><dd class="mono">${esc(JSON.stringify(mon.rejected))}</dd><dt>new routes (sources)</dt><dd class="mono">${esc(JSON.stringify(mon.new_routes))}</dd><dt>new app versions</dt><dd class="mono">${esc(JSON.stringify(mon.new_versions))}</dd><dt>shadow anomaly rate</dt><dd>${fmt(mon.shadow_anomaly_rate, 3)}</dd></dl>` : `<div class="empty">No trusted profile loaded.</div>`}
    <h3>Drift reports</h3>${reports || `<div class="empty">None.</div>`}<h3>Candidate evaluations</h3>${evals ? evals + caveat : `<div class="empty">None.</div>`}`;
}

async function renderModels() {
  let ms, ps;
  try { [ms, ps] = await Promise.all([api("/api/models"), api("/api/profiles")]); } catch (_) { return; }
  const qual = { trusted: "in use (enforcing in enforce mode)", candidate: "registered — NOT qualified for promotion", retired: "superseded" };
  const prof = ps.map((p) => `<tr><td>v${p.version}</td><td>${badge(p.status === "trusted" ? "var(--good)" : p.status === "candidate" ? "var(--warning)" : "var(--neutral)", p.status)}</td><td class="sub">${esc(qual[p.status] || "")}</td><td class="num">${p.provenance.n_windows}</td><td class="num">${p.provenance.n_sources}</td><td>${esc(p.provenance.dataset_ids.join(", "))}</td></tr>`).join("");
  const mods = ms.slice(0, 12).map((m) => { const v = m.validation_metrics; return `<tr><td>${esc(m.detector)}</td><td>p${m.profile_version}</td><td>${esc(m.status)}</td><td class="num">${fmt(v.fpr, 4)}</td><td class="num">${fmt(v.recall, 3)}</td><td class="num">${fmt(v.roc_auc, 3)}</td><td class="num">${fmt(v.mean_latency_us, 0)}</td><td class="num">${v.model_bytes ? fmt(v.model_bytes / 1024, 0) : "–"}</td></tr>`; }).join("");
  $("#models").innerHTML = `<div class="table-wrap short"><table><thead><tr><th>Profile</th><th>Status</th><th>Qualification</th><th class="num">Windows</th><th class="num">Sources</th><th>Datasets</th></tr></thead><tbody>${prof || `<tr><td colspan="6" class="empty">No profiles.</td></tr>`}</tbody></table></div>
    <p class="sub">“Candidate” means registered, <b>not</b> that it passed promotion. Qualification is the predeclared generalization + sensitivity evaluation (P1/P6/P7/A3→A4, <code>RESULTS.md</code>): no candidate has qualified, so <b>v2 stays trusted and nothing is promoted</b>. Val FPR below is the bootstrap gate only.</p>
    <div class="table-wrap short" style="margin-top:6px"><table><thead><tr><th>Detector</th><th>Profile</th><th>Status</th><th class="num">Val FPR</th><th class="num">Val recall</th><th class="num">AUC</th><th class="num">µs/score</th><th class="num">KiB</th></tr></thead><tbody>${mods || `<tr><td colspan="8" class="empty">No models.</td></tr>`}</tbody></table></div>`;
}

async function renderExperiments() {
  let ex;
  try { ex = await api("/api/experiments"); } catch (_) { return; }
  if (!ex.length) { $("#experiments").innerHTML = `<div class="empty">No experiment results recorded.</div>`; return; }
  const keys = ["strategy", "scenario", "datasets", "precision", "recall", "fpr", "attack_sources_blocked", "benign_sources_restricted", "median_first_attack_to_block_s", "attack_requests_exposed", "notes"];
  $("#experiments").innerHTML = `<div class="table-wrap"><table><thead><tr><th>Experiment</th>${keys.map((k) => `<th>${esc(k.replaceAll("_", " "))}</th>`).join("")}</tr></thead><tbody>${ex.slice(0, 60).map((r) => `<tr><td>${esc(r.experiment)}</td>${keys.map((k) => `<td class="${typeof r[k] === "number" ? "num" : ""}">${esc(typeof r[k] === "number" ? fmt(r[k], 3) : Array.isArray(r[k]) ? r[k].join(", ") : r[k] ?? "–")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

function renderTelemetry(o) {
  const t = o.telemetry;
  const sensors = Object.entries(t.sensors || {}).map(([role, s]) => `<dt>sensor ${esc(role)} (mTLS heartbeat)</dt><dd>${badge(s.stale ? "var(--critical)" : s.heartbeat_age_s === null ? "var(--warning)" : "var(--good)", s.stale ? "STALE — evidence degraded" : s.heartbeat_age_s === null ? "awaiting first heartbeat" : `${fmt(s.heartbeat_age_s, 0)} s ago`)}</dd>`).join("");
  if (!Object.keys(t.age_s).length && !Object.keys(t.counts).length && !sensors) {
    $("#telemetry").innerHTML = `<div class="empty">No telemetry received yet (WAF / app / IDS feeds).</div>`;
    return;
  }
  $("#telemetry").innerHTML = `<dl class="kv">${sensors}${Object.entries(t.age_s).filter(([k]) => !k.startsWith("heartbeat:")).map(([k, v]) => `<dt>${esc(k)} last seen</dt><dd>${badge(v < 60 ? "var(--good)" : "var(--warning)", `${fmt(v, 0)} s ago`)}</dd>`).join("")}
    ${Object.entries(t.counts).sort().map(([k, v]) => `<dt>${esc(k)}</dt><dd class="num">${v}</dd>`).join("")}</dl>`;
}

const kvList = (o) => `<dl class="kv">${Object.entries(o).map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(typeof v === "object" && v !== null ? JSON.stringify(v) : v ?? "–")}</dd>`).join("")}</dl>`;
const checks = (cs) => cs.map((c) => `<span class="check">${c.passed ? "✔" : "✘"} ${esc(c.name)}${c.value !== null && c.value !== undefined ? ` = ${fmt(c.value, 4)}` : ""}${c.limit !== null && c.limit !== undefined ? ` (limit ${fmt(c.limit, 4)})` : ""}${c.detail ? ` — ${esc(c.detail)}` : ""}</span>`).join("<br>");

const nz = (o) => (o && Object.keys(o).length ? o : "none since controller start");

async function renderShadow() {
  let sh;
  try { sh = await api("/api/learning/shadow?limit=200"); } catch (_) { return; }
  const st = sh.status;
  if (!st) { $("#shadow").innerHTML = `<div class="empty">Online learning disabled.</div>`; return; }
  const ch = st.challenger || {};
  const ag = sh.agreement;
  const learned = sh.recent_learned.slice(0, 6).map((w) => `<tr><td>${tShort(w.learned_at)}</td><td class="mono">${esc(w.source_ip)}</td><td class="num">${fmt(w.champion_score, 3)}</td><td class="num">${w.n_learned_after}</td><td class="mono">${esc(w.fingerprint.slice(0, 12))}</td></tr>`).join("");
  $("#shadow").innerHTML = `${kvList({
    mode: st.mode, champion: st.champion_model,
    "challenger learned / window": `${ch.n_learned ?? 0} / ${ch.window_size ?? "–"}${ch.warm ? "" : " (cold)"}`,
    "last checkpoint": st.last_checkpoint ? `#${st.last_checkpoint.seq} · n=${st.last_checkpoint.n_learned} · ${tShort(st.last_checkpoint.created_at)}` : "none",
    quarantine: st.quarantine, "eligible (by stage)": nz(st.counts), "excluded (reason)": nz(st.excluded),
  })}
  <h3>Champion vs challenger (last ${ag ? ag.windows : 0} warm windows)</h3>${ag ? kvList({ "both normal": ag.both_normal, "both anomalous": ag.both_anomalous, "champion only": ag.champion_only_anomalous, "challenger only": ag.challenger_only_anomalous }) + `<div class="sub">${esc(ag.note)}</div>` : `<div class="empty">No warm shadow scores yet.</div>`}
  <h3>Recently learned windows (provenance fingerprint)</h3>${learned ? `<div class="table-wrap short"><table><thead><tr><th>Learned</th><th>Source</th><th class="num">Champion</th><th class="num">n</th><th>Fingerprint</th></tr></thead><tbody>${learned}</tbody></table></div>` : `<div class="empty">Nothing learned: no window passed eligibility.</div>`}`;
}

async function renderChallenger() {
  let c;
  try { c = await api("/api/learning/challenger"); } catch (_) { return; }
  const p = c.probation;
  const prob = p ? kvList({ status: p.status, model: p.model_id, parent: p.parent_model_id, until: p.until, windows: p.windows, anomalous: p.anomalous, "baseline rate": fmt(p.baseline_rate, 3) }) : `<div class="empty">No active probation (champion unchanged by online learning).</div>`;
  const evals = c.evaluations.map((e) => `<div class="ev"><b>${tShort(e.evaluated_at)}</b> ${badge(e.passed ? "var(--good)" : "var(--critical)", e.passed ? "gate passed — candidate frozen, awaiting admin" : "gate failed — not promotable")} · learned ${e.n_learned}<br>${checks(e.checks)}</div>`).join("");
  const hist = c.history.map((h) => `<div class="ev">${badge(h.status === "active" ? "var(--warning)" : h.status === "rolled_back" ? "var(--critical)" : "var(--good)", h.status)} ${esc(h.model_id)} ${h.reason ? `— ${esc(h.reason)}` : ""}</div>`).join("");
  const lastFail = (c.evaluations[0]?.checks || []).filter((x) => !x.passed).map((x) => x.name);
  const summary = `<div class="sub" style="margin-bottom:8px">Lifecycle state: <b>no model promoted</b> (champion unchanged by online learning). The gate is exercised live and ${c.evaluations.length && !c.evaluations[0].passed ? `<b>refuses</b> the challenger${lastFail.length ? ` (${esc(lastFail.join(", "))})` : ""}` : "has no passing candidate"}; a pass needs attack-recall data (team runs) and a human promotion. Promote/probation/rollback mechanics are covered by the M3 lifecycle tests.</div>`;
  $("#challenger").innerHTML = `${summary}<h3>Probation</h3>${prob}<h3>Gate evaluations</h3>${evals || `<div class="empty">No evaluations yet.</div>`}<h3>Promotion history</h3>${hist || `<div class="empty">No promotions (nothing has qualified).</div>`}`;
}

async function renderIdsOnly() {
  let as;
  try { as = await api("/api/assessments?limit=400"); } catch (_) { return; }
  const ids = as.filter((a) => a.view === "ids_only").slice(0, 12);
  $("#ids-only").innerHTML = ids.length ? `<div class="table-wrap short"><table><thead><tr><th>Assessed</th><th>Source</th><th>Score</th><th>Evidence</th></tr></thead><tbody>${ids.map((a) => { const [c, l] = BAND[a.band] || BAND.none; return `<tr><td>${tShort(a.assessed_at)}</td><td class="mono">${esc(a.source_ip)}</td><td>${badge(c, `${fmt(a.score, 1)} ${l}`)}</td><td>${a.evidence.map((e) => esc(e.code)).join(", ")}</td></tr>`; }).join("")}</tbody></table></div>` : `<div class="empty">No IDS-only assessments in the recent history.</div>`;
}

function renderGeo(o) {
  const g = o.geoip;
  if (!g) return;
  $("#geo").innerHTML = g.loaded
    ? `${kvList({ release: g.release, "age (days)": g.age_days, ranges: g.ranges, sha256: g.sha256.slice(0, 16) + "…", license: g.license })}${g.stale ? badge("var(--critical)", "STALE — install a newer release") : badge("var(--good)", "fresh")}`
    : `<div class="empty">${esc(g.reason || "not loaded")}</div>`;
  const e = g.enforcement || {};
  const dir = (d) => d && d.countries.length ? `${esc(d.countries.join(", "))} · ${d.networks} networks in ${esc(d.alias)}` : `none (${esc((d && d.alias) || "")} empty)`;
  $("#geo").innerHTML += e.enabled
    ? `<p class="sub" style="margin-top:12px"><b>Real-country enforcement</b> (FW01, ADR-036)</p>${kvList({ inbound: dir(e.inbound), outbound: dir(e.outbound) })}<p class="sub">Published lists; FW01 pulls them and the controller reads the tables back. Inbound is read-back only; outbound is also verified by an egress probe (see the policy's verification).</p>`
    : `<p class="sub">Real-country enforcement disabled; country policies are SIMULATED.</p>`;
}

async function renderAudit() {
  let a;
  try { a = await api("/api/audit?limit=40"); } catch (_) { return; }
  $("#audit tbody").innerHTML = a.map((r) => `<tr><td>${tShort(r.at)}</td><td>${esc(r.actor)}</td><td>${esc(r.action)}</td><td class="mono">${esc(r.subject)}</td></tr>`).join("");
}

async function renderNetwork() {
  let n;
  try { n = await api("/api/network?limit=200"); } catch (_) { return; }
  const d = n.detector || {}, w = n.windows || {}, ev = n.events || {};
  const cal = d.calibration_error
    ? badge("var(--critical)", `calibration error: ${esc(d.calibration_error)}`)
    : d.calibrated_on
      ? badge("var(--good)", `calibrated on ${d.calibrated_on} benign windows`)
      : badge("var(--warning)", "ceilings only (no calibration)");
  const strong = (ev.net_strong || 0), unfam = (ev.net_unfamiliar || 0);
  const verdicts = (n.recent || []).filter((v) => v.unfamiliar || v.strong).slice(0, 8);
  const rows = verdicts.map((v) => `<tr><td>${tShort(v.window_end)}</td><td class="mono">${esc(v.source_ip)}</td>
    <td>${badge(v.strong ? "var(--serious)" : "var(--warning)", v.strong ? "strong" : "unfamiliar")}</td>
    <td class="num">${fmt(v.score, 2)}</td><td class="mono">${esc((v.reasons || []).slice(0, 3).join("; ")) || "–"}</td></tr>`).join("");
  $("#network").innerHTML = `<dl class="kv">
      <dt>mode</dt><dd>${esc(n.mode || "–")}</dd>
      <dt>calibration</dt><dd>${cal}</dd>
      <dt>validation</dt><dd class="sub">benign false-unfamiliar rate only (NV2); recall needs attack runs</dd>
      <dt>tracked sources</dt><dd class="num">${w.tracked_sources ?? 0}</dd>
      <dt>windows too late / dropped</dt><dd class="num">${w.too_late ?? 0} / ${w.dropped ?? 0}</dd>
      <dt>verdicts since start</dt><dd>${unfam} unfamiliar, ${strong} strong</dd>
    </dl>
    <h3>Recent non-benign windows</h3>${verdicts.length
      ? `<div class="table-wrap short"><table><thead><tr><th>Window end</th><th>Source</th><th>Verdict</th><th class="num">Score</th><th>Reasons</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="empty">No unfamiliar or strong network windows in the recent history.</div>`}`;

  const blocks = n.protected_blocked || [];
  const bcount = {};
  for (const b of blocks) { const k = `${b.src_ip}→${b.dst_ip}:${b.dst_port}/${b.proto}`; bcount[k] = bcount[k] || { ...b, n: 0 }; bcount[k].n++; }
  const brows = Object.values(bcount).slice(0, 12).map((b) => `<tr><td class="mono">${esc(b.src_ip)}</td><td class="mono">${esc(b.dst_ip)}:${esc(b.dst_port ?? "")}</td>
    <td>${esc(b.proto)}</td><td>${esc(b.iface)}</td><td class="sub">${esc(b.source_reason)}</td><td class="num">${b.n}</td></tr>`).join("");
  $("#netblocks").innerHTML = `<dl class="kv">
      <dt>protected-source blocks</dt><dd class="num">${ev.pf_block_protected || 0}</dd>
      <dt>client blocks (counted only)</dt><dd class="num">${ev.pf_block_client || 0}</dd>
      <dt>other pf lines (pass/outbound/IPv6)</dt><dd class="num">${ev.pf_other || 0}</dd>
    </dl>
    ${blocks.length
      ? `<div class="table-wrap short"><table><thead><tr><th>From (protected)</th><th>To (forbidden)</th><th>Proto</th><th>Iface</th><th>Why protected</th><th class="num">n</th></tr></thead><tbody>${brows}</tbody></table></div>`
      : `<div class="empty">No protected-source blocks seen. (Normal operation produces none; the isolation suite does.)</div>`}`;
}

async function renderAuthCtl() {
  let h;
  try { h = await api("/api/health"); } catch (_) { return; }
  const waf = (h.backends || []).find((b) => b.backend === "waf") || {};
  const fw = (h.backends || []).find((b) => b.backend === "opnsense") || {};
  const lc = waf.login_controls || fw.login_controls || {};
  const rl = waf.rate_limited || {};
  const lcRows = Object.entries(lc);
  const rlRows = Object.entries(rl);
  const guard = rlRows.filter(([, v]) => JSON.stringify(v).includes("shared_address"));
  $("#authctl").innerHTML = `<div class="grid2">
    <div><h3>Active login controls (A3)</h3>${lcRows.length
      ? `<div class="table-wrap short"><table><thead><tr><th>Account / source</th><th>Control</th></tr></thead><tbody>${lcRows.map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${badge("var(--warning)", esc(typeof v === "object" ? JSON.stringify(v) : v))}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty">No login controls active. In monitor mode these are proposed, not applied; A3 is deployed and refused 0 of 4 255 legitimate logins in evaluation.</div>`}</div>
    <div><h3>Shared-address guard</h3>${guard.length
      ? `<div class="table-wrap short"><table><thead><tr><th>Address</th><th>Downgraded to</th></tr></thead><tbody>${guard.map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${badge("var(--neutral)", "strict rate limit · human approval")}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty">No shared address under guard now. A block proposed for an address shared by ≥ 3 accounts becomes a human-approved strict rate limit (ADR-043); not yet triggered live.</div>`}
    <h3>Active rate limits</h3>${rlRows.length ? kvList(rl) : `<div class="empty">None.</div>`}</div>
  </div>`;
}

async function refresh() {
  try {
    overview = await api("/api/overview");
  } catch (e) {
    $("#tiles").innerHTML = `<div class="tile"><div class="label">Not connected</div><div class="value">–</div><div class="note">${esc(e.message)} — set an API token</div></div>`;
    $("#token-form").hidden = false;
    const el = $("#status");
    const denied = /^401/.test(e.message);
    el.className = "status bad";
    el.querySelector(".status-title").textContent = denied ? "Enter your API token to connect" : "Cannot reach the controller";
    el.querySelector(".status-sub").textContent = denied
      ? (TOKEN ? "That token was not accepted. Paste a valid viewer, operator or admin token in the box above and press Connect." : "The connection works; the page just needs a token. Paste a viewer token in the box above and press Connect.")
      : "Check that the SSH tunnel is still running, then reload.";
    $("#status-reasons").innerHTML = `<li>${esc(e.message)}</li>`;
    return;
  }
  renderTiles(overview);
  lineChart($("#risk-chart"), overview.timeline, { key: "max_risk", label: "max risk", yMax: 100, refs: [{ v: 45, label: "rate-limit" }, { v: 65, label: "block" }] });
  lineChart($("#req-chart"), overview.timeline, { key: "requests", label: "requests" });
  renderSources(overview);
  renderTelemetry(overview);
  renderGeo(overview);
  renderNetSummary();
  if (!statusReady || ++statusTick % 3 === 0) { statusReady = true; renderStatus(); }
}

// Firewall panel: devices' own read-back state (/api/health) plus the latest enforcement decisions.
async function renderFirewall() {
  let h, pol = [];
  try { h = await api("/api/health"); } catch (_) { return; }
  try { pol = await api("/api/policies?limit=5"); } catch (_) { /* optional */ }
  const be = (n) => (h.backends || []).find((b) => b.backend === n) || {};
  const fw = be("opnsense"), waf = be("waf");
  const dot = (ok) => `<span class="dot${ok ? " live-dot" : ""}" style="background:${ok ? "var(--good)" : "var(--critical)"}"></span>`;
  const n = (x) => (x ? (Array.isArray(x) ? x.length : Object.keys(x).length) : 0);
  const blocked = fw.blocked_sources || [];
  const box = (k, v, note) => `<div class="fwbox"><div class="k">${esc(k)}</div><div class="v">${v}</div><div class="n">${note}</div></div>`;
  const gi = (h.backends || []).find((b) => b.geo_inbound)?.geo_inbound || [], go = (h.backends || []).find((b) => b.geo_outbound)?.geo_outbound || [];
  const mode = h.mode;
  const rows = (Array.isArray(pol) ? pol : []).slice(0, 5).map((p) => {
    const t = p.intent.target;
    const target = t.source_ip || t.route || `${t.country_code} ${t.direction}${t.simulated ? " (SIMULATED)" : ""}`;
    return `<tr><td>${tShort(p.updated_at)}</td><td>${esc(p.intent.kind)}</td><td class="mono">${esc(target)}</td><td>${badge(STATE[p.state] || "var(--neutral)", p.state)}</td></tr>`;
  }).join("");
  $("#fw-live").innerHTML = `<div class="fwgrid">
    ${box("FW01 OPNsense", `${dot(fw.reachable)}${fw.reachable ? "reachable" : "UNREACHABLE"}`, esc(fw.error || "API answering; rules read back"))}
    ${box("Blocked at FW01", n(blocked), n(blocked) ? blocked.map(esc).join(", ") : "no source blocked")}
    ${box("WAF01", `${dot(waf.reachable)}${waf.reachable ? "reachable" : "UNREACHABLE"}`, `rules revision ${esc(waf.revision ?? "–")}`)}
    ${box("WAF denies / rate limits", `${n(waf.waf_denied_sources)} / ${n(waf.rate_limited)}`, `login controls: ${n(waf.login_controls)}`)}
    ${box("Country blocks", `${gi.length} in · ${go.length} out`, gi.length + go.length ? esc([...gi, ...go].join(", ")) : "none active")}
    ${box("Enforcement mode", esc(mode), mode === "monitor" ? "AI decisions are recorded, not applied; manual actions are applied" : "ENFORCING: decisions are applied")}
  </div>
  <h3>Latest enforcement decisions</h3>
  ${rows ? `<div class="table-wrap short"><table><thead><tr><th>Time</th><th>Kind</th><th>Target</th><th>State</th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="empty">No enforcement decisions yet.</div>`}`;
}

const TABS = [["overview", "Overview"], ["threats", "Threats"], ["network", "Network"], ["firewall", "Firewall & controls"], ["learning", "Learning"], ["system", "System"]];
function showTab(name) {
  if (!TABS.some(([k]) => k === name)) name = "overview";
  document.querySelectorAll(".tab").forEach((t) => { t.hidden = t.dataset.tab !== name; });
  document.querySelectorAll("#nav a").forEach((l) => { const on = l.dataset.tab === name; l.classList.toggle("on", on); l.setAttribute("aria-selected", on); });
  try { localStorage.setItem("afw_tab", name); } catch (_) { /* ignore */ }
  if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
}
function buildNav() {
  $("#nav").innerHTML = TABS.map(([k, l]) => `<a href="#${k}" data-tab="${k}" role="tab">${esc(l)}</a>`).join("");
  $("#nav").addEventListener("click", (e) => { const a = e.target.closest("a[data-tab]"); if (a) { e.preventDefault(); showTab(a.dataset.tab); } });
  let t = location.hash.slice(1);
  if (!t) { try { t = localStorage.getItem("afw_tab") || ""; } catch (_) { /* ignore */ } }
  showTab(t || "overview");
}
buildNav();
window.addEventListener("hashchange", () => showTab(location.hash.slice(1)));

// ------------------------------------------------------------ toast + confirm dialog
function toast(msg, bad) {
  const t = document.createElement("div");
  t.className = "toast" + (bad ? " bad" : "");
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), bad ? 7000 : 3500);
}
function confirmDialog({ title, body, confirmLabel, danger }) {
  return new Promise((resolve) => {
    const ov = document.createElement("div");
    ov.className = "overlay";
    ov.innerHTML = `<div class="dialog" role="dialog" aria-modal="true" aria-label="${esc(title)}"><h3>${esc(title)}</h3><div class="dlg-body">${body}</div>
      <div class="dlg-actions"><button type="button" data-no>Cancel</button><button type="button" data-yes class="${danger ? "danger" : "primary"}">${esc(confirmLabel || "Confirm")}</button></div></div>`;
    const done = (v) => { ov.remove(); document.removeEventListener("keydown", onKey); resolve(v); };
    const onKey = (e) => { if (e.key === "Escape") done(false); };
    ov.addEventListener("click", (e) => { if (e.target === ov) done(false); });
    ov.querySelector("[data-no]").addEventListener("click", () => done(false));
    ov.querySelector("[data-yes]").addEventListener("click", () => done(true));
    document.addEventListener("keydown", onKey);
    document.body.appendChild(ov);
    ov.querySelector("[data-no]").focus();
  });
}

// ------------------------------------------------------------ connect an AI agent (MCP)
// Builds a copy-paste MCP client config. It never embeds a token value: the
// generated command points at a token *file path* on the lab host, which the
// MCP server (started over ssh) reads there -- no secret ever appears on this page.
// Whatever client connects still goes through the same role-checked, validated,
// audited API as this dashboard; nothing here is a separate or wider channel.
const MCP_ROLE_FILES = {
  operator: { file: "mcp.token", note: "Full firewall actions: block, WAF deny, rate-limit, approve/reject/revoke. Cannot change mode or promote models. Recommended for the demo." },
  admin: { file: "admin.token", note: "Everything operator can do, plus switching mode (monitor/assisted/auto). The current model flags most new legitimate users in auto mode -- only pick this if you intend to demonstrate that, and never leave it in auto mode unattended." },
};
function mcpSnippet(role, target) {
  const home = "/home/" + (target.split("@")[0] || "gns3");
  const tokenFile = `${home}/.config/afw/api/${MCP_ROLE_FILES[role].file}`;
  const remote = `cd ~/uot/ai-adaptive-firewall && AFW_API_URL=https://10.77.50.10:8080 AFW_API_CA=${home}/.config/afw/pki/lab-ca.pem AFW_MCP_TOKEN_FILE=${tokenFile} uv run afw-mcp`;
  const cli = `claude mcp add afw -- ssh ${target} ${JSON.stringify(remote)}`;
  const json = JSON.stringify({ mcpServers: { afw: { command: "ssh", args: [target, remote] } } }, null, 2);
  return { cli, json };
}
function openMcpConnect() {
  const ov = document.createElement("div");
  ov.className = "overlay";
  ov.innerHTML = `<div class="dialog mcp-dialog" role="dialog" aria-modal="true" aria-label="Connect an AI agent">
    <h3>Connect an AI agent (MCP)</h3>
    <div class="dlg-body">
      <p>Any MCP-capable AI assistant (Claude Code, Claude Desktop, others) can control this firewall through the same MCP server this project ships -- validated and audited exactly like the dashboard's own actions, with protected/management addresses always refused.</p>
      <p class="hint">Nothing here reveals a token: the command below points at a token <em>file</em> on the lab host, which is read there when the SSH-launched server starts.</p>
      <label>Role<br><select id="mcp-role"><option value="operator">Operator -- full firewall control (recommended)</option><option value="admin">Admin -- also mode switching</option></select></label>
      <label>SSH target<br><input id="mcp-ssh" type="text" value="gns3@100.103.204.8" spellcheck="false"></label>
      <p class="hint" id="mcp-warn"></p>
      <label>Claude Code (one line)</label>
      <pre class="mcp-code" id="mcp-cli"></pre>
      <button type="button" class="seg" data-copy="mcp-cli">Copy command</button>
      <label>claude_desktop_config.json / other MCP clients</label>
      <pre class="mcp-code" id="mcp-json"></pre>
      <button type="button" class="seg" data-copy="mcp-json">Copy JSON</button>
    </div>
    <div class="dlg-actions"><button type="button" data-no>Close</button></div>
  </div>`;
  const rebuild = () => {
    const role = ov.querySelector("#mcp-role").value;
    const target = ov.querySelector("#mcp-ssh").value.trim() || "gns3@100.103.204.8";
    const { cli, json } = mcpSnippet(role, target);
    ov.querySelector("#mcp-cli").textContent = cli;
    ov.querySelector("#mcp-json").textContent = json;
    ov.querySelector("#mcp-warn").textContent = role === "admin" ? MCP_ROLE_FILES.admin.note : MCP_ROLE_FILES.operator.note;
    ov.querySelector("#mcp-warn").classList.toggle("warn-text", role === "admin");
  };
  ov.querySelector("#mcp-role").addEventListener("change", rebuild);
  ov.querySelector("#mcp-ssh").addEventListener("input", rebuild);
  ov.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(ov.querySelector("#" + b.dataset.copy).textContent); toast("Copied"); }
    catch (_) { toast("Could not copy -- select and copy manually", true); }
  }));
  const close = () => { ov.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  ov.addEventListener("click", (e) => { if (e.target === ov) close(); });
  ov.querySelector("[data-no]").addEventListener("click", close);
  document.addEventListener("keydown", onKey);
  document.body.appendChild(ov);
  rebuild();
}
$("#mcp-btn").addEventListener("click", openMcpConnect);

// ------------------------------------------------------------ role and controls
let ROLE = "none";
let statusReady = false, statusTick = 0;
async function loadRole() {
  try { ROLE = (await api("/api/whoami")).role; } catch (_) { ROLE = "none"; }
}
const canOperate = () => ROLE === "operator" || ROLE === "admin";

async function act(path, body, okMsg) {
  try {
    const r = await api(path, { method: "POST", body: JSON.stringify(body || {}) });
    toast(okMsg(r));
    refresh(); slow();
    return r;
  } catch (e) { toast(e.message.replace(/^\d+ /, ""), true); return null; }
}

async function renderControls() {
  const el = $("#controls");
  if (!el) return;
  if (!canOperate()) {
    el.innerHTML = `<div class="empty">This token can watch but not change anything (role: ${esc(ROLE)}). Click <b>API token</b> and use an operator or admin token to enable controls.</div>`;
    return;
  }
  const mode = overview ? overview.mode : "";
  const modeBtns = ["monitor", "assisted", "auto"].map((m) => `<button type="button" class="seg${m === mode ? " on" : ""}" data-mode="${m}" ${ROLE !== "admin" ? "disabled" : ""}>${m}</button>`).join("");
  el.innerHTML = `<div class="grid2">
    <div><h3>Operating mode</h3>
      <div class="segs">${modeBtns}</div>
      <p class="hint"><b>monitor</b>: the AI only records proposals; your own manual actions are still applied. <b>assisted</b>: every action waits for your approval. <b>auto</b>: low-risk actions apply by themselves within the safety limits.${ROLE !== "admin" ? " Changing the mode needs an admin token." : ""}</p></div>
    <div><h3>Restrict a source</h3>
      <form id="block-form" class="inline">
        <select id="blk-kind" aria-label="Action"><option value="source_block">Block at firewall</option><option value="waf_deny">Deny at WAF</option><option value="rate_limit:strict">Rate-limit (strict)</option><option value="rate_limit:moderate">Rate-limit (moderate)</option></select>
        <input id="blk-ip" placeholder="10.77.20.x" inputmode="decimal" aria-label="IP address" required pattern="^\\d{1,3}(\\.\\d{1,3}){3}$">
        <select id="blk-min" aria-label="Duration"><option value="120">2 min</option><option value="300">5 min</option><option value="900">15 min</option><option value="3600">1 hour</option></select>
        <input id="blk-why" placeholder="reason" maxlength="120" aria-label="Reason">
        <button type="submit" class="danger">Check &amp; apply…</button>
      </form>
      <p class="hint">The validator runs first and shows what would happen. Blocks expire by themselves. Management, database, firewall and WAF addresses are always refused.</p></div>
  </div>`;
  el.querySelectorAll("[data-mode]").forEach((b) => b.addEventListener("click", () => changeMode(b.dataset.mode)));
  $("#block-form").addEventListener("submit", blockFlow);
}

async function changeMode(m) {
  if (!overview || m === overview.mode) return;
  const warn = m === "auto"
    ? `<p><b>Automatic mode will block and rate-limit traffic without asking you.</b></p><p>The current model was measured to flag most <em>new legitimate users</em> (window false-positive rate about 0.84 on unseen users). Enable this only if you accept that real users may be restricted.</p>`
    : m === "assisted" ? `<p>Every restriction will wait for your approval before it touches the firewall.</p>` : `<p>The AI will only record proposals. Your own manual actions are still applied.</p>`;
  if (!(await confirmDialog({ title: `Switch to ${m} mode?`, body: warn, confirmLabel: `Switch to ${m}`, danger: m === "auto" }))) return;
  await act("/api/mode", { mode: m }, () => `Mode is now ${m}`);
}

async function blockFlow(e) {
  e.preventDefault();
  const ip = $("#blk-ip").value.trim(), dur = Number($("#blk-min").value), why = $("#blk-why").value.trim() || "operator block from dashboard";
  const [kind, prof] = $("#blk-kind").value.split(":");
  const body = { kind, target: { type: "source", source_ip: ip }, duration_s: dur, reason: why, ...(prof ? { rate_profile: prof } : {}) };
  const what = $("#blk-kind").selectedOptions[0].textContent;
  let sim;
  try { sim = await api("/api/policies/simulate", { method: "POST", body: JSON.stringify(body) }); } catch (er) { toast(er.message.replace(/^\d+ /, ""), true); return; }
  if (!sim.valid) { toast("Refused: " + sim.errors.join("; "), true); return; }
  const ok = await confirmDialog({
    title: `${what}: ${ip} for ${dur / 60} min?`,
    body: `<p>The validator accepts this action. <b>It will be applied now</b> and removed automatically after ${dur / 60} min; manual actions are enforced even in monitor mode (monitor mode only holds back the AI's own decisions).</p>${(sim.notes || []).map((n) => `<p class="hint">${esc(n)}</p>`).join("")}`,
    confirmLabel: "Apply", danger: true,
  });
  if (ok) await act("/api/policies", body, (r) => `Policy ${r.state}`);
}

async function policyAction(id, verb) {
  const label = { approve: "Approve", reject: "Reject", revoke: "Revoke" }[verb];
  if (!(await confirmDialog({ title: `${label} this decision?`, body: `<p class="mono">${esc(id)}</p>`, confirmLabel: label}))) return;
  await act(`/api/policies/${id}/${verb}`, verb === "approve" ? {} : { reason: `${verb} from dashboard` }, (r) => `${label}d: ${r.state}`);
}

// Protected addresses (lab infrastructure, probes) are tagged, and never counted as a threat.
let PROTECTED = [];
const ip4 = (s) => s.split(".").reduce((n, p) => n * 256 + Number(p), 0);
const isProtected = (ip) => PROTECTED.some(([base, bits]) => { const m = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0; return ((ip4(ip) & m) >>> 0) === ((base & m) >>> 0); });
async function loadProtected() {
  try { PROTECTED = (await api("/api/config")).safety.protected.map((p) => { const [n, b] = p.network.split("/"); return [ip4(n), Number(b ?? 32)]; }); } catch (_) { /* keep */ }
}

// ------------------------------------------------------------ status banner
function computeStatus(o, h, dets) {
  const bad = [], warn = [], good = [];
  const be = (n) => (h.backends || []).find((b) => b.backend === n) || {};
  if (!be("opnsense").reachable) bad.push("FW01 firewall API is not reachable"); else good.push("FW01 firewall reachable");
  if (!be("waf").reachable) bad.push("WAF is not reachable"); else good.push("WAF reachable");
  if (h.model_error) bad.push("Model error: " + h.model_error);
  const stale = Object.entries((o.telemetry || {}).sensors || {}).filter(([, v]) => v.stale).map(([k]) => k);
  if (stale.length) bad.push(`Sensor${stale.length > 1 ? "s" : ""} silent: ${stale.join(", ")}`); else {
    const waiting = Object.entries((o.telemetry || {}).sensors || {}).filter(([, v]) => v.heartbeat_age_s === null).map(([k]) => k);
    if (waiting.length) warn.push(`Waiting for first heartbeat: ${waiting.join(", ")}`); else good.push("all sensors reporting");
  }
  if (o.telemetry_degraded && !stale.length) warn.push("Telemetry degraded");
  const hot = (o.live_sources || []).filter((s) => s.risk >= 45);
  hot.forEach((s) => warn.push(`Suspicious source ${s.source_ip || s.source} (risk ${fmt(s.risk, 0)})`));
  const recent = (dets || []).filter((d) => !isProtected(d.source_ip)).filter((d) => Date.now() - new Date(d.window_end).getTime() < 15 * 60 * 1000);
  if (recent.length) warn.push(`${recent.length} anomalous window${recent.length > 1 ? "s" : ""} in the last 15 min`);
  if (o.pending_approval) warn.push(`${o.pending_approval} decision${o.pending_approval > 1 ? "s" : ""} waiting for your approval`);
  if (o.active_policies.length) good.push(`${o.active_policies.length} active restriction${o.active_policies.length > 1 ? "s" : ""}`);
  good.push(o.mode === "monitor" ? "monitor mode: the AI is not enforcing anything" : `${o.mode} mode`);
  const level = bad.length ? "bad" : hot.length ? "alert" : warn.length ? "warn" : "ok";
  const title = { bad: "System needs attention", alert: "Possible malicious activity", warn: "Watch: something needs a look", ok: "All clear" }[level];
  const sub = { bad: "A component is down or silent; detection may be blind.", alert: "A source is behaving like an attacker. Open Threats.", warn: "Nothing dangerous detected, but review the items below.", ok: "No suspicious activity. Firewall, WAF and sensors are healthy." }[level];
  return { level, title, sub, items: [...bad, ...warn].concat(level === "ok" || !bad.length ? good : []) };
}
async function renderStatus() {
  if (!overview) return;
  if (!PROTECTED.length) await loadProtected();
  let h = {}, dets = [];
  try { h = await api("/api/health"); } catch (_) { /* keep empty */ }
  try { dets = await api("/api/detections?limit=30&anomalous=true"); } catch (_) { /* optional */ }
  const s = computeStatus(overview, h, dets);
  const el = $("#status");
  el.className = "status " + s.level;
  el.querySelector(".status-title").textContent = s.title;
  el.querySelector(".status-sub").textContent = s.sub;
  $("#status-reasons").innerHTML = s.items.map((i) => `<li>${esc(i)}</li>`).join("");
  document.title = (s.level === "ok" ? "" : "● ") + "AFW Control Plane";
}

// ------------------------------------------------------------ threats + network + config
async function renderDetections() {
  if (!PROTECTED.length) await loadProtected();
  let ds;
  try { ds = await api("/api/detections?limit=25&anomalous=true"); } catch (_) { return; }
  const tb = $("#detections tbody");
  if (!ds.length) { tb.innerHTML = `<tr><td colspan="5" class="empty">No anomalous windows recorded. The detectors are running; they flag nothing right now.</td></tr>`; return; }
  tb.innerHTML = ds.map((d) => `<tr><td>${tShort(d.window_end)}</td><td class="mono">${esc(d.source_ip)}${isProtected(d.source_ip) ? " " + badge("var(--neutral)", "lab infrastructure") : ""}</td><td>${esc(d.detector)}</td><td class="num">${fmt(d.score, 3)} / ${fmt(d.threshold, 3)}</td><td class="num">${esc(d.n_requests)}</td></tr>`).join("");
}
function renderNetSummary() {
  const c = ((overview || {}).telemetry || {}).counts || {};
  const box = (k, v, n) => `<div class="fwbox"><div class="k">${esc(k)}</div><div class="v">${esc(v ?? 0)}</div><div class="n">${esc(n)}</div></div>`;
  $("#netsummary").innerHTML = `<div class="fwgrid">
    ${box("Connections seen", c.net_flow, "flows reported by FW01's IDS sensor")}
    ${box("DNS lookups", c.net_dns, "names resolved by lab clients")}
    ${box("TLS sessions", c.net_tls, "encrypted sessions observed")}
    ${box("Unfamiliar behaviour", c.net_unfamiliar, "windows unlike the benign baseline")}
    ${box("Firewall-dropped packets", c.pf_other, "pf log lines received")}
    ${box("Telemetry messages", c.received, "all sensors, since start")}
  </div>`;
}
async function renderConfig() {
  let x;
  try { x = await api("/api/config"); } catch (_) { return; }
  const row = (k, v) => `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`;
  const r = x.risk, s = x.safety;
  $("#config").innerHTML = `<div class="grid2">
    <div><h3>Risk thresholds (evidence score 0–100)</h3><dl class="kv">${row("watch", r.watch)}${row("rate-limit", r.rate_limit)}${row("block", r.block)}${row("escalate", r.escalate)}${row("history half-life", r.history_half_life_s + " s")}${row("base block time", r.base_block_s + " s")}</dl>
      <h3>Detection window</h3><dl class="kv">${row("length / hop", `${x.window.length_s} s / ${x.window.hop_s} s`)}${row("min requests", x.window.min_requests)}</dl>
      <h3>Protected application</h3><dl class="kv">${x.services.map((v) => row(v.name, `${v.address}:${v.port}`)).join("")}${x.applications.map((v) => row(v.app_id, `${v.routes} allowed routes`)).join("")}</dl></div>
    <div><h3>Safety limits</h3><dl class="kv">${row("shortest action", s.min_duration_s + " s")}${row("longest automatic", s.max_auto_duration_s + " s")}${row("longest any", s.max_duration_s + " s")}${row("max active policies", s.max_active_policies)}${row("max auto actions / min", s.max_auto_actions_per_minute)}${row("may apply automatically", s.auto_kinds.join(", "))}</dl>
      <h3>Never blocked (protected)</h3><div class="table-wrap short"><table><tbody>${s.protected.map((p) => `<tr><td class="mono">${esc(p.network)}</td><td>${esc(p.reason)}</td></tr>`).join("")}</tbody></table></div></div>
  </div>`;
}


async function slow() { renderStatus(); renderDetections(); renderConfig(); renderControls(); renderFirewall(); renderPolicies(); renderAdaptation(); renderShadow(); renderChallenger(); renderIdsOnly(); renderModels(); renderNetwork(); renderAuthCtl(); renderExperiments(); renderAudit(); if (selected) renderBaseline(); }

loadRole().then(() => { refresh(); slow(); });
setInterval(refresh, 2000);
setInterval(slow, 6000);
