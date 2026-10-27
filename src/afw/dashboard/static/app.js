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

$("#token-btn").addEventListener("click", () => {
  const t = prompt("API bearer token (viewer role or higher)", TOKEN);
  if (t !== null) {
    TOKEN = t.trim();
    try { localStorage.setItem("afw_token", TOKEN); } catch (_) { /* ignore */ }
    refresh(); slow();
  }
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
      <td><button type="button" data-explain="${esc(p.policy_id)}">Explain</button>${p.state === "pending_approval" ? ` <button type="button" data-approve="${esc(p.policy_id)}">Approve</button>` : ""}</td></tr>`;
  }).join("");
  tb.querySelectorAll("[data-explain]").forEach((b) => b.addEventListener("click", () => explain(b.dataset.explain)));
  tb.querySelectorAll("[data-approve]").forEach((b) => b.addEventListener("click", async () => {
    try { await api(`/api/policies/${b.dataset.approve}/approve`, { method: "POST" }); renderPolicies(); } catch (e) { alert(e.message); }
  }));
}

async function explain(id) {
  let x;
  try { x = await api(`/api/policies/${id}/explain`); } catch (e) { alert(e.message); return; }
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
  const evals = a.evaluations.slice(0, 3).map((e) => `<div class="ev"><b>Candidate profile v${e.candidate_profile_version}</b> — ${badge(e.passed ? "var(--good)" : "var(--critical)", e.passed ? "gate passed" : "gate failed")}<br>${e.checks.map((c) => `<span class="check">${c.passed ? "✔" : "✘"} ${esc(c.name)} ${c.value !== null ? `= ${fmt(c.value, 4)}` : ""}${c.limit !== null ? ` (limit ${fmt(c.limit, 4)})` : ""}</span>`).join("<br>")}</div>`).join("");
  $("#adaptation").innerHTML = `${mon ? `<dl class="kv"><dt>shadow windows accepted</dt><dd>${mon.accepted_windows}</dd><dt>rejected (reputation gate)</dt><dd class="mono">${esc(JSON.stringify(mon.rejected))}</dd><dt>new routes (sources)</dt><dd class="mono">${esc(JSON.stringify(mon.new_routes))}</dd><dt>new app versions</dt><dd class="mono">${esc(JSON.stringify(mon.new_versions))}</dd><dt>shadow anomaly rate</dt><dd>${fmt(mon.shadow_anomaly_rate, 3)}</dd></dl>` : `<div class="empty">No trusted profile loaded.</div>`}
    <h3>Drift reports</h3>${reports || `<div class="empty">None.</div>`}<h3>Candidate evaluations</h3>${evals || `<div class="empty">None.</div>`}`;
}

async function renderModels() {
  let ms, ps;
  try { [ms, ps] = await Promise.all([api("/api/models"), api("/api/profiles")]); } catch (_) { return; }
  const prof = ps.map((p) => `<tr><td>v${p.version}</td><td>${badge(p.status === "trusted" ? "var(--good)" : "var(--neutral)", p.status)}</td><td class="num">${p.provenance.n_windows}</td><td class="num">${p.provenance.n_sources}</td><td>${esc(p.provenance.dataset_ids.join(", "))}</td></tr>`).join("");
  const mods = ms.slice(0, 12).map((m) => { const v = m.validation_metrics; return `<tr><td>${esc(m.detector)}</td><td>p${m.profile_version}</td><td>${esc(m.status)}</td><td class="num">${fmt(v.fpr, 4)}</td><td class="num">${fmt(v.recall, 3)}</td><td class="num">${fmt(v.roc_auc, 3)}</td><td class="num">${fmt(v.mean_latency_us, 0)}</td><td class="num">${v.model_bytes ? fmt(v.model_bytes / 1024, 0) : "–"}</td></tr>`; }).join("");
  $("#models").innerHTML = `<div class="table-wrap short"><table><thead><tr><th>Profile</th><th>Status</th><th class="num">Windows</th><th class="num">Sources</th><th>Datasets</th></tr></thead><tbody>${prof || `<tr><td colspan="5" class="empty">No profiles.</td></tr>`}</tbody></table></div>
    <div class="table-wrap short" style="margin-top:10px"><table><thead><tr><th>Detector</th><th>Profile</th><th>Status</th><th class="num">Val FPR</th><th class="num">Val recall</th><th class="num">AUC</th><th class="num">µs/score</th><th class="num">KiB</th></tr></thead><tbody>${mods || `<tr><td colspan="8" class="empty">No models.</td></tr>`}</tbody></table></div>`;
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
  $("#challenger").innerHTML = `<h3>Probation</h3>${prob}<h3>Gate evaluations</h3>${evals || `<div class="empty">No evaluations yet.</div>`}<h3>Promotion history</h3>${hist || `<div class="empty">No promotions.</div>`}`;
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
}

async function renderAudit() {
  let a;
  try { a = await api("/api/audit?limit=40"); } catch (_) { return; }
  $("#audit tbody").innerHTML = a.map((r) => `<tr><td>${tShort(r.at)}</td><td>${esc(r.actor)}</td><td>${esc(r.action)}</td><td class="mono">${esc(r.subject)}</td></tr>`).join("");
}

async function refresh() {
  try {
    overview = await api("/api/overview");
  } catch (e) {
    $("#tiles").innerHTML = `<div class="tile"><div class="label">Not connected</div><div class="value">–</div><div class="note">${esc(e.message)} — set an API token</div></div>`;
    return;
  }
  renderTiles(overview);
  lineChart($("#risk-chart"), overview.timeline, { key: "max_risk", label: "max risk", yMax: 100, refs: [{ v: 45, label: "rate-limit" }, { v: 65, label: "block" }] });
  lineChart($("#req-chart"), overview.timeline, { key: "requests", label: "requests" });
  renderSources(overview);
  renderTelemetry(overview);
  renderGeo(overview);
}

async function slow() { renderPolicies(); renderAdaptation(); renderShadow(); renderChallenger(); renderIdsOnly(); renderModels(); renderExperiments(); renderAudit(); if (selected) renderBaseline(); }

refresh(); slow();
setInterval(refresh, 2000);
setInterval(slow, 6000);
