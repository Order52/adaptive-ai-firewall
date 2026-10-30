# Live dashboard + explainability evidence (2026-10-20/21)

Re-verification of the operator dashboard against the **real** trained profile v2
(after the cold restart and the 60-min soak), and a live explainable-detection
example. Closes the earlier "dashboard doesn't work well" concern with current
real-data state.

## Dashboard render — PASS

- Rendered the live controller dashboard (`http://10.77.50.10:8080/`) with headless
  Chromium (Playwright), viewer token injected via `localStorage['afw_token']`.
- **No console errors**; every panel populated from real data:
  - stat tiles: mode **monitor**, trusted profile **v2** (361 windows, 6 sources,
    `b4a83e64fc22`), ML model `isolation_forest-p2`, live sources, **0 active
    policies**, controller RSS.
  - highest-risk-per-window and requests-per-window charts; live-sources table with
    per-detector score/threshold; baseline-vs-current behaviour panel.
  - adaptive-policy-decisions lifecycle history (proposed → validated → applied →
    enforced → expired/rolled_back) with enforcement read-back
    (`states_killed`, `legitimate_ok`, `traffic=blocked`).
  - controlled-adaptation panel (shadow windows, drift reports, candidate gates);
    models-&-profiles table (v1 retired / v2 trusted; per-detector val FPR 0.013).
  - M0/M1/M2 experiments table; telemetry-health panel; audit trail.
- Figure: `docs/figures/fig-e-dashboard-live.png`.

## Live explainable detection — source 10.77.20.250 (the health prober)

A genuine live example of the explainable-AI requirement (assessment
`risk-7b3ee514524a`, 2026-10-21T03:23:58Z, profile v2, **monitor** mode):

| detector | score / threshold | anomalous | top occlusion drivers |
|---|---|---|---|
| robust_stats | 15.0 / 3.528 | yes | `unknown_route_frac`=1 (z=+20), `route_entropy`=0 (z=−10) |
| isolation_forest | 0.796 / 0.627 | yes | `distinct_usernames`=0, `login_rate`=0 (z=−3.4), `req_rate` (z=−4.9) |

Correlated risk **59 / band elevated**. Human reason codes:
`unknown_route_frac_high`, `route_entropy_low`, `login_rate_contrib`.

**Interpretation (honest):** `10.77.20.250` is the health-probe IP, which hits a
single endpoint (`/health`, a route not in the learned user-journey profile), never
logs in, and is very sparse — so it is *correctly* flagged as behaviourally
anomalous. In **monitor** mode it is observed, not blocked. This is a feature, not a
bug, and it illustrates a real deployment consideration: **infrastructure probes
should be allowlisted before switching an app to enforce mode**, or trained into the
profile as a legitimate behaviour class. It also demonstrates the system reacting to
a genuinely different behavioural pattern with a fully explained decision.

Figure: `docs/figures/fig-f-explainable-detection.png`.

## Reproduce

`scratchpad/render_dash.py` pattern: launch headless Chromium, inject the viewer
token into `localStorage`, open the dashboard, screenshot full page. Explainability
numbers come from `GET /api/.../risk_assessments` (MCP `risk_assessments` /
`recent_detections`) for the source.
