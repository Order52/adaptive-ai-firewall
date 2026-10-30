# Dissertation figures

Publication-ready figures generated **only from committed evidence** — no synthetic
or fabricated numbers. Each is provided as PDF (for LaTeX `\includegraphics`) and PNG
(for Word/preview); Figure C is also hand-authored SVG.

| Figure | File | Source evidence | Point it makes |
|---|---|---|---|
| **A** | `fig-a-detector-latency` | `real-benign-baseline-2026-10-17.md` (detector table) | At the **same 1.30% validation FPR**, the ML detector (Isolation Forest, ~11.4 ms) costs ~800× the statistical detector (robust_stats, ~14 µs) — the measured price of M2 over M1. |
| **B** | `fig-b-zero-false-positives` | `real-benign-baseline-2026-10-17.md` (live-inference table) | On **genuine lab traffic**, profile v2 scores every live benign source **below every detector threshold** (score ÷ threshold < 1.0) — zero false positives, unlike the earlier synthetic profile. |
| **C** | `fig-c-adaptation-lifecycle` | `real-benign-baseline-2026-10-17.md` (Scenario C) | The **real** drift → candidate → anti-poisoning gate → reviewed promotion → recovery loop, observed live. Attacker traffic cannot define "normal" (multi-source gate, human-in-the-loop promote). |
| **D** | `fig-d-soak-stability` | `soak-*.md` / `samples.tsv` (sustained-load soak) | Controller RSS and tick latency stay flat across a >60-minute continuous benign soak — no leak, no drift, benign traffic never restricted. |
| **E** | `fig-e-dashboard-live` (PNG) | live dashboard render (`dashboard-live-2026-10-20.md`) | The operator dashboard populated with **real** profile-v2 data: stat tiles, live risk, policy-lifecycle history, model/profile table, candidate-evaluation gates, M0/M1/M2 experiments, telemetry health, audit trail — renders with no console errors. |
| **F** | `fig-f-explainable-detection` | `dashboard-live-2026-10-20.md` (live assessment `risk-7b3ee514524a`) | **Explainable AI on live traffic**: occlusion feature attributions show *why* the health-probe source scored elevated (unknown route, never logs in, sparse) — in monitor mode, observed not blocked. |

## Regenerate

```bash
# A, B (and D if a soak samples.tsv exists) — ephemeral matplotlib, no project dep change:
uv run --with matplotlib python docs/figures/make_figures.py [path/to/samples.tsv]

# C (SVG -> PDF/PNG):
uv run --with cairosvg python -c "import cairosvg; \
  cairosvg.svg2pdf(url='docs/figures/fig-c-adaptation-lifecycle.svg', write_to='docs/figures/fig-c-adaptation-lifecycle.pdf'); \
  cairosvg.svg2png(url='docs/figures/fig-c-adaptation-lifecycle.svg', write_to='docs/figures/fig-c-adaptation-lifecycle.png', output_width=1600)"
```

Colours use the validated `dataviz` reference categorical palette (blue/orange/aqua,
fixed order); no dual-axis; threshold shown as a single reference line. If a figure's
numbers ever diverge from the evidence files, the **evidence files are authoritative**.
