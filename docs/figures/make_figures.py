#!/usr/bin/env python3
"""Generate dissertation figures for AI-Adaptive-Firewall from REAL evidence.

Every number below is transcribed from committed evidence files — nothing is
synthetic or fabricated:
  - artifacts/evidence/real-benign-baseline-2026-10-17.md
  - artifacts/evidence/soak-*.md (Figure D, when a soak has been run)

Run (no project-dependency change needed):
  uv run --with matplotlib python docs/figures/make_figures.py

Outputs PDF (LaTeX) + PNG (Word/preview) into docs/figures/.
Palette: the validated `dataviz` reference categorical hues, fixed order.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

OUT = Path(__file__).resolve().parent

# dataviz reference categorical palette (light surface), fixed order
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#8a8982"
SURFACE, GRID = "#fcfcfb", "#e7e6e2"

mpl.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "font.family": "DejaVu Sans", "font.size": 10.5,
    "axes.edgecolor": MUTED, "axes.labelcolor": INK2, "text.color": INK,
    "xtick.color": INK2, "ytick.color": INK2,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.spines.top": False, "axes.spines.right": False,
})


def save(fig, stem: str) -> None:
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"{stem}.{ext}", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {stem}.pdf / .png")


def fig_a_latency() -> None:
    """Per-detector scoring latency (log) — the cost of ML at equal FP budget."""
    # from real-benign-baseline: thresholds chosen on real validation @1% FP budget
    names = ["robust_stats\n(M1 statistical)", "half_space_trees\n(streaming)",
             "isolation_forest\n(M2 ML)"]
    micros = [14.0, 57.0, 11400.0]          # µs/window scoring latency
    colors = [BLUE, AQUA, ORANGE]
    fig, ax = plt.subplots(figsize=(6.6, 3.1))
    y = range(len(names))
    ax.barh(list(y), micros, color=colors, height=0.6, zorder=3)
    ax.set_xscale("log")
    ax.set_xlim(5, 30000)
    ax.set_yticks(list(y)); ax.set_yticklabels(names)
    ax.invert_yaxis()
    ax.set_xlabel("scoring latency per window (µs, log scale)")
    ax.xaxis.set_major_formatter(FuncFormatter(
        lambda v, _: f"{v:.0f}µs" if v < 1000 else f"{v/1000:.0f}ms"))
    for yi, v in zip(y, micros):
        lab = f"{v:.0f} µs" if v < 1000 else f"{v/1000:.1f} ms"
        ax.text(v * 1.15, yi, lab, va="center", ha="left",
                color=INK, fontsize=9.5, fontweight="bold")
    ax.set_title("Detector scoring cost — all at 1.30% validation FPR (1% budget)",
                 color=INK, fontsize=11, fontweight="bold", loc="left", pad=10)
    ax.text(0, 1.14, "The ML detector (Isolation Forest) costs ~800× the statistical "
            "detector for the same false-positive budget.",
            transform=ax.transAxes, color=INK2, fontsize=8.7)
    save(fig, "fig-a-detector-latency")


def fig_b_zero_fp() -> None:
    """Live inference on real benign: every detector score below its threshold."""
    # from real-benign-baseline "Live inference verification" table
    srcs = ["10.77.20.10", "10.77.20.11", "10.77.20.12", "10.77.20.13"]
    rs = [1.449, 0.417, 2.023, 1.390]; rs_thr = 3.528
    iforest = [0.456, 0.375, 0.506, 0.505]; if_thr = 0.627
    # normalise each score as a fraction of its own threshold (1.0 = threshold)
    rs_r = [v / rs_thr for v in rs]
    if_r = [v / if_thr for v in iforest]
    fig, ax = plt.subplots(figsize=(6.6, 3.4))
    x = range(len(srcs)); w = 0.38
    b1 = ax.bar([i - w / 2 for i in x], rs_r, w, color=BLUE, zorder=3,
                label="robust_stats (M1)")
    b2 = ax.bar([i + w / 2 for i in x], if_r, w, color=ORANGE, zorder=3,
                label="isolation_forest (M2)")
    ax.axhline(1.0, color=INK2, lw=1.4, ls="--", zorder=4)
    ax.text(len(srcs) - 0.5, 1.02, "threshold", color=INK2, fontsize=8.5,
            ha="right", va="bottom", fontstyle="italic")
    ax.set_ylim(0, 1.15)
    ax.set_xticks(list(x)); ax.set_xticklabels(srcs, fontsize=9)
    ax.set_ylabel("detector score ÷ its threshold")
    ax.set_xlabel("real benign source (USERS zone)")
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.015,
                    f"{b.get_height():.2f}", ha="center", va="bottom",
                    color=INK2, fontsize=7.8)
    ax.legend(loc="upper left", frameon=False, fontsize=8.8, ncol=2)
    ax.set_title("Zero false positives on real traffic — all scores below threshold",
                 color=INK, fontsize=11, fontweight="bold", loc="left", pad=10)
    ax.text(0, 1.14, "Profile v2 (trained on 361 real benign windows) scores every "
            "live benign source below every detector threshold.",
            transform=ax.transAxes, color=INK2, fontsize=8.7)
    save(fig, "fig-b-zero-false-positives")


def fig_d_soak(samples_tsv: Path) -> None:
    """Controller stability over the soak — RSS + tick latency timeseries."""
    rows = list(csv.DictReader(samples_tsv.open(), delimiter="\t"))
    def col(k):
        out = []
        for r in rows:
            try:
                out.append(float(r[k]))
            except (ValueError, KeyError, TypeError):
                out.append(None)
        return out
    mins = [float(r["elapsed_s"]) / 60 for r in rows]
    rss = col("ctrl_rss_mb"); tick = col("tick_max_ms")
    fig, ax1 = plt.subplots(figsize=(6.6, 3.2))
    ax1.plot(mins, rss, color=BLUE, lw=2, marker="o", ms=4, zorder=3,
             label="controller RSS (MB)")
    ax1.set_xlabel("elapsed (minutes)")
    ax1.set_ylabel("controller RSS (MB)", color=BLUE)
    ax1.tick_params(axis="y", labelcolor=BLUE)
    lo = min(v for v in rss if v is not None); hi = max(v for v in rss if v is not None)
    ax1.set_ylim(lo - 20, hi + 20)
    ax1.set_title("Controller stability over sustained benign load",
                  color=INK, fontsize=11, fontweight="bold", loc="left", pad=10)
    save(fig, "fig-d-soak-stability")


if __name__ == "__main__":
    print("Generating figures from real evidence ->", OUT)
    fig_a_latency()
    fig_b_zero_fp()
    soak = sorted(OUT.parent.parent.glob("artifacts/evidence/soak-*/samples.tsv"))
    arg_tsv = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    tsv = arg_tsv or (soak[-1] if soak else None)
    if tsv and tsv.exists():
        print(f"  soak samples: {tsv}")
        fig_d_soak(tsv)
    else:
        print("  (fig D skipped — no soak samples.tsv yet)")
    print("done.")
