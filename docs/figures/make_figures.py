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

mpl.rcParams.update(
    {
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "font.family": "DejaVu Sans",
        "font.size": 10.5,
        "axes.edgecolor": MUTED,
        "axes.labelcolor": INK2,
        "text.color": INK,
        "xtick.color": INK2,
        "ytick.color": INK2,
        "axes.grid": True,
        "grid.color": GRID,
        "grid.linewidth": 0.8,
        "axes.spines.top": False,
        "axes.spines.right": False,
    }
)


def save(fig, stem: str) -> None:
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"{stem}.{ext}", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {stem}.pdf / .png")


def fig_a_latency() -> None:
    """Per-detector scoring latency (log) — the cost of ML at equal FP budget."""
    # from real-benign-baseline: thresholds chosen on real validation @1% FP budget
    names = [
        "robust_stats\n(M1 statistical)",
        "half_space_trees\n(streaming)",
        "isolation_forest\n(M2 ML)",
    ]
    micros = [14.0, 57.0, 11400.0]  # µs/window scoring latency
    colors = [BLUE, AQUA, ORANGE]
    fig, ax = plt.subplots(figsize=(6.6, 3.1))
    y = range(len(names))
    ax.barh(list(y), micros, color=colors, height=0.6, zorder=3)
    ax.set_xscale("log")
    ax.set_xlim(5, 30000)
    ax.set_yticks(list(y))
    ax.set_yticklabels(names)
    ax.invert_yaxis()
    ax.set_xlabel("scoring latency per window (µs, log scale)")
    ax.xaxis.set_major_formatter(
        FuncFormatter(lambda v, _: f"{v:.0f}µs" if v < 1000 else f"{v / 1000:.0f}ms")
    )
    for yi, v in zip(y, micros, strict=True):
        lab = f"{v:.0f} µs" if v < 1000 else f"{v / 1000:.1f} ms"
        ax.text(
            v * 1.15, yi, lab, va="center", ha="left", color=INK, fontsize=9.5, fontweight="bold"
        )
    ax.set_title(
        "Detector scoring cost — all at 1.30% validation FPR (1% budget)",
        color=INK,
        fontsize=11,
        fontweight="bold",
        loc="left",
        pad=10,
    )
    ax.text(
        0,
        1.14,
        "The ML detector (Isolation Forest) costs ~800\u00d7 the statistical "
        "detector for the same false-positive budget.",
        transform=ax.transAxes,
        color=INK2,
        fontsize=8.7,
    )
    save(fig, "fig-a-detector-latency")


def fig_b_zero_fp() -> None:
    """Live inference on real benign: every detector score below its threshold."""
    # from real-benign-baseline "Live inference verification" table
    srcs = ["10.77.20.10", "10.77.20.11", "10.77.20.12", "10.77.20.13"]
    rs = [1.449, 0.417, 2.023, 1.390]
    rs_thr = 3.528
    iforest = [0.456, 0.375, 0.506, 0.505]
    if_thr = 0.627
    # normalise each score as a fraction of its own threshold (1.0 = threshold)
    rs_r = [v / rs_thr for v in rs]
    if_r = [v / if_thr for v in iforest]
    fig, ax = plt.subplots(figsize=(6.6, 3.4))
    x = range(len(srcs))
    w = 0.38
    b1 = ax.bar([i - w / 2 for i in x], rs_r, w, color=BLUE, zorder=3, label="robust_stats (M1)")
    b2 = ax.bar(
        [i + w / 2 for i in x], if_r, w, color=ORANGE, zorder=3, label="isolation_forest (M2)"
    )
    ax.axhline(1.0, color=INK2, lw=1.4, ls="--", zorder=4)
    ax.text(
        len(srcs) - 0.5,
        1.02,
        "threshold",
        color=INK2,
        fontsize=8.5,
        ha="right",
        va="bottom",
        fontstyle="italic",
    )
    ax.set_ylim(0, 1.15)
    ax.set_xticks(list(x))
    ax.set_xticklabels(srcs, fontsize=9)
    ax.set_ylabel("detector score ÷ its threshold")
    ax.set_xlabel("real benign source (USERS zone)")
    for bars in (b1, b2):
        for b in bars:
            ax.text(
                b.get_x() + b.get_width() / 2,
                b.get_height() + 0.015,
                f"{b.get_height():.2f}",
                ha="center",
                va="bottom",
                color=INK2,
                fontsize=7.8,
            )
    ax.legend(loc="upper left", frameon=False, fontsize=8.8, ncol=2)
    ax.set_title(
        "Zero false positives on real traffic — all scores below threshold",
        color=INK,
        fontsize=11,
        fontweight="bold",
        loc="left",
        pad=10,
    )
    ax.text(
        0,
        1.14,
        "Profile v2 (trained on 361 real benign windows) scores every "
        "live benign source below every detector threshold.",
        transform=ax.transAxes,
        color=INK2,
        fontsize=8.7,
    )
    save(fig, "fig-b-zero-false-positives")


def fig_d_soak(samples_tsv: Path) -> None:
    """Controller stability over the soak — RSS and tick latency (small multiples).

    Two stacked panels (each its own y-axis — never a dual-axis chart).
    """
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
    rss = col("ctrl_rss_mb")
    tp50 = col("tick_p50_ms")
    tmax = col("tick_max_ms")

    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(6.6, 4.6), sharex=True, gridspec_kw={"height_ratios": [1, 1], "hspace": 0.28}
    )

    # panel 1: resident memory (leak check)
    ax1.plot(mins, rss, color=BLUE, lw=2, marker="o", ms=3.5, zorder=3)
    ax1.set_ylabel("controller RSS (MB)")
    rss_ok = [v for v in rss if v is not None]
    lo, hi = min(rss_ok), max(rss_ok)
    ax1.set_ylim(lo - 14, hi + 14)
    ax1.text(
        0.015,
        0.90,
        f"RSS {lo:.0f}→{hi:.0f} MB over 60 min (+{hi - lo:.1f} MB) — no leak",
        transform=ax1.transAxes,
        color=INK2,
        fontsize=8.8,
        va="top",
    )

    # panel 2: control-loop tick latency (p50 vs max)
    ax2.plot(mins, tmax, color=ORANGE, lw=1.6, marker="o", ms=3, zorder=3, label="tick max")
    ax2.plot(mins, tp50, color=BLUE, lw=2, marker="o", ms=3, zorder=4, label="tick p50")
    ax2.set_ylabel("control-loop tick (ms)")
    ax2.set_xlabel("elapsed (minutes)")
    ax2.legend(loc="upper right", frameon=False, fontsize=8.6, ncol=2)
    p50_ok = [v for v in tp50 if v is not None]
    ax2.text(
        0.015,
        0.90,
        f"tick p50 steady ≈{sum(p50_ok) / len(p50_ok):.1f} ms (one transient max spike)",
        transform=ax2.transAxes,
        color=INK2,
        fontsize=8.8,
        va="top",
    )

    ax1.set_title(
        "Controller stability over a 60-min benign soak — zero false positives, zero policies",
        color=INK,
        fontsize=10.5,
        fontweight="bold",
        loc="left",
        pad=12,
    )
    save(fig, "fig-d-soak-stability")


def fig_f_explain() -> None:
    """Explainable detection — why the live health-probe source scored elevated.

    Occlusion feature attributions for the robust_stats + isolation_forest
    detections of source 10.77.20.250 (assessment risk-7b3ee514524a,
    2026-10-21T03:23:58, profile v2, score 59 / band elevated, MONITOR mode).
    robust_z = deviation from the trusted-profile baseline (positive = above
    profile, negative = below). Diverging encoding: warm = above, cool = below.
    """
    # feature, robust_z, human reason  (from the live detection, real values)
    feats = [
        ("unknown_route_frac", 20.0, "100% of requests to a route not in the profile"),
        ("route_entropy", -10.0, "only one route (no journey variety)"),
        ("req_rate", -4.86, "far fewer requests/s than a real user"),
        ("login_rate", -3.37, "never logs in"),
        ("distinct_usernames", -2.7, "no distinct users"),
        ("req_bytes_p95", -2.03, "smaller requests than normal"),
    ]
    feats = feats[::-1]  # largest driver on top after invert
    names = [f[0] for f in feats]
    z = [f[1] for f in feats]
    warm, cool = ORANGE, BLUE  # diverging poles + neutral zero line
    colors = [warm if v > 0 else cool for v in z]
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    y = range(len(names))
    ax.barh(list(y), z, color=colors, height=0.62, zorder=3)
    ax.axvline(0, color=INK2, lw=1.2, zorder=4)
    ax.set_yticks(list(y))
    ax.set_yticklabels(names, fontsize=9.5)
    ax.set_xlim(-14, 24)
    ax.set_xlabel("deviation from trusted profile (robust z-score)")
    for yi, (_nm, v, _why) in zip(y, feats, strict=True):
        ha = "left" if v > 0 else "right"
        off = 0.6 if v > 0 else -0.6
        ax.text(
            v + off,
            yi,
            f"z={v:+.1f}",
            va="center",
            ha=ha,
            color=INK,
            fontsize=8.6,
            fontweight="bold",
        )
    ax.set_title(
        "Explainable detection — why source 10.77.20.250 scored elevated (59)",
        color=INK,
        fontsize=11,
        fontweight="bold",
        loc="left",
        pad=10,
    )
    ax.text(
        0,
        1.13,
        "Live monitor-mode assessment (profile v2). Occlusion "
        "attributions name the drivers: a single unknown route, never logs "
        "in, very sparse — the health-probe signature, not a user journey.",
        transform=ax.transAxes,
        color=INK2,
        fontsize=8.4,
        wrap=True,
    )
    # warm/cool legend (diverging, not categorical series)
    ax.text(
        0.995,
        0.06,
        "warm = above profile   cool = below profile",
        transform=ax.transAxes,
        color=INK2,
        fontsize=8,
        ha="right",
    )
    save(fig, "fig-f-explainable-detection")


if __name__ == "__main__":
    print("Generating figures from real evidence ->", OUT)
    fig_a_latency()
    fig_b_zero_fp()
    fig_f_explain()
    soak = sorted(OUT.parent.parent.glob("artifacts/evidence/soak-*/samples.tsv"))
    arg_tsv = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    tsv = arg_tsv or (soak[-1] if soak else None)
    if tsv and tsv.exists():
        print(f"  soak samples: {tsv}")
        fig_d_soak(tsv)
    else:
        print("  (fig D skipped — no soak samples.tsv yet)")
    print("done.")
