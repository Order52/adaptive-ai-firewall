"""Promotion gate for the online HST challenger (M3, ADR-030).

The challenger is compared with the frozen champion HST on recorded holdout
runs that neither model trained on. Every check is reported with its value and
limit; the gate passes only if all checks pass. In particular:

* no labelled attack runs, or only synthetic ones, FAILS the gate (a challenger
  must never be promoted without evidence it still detects attacks);
* a challenger whose learned windows overlap the holdout, or came from a source
  that is tainted now (late evidence), FAILS the gate (leakage / poisoning);
* holdout windows are non-overlapping (tumbling per source), so sample sizes
  are not inflated by the 5 s hop of the 30 s sliding windows.
"""

from __future__ import annotations

from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address
from typing import Any

import numpy as np

from afw.config import PromotionConfig
from afw.domain.adaptation import GateCheck
from afw.domain.features import FeatureVector
from afw.domain.learning import LearnedWindow
from afw.domain.profiles import BehaviorProfile
from afw.ml.evaluation import benign_quantiles, threshold_for_fpr
from afw.ml.inference import LoadedModel
from afw.ml.online import OnlineChallenger
from afw.profiling.eligibility import SENSITIVE

_FRACTIONS = {"auth_fail_frac", "client_err_frac"}


@dataclass(frozen=True)
class Holdout:
    benign: Sequence[FeatureVector]
    attack: Sequence[FeatureVector]
    benign_dataset_ids: tuple[str, ...]
    attack_dataset_ids: tuple[str, ...]
    synthetic_attack: bool
    spans: tuple[tuple[IPv4Address, datetime, datetime], ...]  # labelled source activity


@dataclass(frozen=True)
class GateResult:
    checks: tuple[GateCheck, ...]
    threshold: float
    benign_quantiles: tuple[float, ...]
    metrics: dict[str, float | int | None]


def tumbling(windows: Sequence[FeatureVector]) -> list[FeatureVector]:
    """Non-overlapping subsample per source, in time order."""
    last: dict[IPv4Address, datetime] = {}
    out: list[FeatureVector] = []
    for w in sorted(windows, key=lambda w: (w.window_end, int(w.source_ip))):
        end = last.get(w.source_ip)
        if end is None or w.window_start >= end:
            out.append(w)
            last[w.source_ip] = w.window_end
    return out


def sensitive_probes(
    windows: Sequence[FeatureVector], profile: BehaviorProfile
) -> list[FeatureVector]:
    """Counterfactual attack-like probes: one benign window with one security-sensitive
    feature pushed well beyond the trusted q99. Learning must never make these normal."""
    out = []
    for w in windows:
        for name in SENSITIVE:
            q99 = profile.features[name].q99
            v = min(1.0, max(2 * q99, 0.5)) if name in _FRACTIONS else max(2 * q99, q99 + 1.0)
            out.append(w.model_copy(update={"values": {**w.values, name: v}}))
    return out


def _conditional(
    det: object, base: Sequence[FeatureVector], probes: Sequence[FeatureVector], thr: float, k: int
) -> tuple[float, int]:
    """(flag rate, n) over probes whose base window ``det`` scores normal; probes are
    ``k`` per base window, in order."""
    if not base:
        return 0.0, 0
    normal = np.asarray(det.score(_rows(base))) < thr  # type: ignore[attr-defined]
    keep = [p for i, p in enumerate(probes) if normal[i // k]]
    return (_rate(det, keep, thr), len(keep)) if keep else (0.0, 0)


def matched_sensitivity(
    champ_det: object,
    champ_thr: float,
    ch_det: object,
    ch_thr: float,
    bases: Sequence[FeatureVector],
    profile: BehaviorProfile,
) -> dict[str, Any]:
    """Per sensitive feature, the probe flag rate of each model over the base windows
    that BOTH models score normal (same windows, so margin/population cannot confound)."""
    k = len(SENSITIVE)
    probes = sensitive_probes(bases, profile)
    if not bases:
        return {"matched_bases": 0, "per_feature": {}, "probes": probes}
    x = _rows(bases)
    both = (np.asarray(champ_det.score(x)) < champ_thr) & (  # type: ignore[attr-defined]
        np.asarray(ch_det.score(x)) < ch_thr  # type: ignore[attr-defined]
    )
    per: dict[str, dict[str, float]] = {}
    for j, name in enumerate(SENSITIVE):
        sel = [probes[i * k + j] for i in np.flatnonzero(both)]
        per[name] = {
            "champion": _rate(champ_det, sel, champ_thr),
            "challenger": _rate(ch_det, sel, ch_thr),
        }
    return {"matched_bases": int(both.sum()), "per_feature": per, "probes": probes}


def _rows(windows: Sequence[FeatureVector]) -> np.ndarray:
    return np.array([w.as_row() for w in windows], dtype=float)


def _rate(det: object, windows: Sequence[FeatureVector], thr: float) -> float:
    if not windows:
        return 0.0
    scores = np.asarray(det.score(_rows(windows)))  # type: ignore[attr-defined]
    return float(np.mean(scores >= thr))


def evaluate_challenger(
    *,
    champion: LoadedModel,
    challenger: OnlineChallenger,
    profile: BehaviorProfile,
    holdout: Holdout,
    lineage: Sequence[LearnedWindow],
    tainted: AbstractSet[IPv4Address],
    pc: PromotionConfig,
) -> GateResult:
    checks: list[GateCheck] = []
    window_size = int(challenger.detector.window_size)
    checks.append(
        GateCheck(
            name="min_learning",
            passed=challenger.n_learned >= window_size,
            value=challenger.n_learned,
            limit=window_size,
            detail="HST predictions change only after a full reference window (pivot)",
        )
    )
    leaked = [
        w
        for w in lineage
        for ip, start, end in holdout.spans
        if w.source_ip == ip and w.window_end >= start and w.window_start <= end
    ]
    checks.append(
        GateCheck(
            name="holdout_not_learned",
            passed=not leaked,
            value=len(leaked),
            limit=0,
            detail="learned windows overlapping a labelled holdout source's activity",
        )
    )
    late = sorted({str(w.source_ip) for w in lineage if w.source_ip in tainted})
    checks.append(
        GateCheck(
            name="ledger_clean",
            passed=not late,
            value=len(late),
            limit=0,
            detail="learned sources tainted after admission: "
            + (", ".join(late[:5]) if late else "none"),
        )
    )

    benign = tumbling(holdout.benign)
    half = len(benign) // 2
    cal, test = benign[:half], benign[half:]
    sized = min(len(cal), len(test)) >= pc.min_holdout_windows
    checks.append(
        GateCheck(
            name="holdout_size",
            passed=sized,
            value=min(len(cal), len(test)),
            limit=pc.min_holdout_windows,
            detail=f"non-overlapping benign holdout windows per half ({len(benign)} total)",
        )
    )
    metrics: dict[str, float | int | None] = {
        "n_learned": challenger.n_learned,
        "holdout_calibration": len(cal),
        "holdout_test": len(test),
    }
    if not sized:
        return GateResult(tuple(checks), champion.record.threshold, (), metrics)

    ch_det, champ_det = challenger.detector, champion.detector
    cal_scores = np.asarray(ch_det.score(_rows(cal)))
    thr = threshold_for_fpr(cal_scores, pc.target_fpr)
    champ_thr = champion.record.threshold
    ch_fpr = _rate(ch_det, test, thr)
    champ_fpr = _rate(champ_det, test, champ_thr)
    fpr_limit = max(champ_fpr, 2 * pc.target_fpr)
    checks.append(
        GateCheck(
            name="benign_fpr_not_worse",
            passed=ch_fpr <= fpr_limit,
            value=round(ch_fpr, 4),
            limit=round(fpr_limit, 4),
            detail=f"champion FPR on the same holdout = {champ_fpr:.4f}",
        )
    )
    metrics |= {
        "threshold": round(thr, 6),
        "champion_threshold": round(champ_thr, 6),
        "challenger_fpr": round(ch_fpr, 4),
        "champion_fpr": round(champ_fpr, 4),
    }

    if not holdout.attack:
        checks.append(
            GateCheck(
                name="attack_recall_regression",
                passed=False,
                detail="no labelled attack runs supplied (team-supplied scenarios required)",
            )
        )
    elif holdout.synthetic_attack:
        checks.append(
            GateCheck(
                name="attack_recall_regression",
                passed=False,
                detail="synthetic attack data cannot support promotion",
            )
        )
    else:
        attack = tumbling(holdout.attack)
        ch_rec = _rate(ch_det, attack, thr)
        champ_rec = _rate(champ_det, attack, champ_thr)
        checks.append(
            GateCheck(
                name="attack_recall_regression",
                passed=ch_rec >= champ_rec - pc.recall_tolerance,
                value=round(ch_rec, 4),
                limit=round(champ_rec - pc.recall_tolerance, 4),
                detail=f"champion recall {champ_rec:.4f} on {len(attack)} attack windows",
            )
        )
        metrics |= {
            "attack_windows": len(attack),
            "challenger_recall": round(ch_rec, 4),
            "champion_recall": round(champ_rec, 4),
        }

    # Sensitivity on MATCHED bases (P2, 2026-10-28). Each model's own-normal bases are
    # different populations with different distances to the threshold, so comparing
    # own-normal flag rates confounds sensitivity with margin (a model whose normal
    # windows sit deep inside dense regions flags fewer one-feature probes). The check
    # therefore uses only base windows BOTH models score normal, and requires, for
    # every sensitive feature separately, challenger rate >= champion rate - tolerance.
    # Too few matched bases is a failure (no evidence of invariance), never a pass.
    sens = matched_sensitivity(champ_det, champ_thr, ch_det, thr, test, profile)
    worst = min((f["challenger"] - f["champion"], name) for name, f in sens["per_feature"].items())
    enough = sens["matched_bases"] >= pc.min_holdout_windows
    checks.append(
        GateCheck(
            name="sensitive_invariance",
            passed=enough and worst[0] >= -pc.sensitive_tolerance,
            value=round(worst[0], 4),
            limit=-pc.sensitive_tolerance,
            detail=f"worst per-feature (challenger - champion) probe flag rate on "
            f"{sens['matched_bases']} matched normal bases: {worst[1]}"
            + ("" if enough else f"; fewer than {pc.min_holdout_windows} matched bases"),
        )
    )
    ch_cond, _ = _conditional(ch_det, test, sens["probes"], thr, len(SENSITIVE))
    champ_cond, _ = _conditional(champ_det, test, sens["probes"], champ_thr, len(SENSITIVE))
    metrics |= {
        "sensitive_matched_bases": sens["matched_bases"],
        **{
            f"sensitive_{n}_{who}": round(f[who], 4)
            for n, f in sens["per_feature"].items()
            for who in ("challenger", "champion")
        },
        # reported for transparency; not decisive (population/margin confounded)
        "sensitive_own_normal_challenger": round(ch_cond, 4),
        "sensitive_own_normal_champion": round(champ_cond, 4),
        "sensitive_raw_challenger": round(_rate(ch_det, sens["probes"], thr), 4),
        "sensitive_raw_champion": round(_rate(champ_det, sens["probes"], champ_thr), 4),
    }
    test_scores = np.asarray(ch_det.score(_rows(test)))
    return GateResult(tuple(checks), thr, benign_quantiles(test_scores), metrics)
