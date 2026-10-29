"""Incremental supervised known-threat classifier with verified delayed labels (item 3).

The batch baseline is ``supervised.KnownThreatClassifier`` (RandomForest, refit on all
labelled windows). This module learns one window at a time with a river model
(Adaptive Random Forest or Hoeffding Adaptive Tree) and is evaluated prequentially:
every window is predicted *before* any label for it can be learnt.

Labels:

* A label is a ``VerifiedLabel``: a family for one window identified by
  ``(app, source, window_end)``, with a provenance naming who verified it (a dataset
  manifest, i.e. the team's record of what they ran, or an operator decision). It
  becomes known only at ``available_at``, which is after the window (delayed labels).
* A label whose provenance is the model itself, an anomaly verdict or anything not
  in ``TRUSTED_PROVENANCE`` is refused: an anomaly is never treated as confirmed
  malicious, and the model's own prediction is never ground truth.

Defences:

* **Poisoning.** Labels only for windows the classifier has actually seen (no
  fabricated windows), one label per window (a conflicting second label quarantines
  the window), a per-source cap on learnt labels per hour, and a cap on the share of
  any one provenance among recent learning. Refusals are counted, never silent.
* **Catastrophic forgetting.** A bounded per-family rehearsal reservoir: each learnt
  label is followed by replays of other families, so a long run of one family cannot
  erase the others; and a checkpoint is only offered as a challenger if it does not
  lose recall on a fixed anchor set (``Checkpoint.anchor``).

Lifecycle (``ClassifierLifecycle``): shadow -> challenger -> (gate on an independent,
dataset-disjoint evaluation + human approval) -> probation -> champion, with automatic
rollback when probation shows more false alerts than allowed. Nothing here enforces:
the classifier's verdicts stay in shadow until a human qualifies it.
"""

from __future__ import annotations

import hashlib
import pickle
import random
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from river import forest, tree

from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.ml.supervised import BENIGN, UNKNOWN, KnownThreatVerdict, LabelledWindow, wilson

TRUSTED_PROVENANCE = ("manifest:", "operator:")


def window_id(fv: FeatureVector) -> str:
    """Stable identity of one window: the same request window always has the same id."""
    return f"{fv.app_id}|{fv.source_ip}|{fv.window_end.isoformat()}"


@dataclass(frozen=True)
class VerifiedLabel:
    window: str  # window_id
    family: str
    provenance: str  # "manifest:<dataset>" or "operator:<who>"
    available_at: datetime


def _x(fv: FeatureVector) -> dict[str, float]:
    return {n: float(fv.values.get(n, 0.0)) for n in FEATURE_NAMES}


def make_model(kind: str, seed: int) -> Any:
    if kind == "arf":
        return forest.ARFClassifier(n_models=10, seed=seed)
    if kind == "hat":
        return tree.HoeffdingAdaptiveTreeClassifier(seed=seed)
    raise ValueError(f"unknown incremental model {kind}")


class IncrementalThreatClassifier:
    def __init__(
        self,
        kind: str = "arf",
        min_confidence: float = 0.8,
        min_per_family: int = 20,
        seed: int = 0,
    ) -> None:
        self.kind = kind
        self.min_confidence = min_confidence
        self.min_per_family = min_per_family
        self.seed = seed
        self.model = make_model(kind, seed)
        self.learnt: Counter[str] = Counter()

    def predict(self, fv: FeatureVector) -> KnownThreatVerdict:
        """Abstains (``unknown``) below the confidence floor, and for a family it has
        seen fewer than ``min_per_family`` labels of: it does not claim what it has
        barely learnt."""
        if BENIGN not in self.learnt or len(self.learnt) < 2:
            return KnownThreatVerdict(UNKNOWN, 0.0)
        proba = self.model.predict_proba_one(_x(fv)) or {}
        if not proba:
            return KnownThreatVerdict(UNKNOWN, 0.0)
        fam, conf = max(proba.items(), key=lambda kv: kv[1])
        if conf < self.min_confidence or self.learnt[str(fam)] < self.min_per_family:
            return KnownThreatVerdict(UNKNOWN, round(float(conf), 4))
        return KnownThreatVerdict(str(fam), round(float(conf), 4))

    def learn(self, fv: FeatureVector, family: str) -> None:
        self.model.learn_one(_x(fv), family)
        self.learnt[family] += 1


@dataclass
class LabelGuard:
    """Which verified labels may be learnt (poisoning defences)."""

    per_source_per_hour: int = 120
    max_provenance_share: float = 0.8  # of the last ``share_window`` learnt labels
    share_window: int = 500
    min_for_share: int = 100
    refused: Counter[str] = field(default_factory=Counter)
    _labelled: dict[str, str] = field(default_factory=dict)
    _quarantined: set[str] = field(default_factory=set)
    _per_source: dict[str, deque[datetime]] = field(default_factory=lambda: defaultdict(deque))
    _recent: deque[str] = field(default_factory=deque)

    def admit(self, label: VerifiedLabel, fv: FeatureVector | None) -> bool:
        why = self._why(label, fv)
        if why:
            self.refused[why] += 1
            return False
        assert fv is not None
        self._labelled[label.window] = label.family
        src = str(fv.source_ip)
        self._per_source[src].append(label.available_at)
        self._recent.append(label.provenance)
        while len(self._recent) > self.share_window:
            self._recent.popleft()
        return True

    def _why(self, label: VerifiedLabel, fv: FeatureVector | None) -> str | None:
        if not label.provenance.startswith(TRUSTED_PROVENANCE):
            return "untrusted_provenance"
        if fv is None:
            return "unknown_window"  # a label for a window that was never seen
        if label.available_at < fv.window_end:
            return "label_before_window"
        if label.window in self._quarantined:
            return "quarantined"
        prior = self._labelled.get(label.window)
        if prior is not None:
            if prior != label.family:
                self._quarantined.add(label.window)
                return "conflicting_label"
            return "duplicate"
        q = self._per_source[str(fv.source_ip)]
        while q and label.available_at - q[0] > timedelta(hours=1):
            q.popleft()
        if len(q) >= self.per_source_per_hour:
            return "source_rate_cap"
        if label.provenance.startswith("operator:") and len(self._recent) >= self.min_for_share:
            share = self._recent.count(label.provenance) / len(self._recent)
            if share >= self.max_provenance_share:
                return "provenance_share_cap"  # one operator cannot dominate learning
        return None

    def quarantined(self, window: str) -> bool:
        return window in self._quarantined


class Rehearsal:
    """Bounded per-family reservoir; after each new label, one replay of every other
    family keeps earlier families present in the stream (anti-forgetting)."""

    def __init__(self, per_family: int = 200, seed: int = 0) -> None:
        self.per_family = per_family
        self.rng = random.Random(seed)
        self.buf: dict[str, list[FeatureVector]] = defaultdict(list)
        self.seen: Counter[str] = Counter()

    def add(self, fv: FeatureVector, family: str) -> None:
        self.seen[family] += 1
        b = self.buf[family]
        if len(b) < self.per_family:
            b.append(fv)
        else:
            j = self.rng.randrange(self.seen[family])
            if j < self.per_family:
                b[j] = fv

    def replays(self, family: str) -> list[tuple[FeatureVector, str]]:
        return [(self.rng.choice(b), f) for f, b in sorted(self.buf.items()) if f != family and b]


@dataclass(frozen=True)
class Checkpoint:
    index: int
    at: datetime
    sha256: str
    learnt: dict[str, int]
    provenance: dict[str, int]  # learnt labels by provenance
    anchor: dict[str, float]  # recall per family (and benign specificity) on the anchor set
    blob: bytes = field(repr=False, compare=False)

    def load(self) -> IncrementalThreatClassifier:
        clf: IncrementalThreatClassifier = pickle.loads(self.blob)  # noqa: S301 (own checkpoint, sha checked)
        if hashlib.sha256(self.blob).hexdigest() != self.sha256:
            raise ValueError("checkpoint does not match its sha256")
        return clf


def predict_one(clf: Any, fv: FeatureVector) -> KnownThreatVerdict:
    """One verdict from either the incremental or the batch (RandomForest) classifier."""
    if isinstance(clf, IncrementalThreatClassifier):
        return clf.predict(fv)
    verdict: KnownThreatVerdict = clf.predict([fv])[0]
    return verdict


def per_family_recall(clf: Any, windows: Sequence[LabelledWindow]) -> dict[str, float]:
    """Recall per attack family and specificity (benign kept benign/unknown)."""
    hit: Counter[str] = Counter()
    n: Counter[str] = Counter()
    for w in windows:
        fam = predict_one(clf, w.fv).family
        n[w.family] += 1
        if w.family == BENIGN:
            hit[w.family] += fam in (BENIGN, UNKNOWN)
        else:
            hit[w.family] += fam == w.family
    return {f: round(hit[f] / n[f], 4) for f in sorted(n)}


@dataclass
class StreamItem:
    fv: FeatureVector
    family: str  # the manifest's label; delivered to the learner only via a VerifiedLabel
    dataset_id: str


@dataclass
class PrequentialReport:
    kind: str
    label_delay_s: float
    windows: int = 0
    predicted: Counter[tuple[str, str]] = field(default_factory=Counter)  # (true, predicted)
    by_dataset: Counter[tuple[str, str, str]] = field(default_factory=Counter)
    learnt: int = 0
    replays: int = 0
    refused: dict[str, int] = field(default_factory=dict)
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    synthetic: bool = False

    def as_dict(self) -> dict[str, Any]:
        fams = sorted({t for t, _ in self.predicted})
        per: dict[str, Any] = {}
        for f in fams:
            row = {p: c for (t, p), c in self.predicted.items() if t == f}
            n = sum(row.values())
            if f == BENIGN:
                fp = sum(c for p, c in row.items() if p not in (BENIGN, UNKNOWN))
                lo, hi = wilson(fp, n)
                per[f] = {"windows": n, "fpr": round(fp / n, 4), "fpr_ci95": [lo, hi]}
            else:
                lo, hi = wilson(row.get(f, 0), n)
                per[f] = {
                    "windows": n,
                    "recall": round(row.get(f, 0) / n, 4),
                    "recall_ci95": [round(lo, 4), round(hi, 4)],
                    "unknown": round(row.get(UNKNOWN, 0) / n, 4),
                    "missed_as_benign": round(row.get(BENIGN, 0) / n, 4),
                }
        return {
            "SYNTHETIC": self.synthetic,
            "kind": self.kind,
            "label_delay_s": self.label_delay_s,
            "windows": self.windows,
            "learnt": self.learnt,
            "replays": self.replays,
            "refused": self.refused,
            "per_family": per,
            "checkpoints": self.checkpoints,
            "recall_by_dataset": self.recall_by_dataset(),
        }

    def recall_by_dataset(self) -> dict[str, dict[str, float]]:
        """Per dataset (or stream segment): recall per family, benign as specificity."""
        n: Counter[tuple[str, str]] = Counter()
        hit: Counter[tuple[str, str]] = Counter()
        for (ds, t, p), c in self.by_dataset.items():
            n[(ds, t)] += c
            ok = p in (BENIGN, UNKNOWN) if t == BENIGN else p == t
            hit[(ds, t)] += c * ok
        out: dict[str, dict[str, float]] = {}
        for (ds, t), k in sorted(n.items()):
            out.setdefault(ds, {})[t] = round(hit[(ds, t)] / k, 4)
        return out


def prequential(
    stream: Iterable[StreamItem],
    *,
    kind: str = "arf",
    label_delay_s: float = 300.0,
    seed: int = 0,
    guard: LabelGuard | None = None,
    rehearsal: Rehearsal | None = None,
    anchor: Sequence[LabelledWindow] = (),
    checkpoint_every: int = 500,
    extra_labels: Iterable[VerifiedLabel] = (),
    synthetic: bool = False,
) -> tuple[PrequentialReport, list[Checkpoint]]:
    """Predict-before-learn over a time-ordered stream. Each window's manifest label is
    released as a ``VerifiedLabel`` ``label_delay_s`` after the window ends; labels are
    learnt only once available and admitted by the guard. ``extra_labels`` lets a test
    inject untrusted or adversarial labels through the same path."""
    clf = IncrementalThreatClassifier(kind, seed=seed)
    guard = guard or LabelGuard()
    rehearsal = rehearsal if rehearsal is not None else Rehearsal(seed=seed)
    rep = PrequentialReport(kind=kind, label_delay_s=label_delay_s, synthetic=synthetic)
    seen: dict[str, FeatureVector] = {}
    pending: list[VerifiedLabel] = sorted(extra_labels, key=lambda lab: lab.available_at)
    provenance: Counter[str] = Counter()
    checkpoints: list[Checkpoint] = []
    delay = timedelta(seconds=label_delay_s)

    def deliver(now: datetime) -> None:
        nonlocal pending
        due = [lab for lab in pending if lab.available_at <= now]
        pending = [lab for lab in pending if lab.available_at > now]
        for lab in due:
            fv = seen.get(lab.window)
            if not guard.admit(lab, fv):
                continue
            assert fv is not None
            clf.learn(fv, lab.family)
            rep.learnt += 1
            provenance[lab.provenance.split(":", 1)[0]] += 1
            for rfv, rfam in rehearsal.replays(lab.family):
                clf.learn(rfv, rfam)
                rep.replays += 1
            rehearsal.add(fv, lab.family)
            if rep.learnt % checkpoint_every == 0:
                blob = pickle.dumps(clf)
                cp = Checkpoint(
                    index=len(checkpoints),
                    at=now,
                    sha256=hashlib.sha256(blob).hexdigest(),
                    learnt=dict(clf.learnt),
                    provenance=dict(provenance),
                    anchor=per_family_recall(clf, anchor) if anchor else {},
                    blob=blob,
                )
                checkpoints.append(cp)
                rep.checkpoints.append(
                    {
                        "index": cp.index,
                        "at": cp.at.isoformat(),
                        "sha256": cp.sha256,
                        "learnt": cp.learnt,
                        "anchor": cp.anchor,
                    }
                )

    for item in sorted(stream, key=lambda s: s.fv.window_end):
        now = item.fv.window_end
        deliver(now)
        wid = window_id(item.fv)
        v = clf.predict(item.fv)  # before any label for this window exists
        rep.predicted[(item.family, v.family)] += 1
        rep.by_dataset[(item.dataset_id, item.family, v.family)] += 1
        rep.windows += 1
        seen[wid] = item.fv
        pending.append(VerifiedLabel(wid, item.family, f"manifest:{item.dataset_id}", now + delay))
        pending.sort(key=lambda lab: lab.available_at)
    if pending:
        deliver(max(lab.available_at for lab in pending))
    rep.refused = dict(guard.refused)
    return rep, checkpoints


# ------------------------------------------------------------------ lifecycle
class Stage(StrEnum):
    SHADOW = "shadow"
    CHALLENGER = "challenger"
    PROBATION = "probation"
    CHAMPION = "champion"
    RETIRED = "retired"
    ROLLED_BACK = "rolled_back"


@dataclass
class GateResult:
    passed: bool
    reasons: list[str]
    challenger: dict[str, float]
    champion: dict[str, float]


@dataclass
class ClassifierLifecycle:
    """Champion/challenger for the known-threat classifier. Every transition is
    recorded; promotion needs the gate *and* a named human; probation rolls back on
    its own. ``enforcing`` stays False: the live controller does not act on this
    classifier until a human qualifies it outside this object."""

    max_benign_fpr: float = 0.02
    max_benign_fpr_ci_high: float = 0.05
    max_recall_drop: float = 0.05
    probation_min_windows: int = 500
    champion: Any = None
    champion_id: str | None = None
    previous: tuple[Any, str | None] | None = None
    challenger: Any = None
    challenger_id: str | None = None
    challenger_trained_on: frozenset[str] = frozenset()
    stage: Stage = Stage.SHADOW
    history: list[dict[str, Any]] = field(default_factory=list)
    _probation: Counter[str] = field(default_factory=Counter)
    enforcing: bool = False

    def _log(self, event: str, **kw: Any) -> None:
        self.history.append({"event": event, "stage": self.stage.value} | kw)

    def propose(self, model: Any, model_id: str, trained_on: Iterable[str]) -> None:
        self.challenger, self.challenger_id = model, model_id
        self.challenger_trained_on = frozenset(trained_on)
        self.stage = Stage.CHALLENGER
        self._log("proposed", model=model_id, trained_on=sorted(self.challenger_trained_on))

    def gate(self, evaluation: Sequence[LabelledWindow]) -> GateResult:
        """Independent evaluation: datasets the challenger never learnt from."""
        if self.challenger is None:
            raise RuntimeError("no challenger")
        used = {w.dataset_id for w in evaluation} & self.challenger_trained_on
        if used:
            raise ValueError(f"evaluation shares datasets with the challenger: {sorted(used)}")
        reasons: list[str] = []
        ch = per_family_recall(self.challenger, evaluation)
        cp = per_family_recall(self.champion, evaluation) if self.champion is not None else {}
        n_benign = sum(1 for w in evaluation if w.family == BENIGN)
        if n_benign == 0:
            reasons.append("no benign windows in the evaluation")
        else:
            fp = sum(
                predict_one(self.challenger, w.fv).attack for w in evaluation if w.family == BENIGN
            )
            _, hi = wilson(fp, n_benign)
            if fp / n_benign > self.max_benign_fpr or hi > self.max_benign_fpr_ci_high:
                reasons.append(f"benign fpr {fp}/{n_benign} (ci high {hi:.4f})")
        for fam, r in cp.items():
            if fam != BENIGN and ch.get(fam, 0.0) < r - self.max_recall_drop:
                reasons.append(f"{fam} recall {ch.get(fam, 0.0)} < champion {r}")
        res = GateResult(not reasons, reasons, ch, cp)
        self._log("gate", model=self.challenger_id, passed=res.passed, reasons=reasons)
        return res

    def promote(self, gate: GateResult, approved_by: str) -> None:
        if not gate.passed:
            raise PermissionError("the gate did not pass")
        if not approved_by:
            raise PermissionError("promotion needs a named human approver")
        self.previous = (self.champion, self.champion_id)
        self.champion, self.champion_id = self.challenger, self.challenger_id
        self.challenger, self.challenger_id = None, None
        self.stage = Stage.PROBATION
        self._probation.clear()
        self._log("promoted_to_probation", model=self.champion_id, approved_by=approved_by)

    def observe_benign(self, verdicts: Iterable[KnownThreatVerdict]) -> None:
        """Probation: trusted-benign windows scored by the new champion (shadow)."""
        if self.stage is not Stage.PROBATION:
            return
        for v in verdicts:
            self._probation["n"] += 1
            self._probation["fp"] += int(v.attack)
        n, fp = self._probation["n"], self._probation["fp"]
        lo, _ = wilson(fp, n)
        if n and lo > self.max_benign_fpr:  # clearly worse than allowed: roll back now
            self.rollback(f"probation fpr {fp}/{n}, ci low {lo:.4f}")
        elif n >= self.probation_min_windows:
            self.stage = Stage.CHAMPION
            self._log("probation_passed", model=self.champion_id, fp=fp, n=n)

    def rollback(self, reason: str) -> None:
        if self.previous is None:
            raise RuntimeError("nothing to roll back to")
        bad = self.champion_id
        self.champion, self.champion_id = self.previous
        self.previous = None
        self.stage = Stage.ROLLED_BACK
        self._log("rolled_back", model=bad, restored=self.champion_id, reason=reason)


# ------------------------------------------------------------------ benchmark
def batch_prequential(
    stream: Iterable[StreamItem],
    *,
    label_delay_s: float = 300.0,
    refit_every: int = 500,
    seed: int = 0,
    synthetic: bool = False,
) -> PrequentialReport:
    """The batch baseline on the same predict-before-learn stream: a RandomForest
    (``KnownThreatClassifier``) refit on every label available so far, every
    ``refit_every`` new labels. Same delayed-label discipline, no guard needed (manifest
    labels only)."""
    from afw.ml.supervised import KnownThreatClassifier

    rep = PrequentialReport(kind="rf_batch", label_delay_s=label_delay_s, synthetic=synthetic)
    delay = timedelta(seconds=label_delay_s)
    pending: deque[tuple[datetime, LabelledWindow]] = deque()
    known: list[LabelledWindow] = []
    clf: KnownThreatClassifier | None = None
    since_fit = 0
    for item in sorted(stream, key=lambda s: s.fv.window_end):
        now = item.fv.window_end
        while pending and pending[0][0] <= now:
            known.append(pending.popleft()[1])
            rep.learnt += 1
            since_fit += 1
        if since_fit >= refit_every or (clf is None and since_fit):
            try:
                clf = KnownThreatClassifier(seed=seed).fit(known)
                since_fit = 0
            except ValueError:
                pass  # not enough per family yet
        v = clf.predict([item.fv])[0] if clf is not None else KnownThreatVerdict(UNKNOWN, 0.0)
        rep.predicted[(item.family, v.family)] += 1
        rep.by_dataset[(item.dataset_id, item.family, v.family)] += 1
        rep.windows += 1
        pending.append(
            (now + delay, LabelledWindow(item.fv, item.family, item.dataset_id, synthetic))
        )
    return rep
