"""Supervised known-threat classifier (N3) and the withheld-family protocol (N4).

Learns attack *families* (brute force, scanning, injection, ...) from windows whose
labels come from a dataset manifest: who ran which attack from which address and
when. Labels are never taken from the controller's own predictions.

Discipline:

* **Grouped splits.** Windows of one run are strongly correlated, so splitting
  windows at random leaks the test set into training. Splits are by dataset (one
  capture run), and a split that shares a dataset is refused.
* **Provenance.** Manifests generated synthetically (``generator`` starts with
  ``SYNTHETIC``) are refused unless the caller opts in, and the opt-in is recorded
  in the report, so synthetic results are never presented as team-attack results.
* **Abstention.** A prediction below ``min_confidence`` is ``unknown``: neither a
  known family nor benign. Unknown windows are left to the novelty path; the
  classifier never claims an attack it has not learnt.
* **Withheld families.** ``withheld_family`` trains without one family and reports
  how that family's windows are treated (another family / unknown / benign). This is
  how novelty is measured without pretending a seen family is new.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.ml.datasets import DatasetManifest, LabelIndex, Role

BENIGN = "benign"
UNKNOWN = "unknown"
Z95_TWO_SIDED = 1.96


@dataclass(frozen=True)
class LabelledWindow:
    fv: FeatureVector
    family: str  # "benign" or the manifest's attack_type
    dataset_id: str
    synthetic: bool


def labelled_windows(
    manifest: DatasetManifest, vectors: Iterable[FeatureVector], allow_synthetic: bool = False
) -> list[LabelledWindow]:
    """Windows a manifest labels. Unlabelled, probe and family-less attack windows are
    dropped (an attack with no recorded type cannot teach a family)."""
    synthetic = manifest.generator.upper().startswith("SYNTHETIC")
    if synthetic and not allow_synthetic:
        raise ValueError(f"dataset {manifest.dataset_id} is synthetic; refused without opt-in")
    idx = LabelIndex(manifest)
    out: list[LabelledWindow] = []
    for fv in vectors:
        role = idx.label(fv)
        if role is Role.BENIGN:
            family: str | None = BENIGN
        elif role is Role.ATTACK:
            family = idx.attack_type(fv)
        else:
            family = None
        if family:
            out.append(LabelledWindow(fv, family, manifest.dataset_id, synthetic))
    return out


def split_by_dataset(
    windows: Sequence[LabelledWindow], test_datasets: Iterable[str]
) -> tuple[list[LabelledWindow], list[LabelledWindow]]:
    test = set(test_datasets)
    train = [w for w in windows if w.dataset_id not in test]
    held = [w for w in windows if w.dataset_id in test]
    if not train or not held:
        raise ValueError("both sides of a split need windows")
    return train, held


def _rows(windows: Sequence[LabelledWindow]) -> np.ndarray:
    return np.array([w.fv.as_row() for w in windows], dtype=float).reshape(-1, len(FEATURE_NAMES))


@dataclass(frozen=True)
class KnownThreatVerdict:
    family: str  # a learnt family, "benign" or "unknown"
    confidence: float

    @property
    def attack(self) -> bool:
        return self.family not in (BENIGN, UNKNOWN)


class KnownThreatClassifier:
    def __init__(
        self, min_confidence: float = 0.8, min_per_family: int = 20, seed: int = 0
    ) -> None:
        self.min_confidence = min_confidence
        self.min_per_family = min_per_family
        self.seed = seed
        self._model: RandomForestClassifier | None = None
        self.train_datasets: frozenset[str] = frozenset()

    @property
    def families(self) -> tuple[str, ...]:
        return tuple(str(c) for c in self._model.classes_) if self._model is not None else ()

    def fit(self, windows: Sequence[LabelledWindow]) -> KnownThreatClassifier:
        counts = Counter(w.family for w in windows)
        if BENIGN not in counts or len(counts) < 2:
            raise ValueError("training needs benign windows and at least one attack family")
        small = {f: n for f, n in counts.items() if n < self.min_per_family}
        if small:
            raise ValueError(f"too few windows per family (need {self.min_per_family}): {small}")
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_leaf=3,
            class_weight="balanced_subsample",
            random_state=self.seed,
            n_jobs=1,
        )
        model.fit(_rows(windows), [w.family for w in windows])
        self._model = model
        self.train_datasets = frozenset(w.dataset_id for w in windows)
        return self

    def predict(self, vectors: Sequence[FeatureVector]) -> list[KnownThreatVerdict]:
        if self._model is None:
            raise RuntimeError("classifier is not trained")
        x = np.array([v.as_row() for v in vectors], dtype=float).reshape(-1, len(FEATURE_NAMES))
        proba = self._model.predict_proba(x)
        classes = self.families
        out = []
        for row in proba:
            i = int(np.argmax(row))
            conf = float(row[i])
            fam = classes[i] if conf >= self.min_confidence else UNKNOWN
            out.append(KnownThreatVerdict(fam, round(conf, 4)))
        return out


def wilson(count: int, n: int, z: float = Z95_TWO_SIDED) -> tuple[float, float]:
    """Two-sided 95 % Wilson interval for count/n."""
    if n == 0:
        return (0.0, 1.0)
    p = count / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass
class Evaluation:
    n_windows: int
    synthetic: bool
    benign_windows: int
    benign_flagged: int  # benign windows predicted as any attack family
    per_family: dict[str, dict[str, float]] = field(default_factory=dict)
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        lo, hi = wilson(self.benign_flagged, self.benign_windows)
        return {
            "n_windows": self.n_windows,
            "SYNTHETIC": self.synthetic,
            "benign_fpr": self.benign_flagged / self.benign_windows
            if self.benign_windows
            else None,
            "benign_fpr_ci95": [round(lo, 4), round(hi, 4)],
            "benign_windows": self.benign_windows,
            "per_family": self.per_family,
            "confusion": self.confusion,
        }


def evaluate(clf: KnownThreatClassifier, test: Sequence[LabelledWindow]) -> Evaluation:
    overlap = clf.train_datasets & {w.dataset_id for w in test}
    if overlap:
        raise ValueError(f"test shares datasets with training: {sorted(overlap)}")
    verdicts = clf.predict([w.fv for w in test])
    confusion: dict[str, Counter[str]] = {}
    for w, v in zip(test, verdicts, strict=True):
        confusion.setdefault(w.family, Counter())[v.family] += 1
    benign = confusion.get(BENIGN, Counter())
    ev = Evaluation(
        n_windows=len(test),
        synthetic=any(w.synthetic for w in test),
        benign_windows=sum(benign.values()),
        benign_flagged=sum(n for f, n in benign.items() if f not in (BENIGN, UNKNOWN)),
        confusion={k: dict(c) for k, c in confusion.items()},
    )
    for fam, c in confusion.items():
        if fam == BENIGN:
            continue
        n = sum(c.values())
        lo, hi = wilson(c[fam], n)
        ev.per_family[fam] = {
            "windows": n,
            "recall": c[fam] / n,
            "recall_ci95_low": round(lo, 4),
            "recall_ci95_high": round(hi, 4),
            "detected_as_other_family": sum(
                k for f, k in c.items() if f not in (fam, BENIGN, UNKNOWN)
            )
            / n,
            "unknown": c[UNKNOWN] / n,
            "missed_as_benign": c[BENIGN] / n,
        }
    return ev


def withheld_family(
    windows: Sequence[LabelledWindow],
    family: str,
    test_datasets: Iterable[str],
    clf: KnownThreatClassifier | None = None,
) -> dict[str, object]:
    """Train without ``family`` (and on no test dataset); report how the held-out
    family's test windows are treated. 'unknown' and 'other family' both mean the
    window was not taken for benign; only 'benign' is a miss."""
    if family == BENIGN:
        raise ValueError("benign cannot be withheld")
    train, test = split_by_dataset(windows, test_datasets)
    train = [w for w in train if w.family != family]
    clf = (clf or KnownThreatClassifier()).fit(train)
    target = [w for w in test if w.family == family]
    if not target:
        raise ValueError(f"no {family} windows in the test datasets")
    c = Counter(v.family for v in clf.predict([w.fv for w in target]))
    n = len(target)
    not_benign = n - c[BENIGN]
    lo, hi = wilson(not_benign, n)
    return {
        "withheld": family,
        "windows": n,
        "SYNTHETIC": any(w.synthetic for w in target),
        "as_other_family": sum(k for f, k in c.items() if f not in (BENIGN, UNKNOWN)) / n,
        "unknown": c[UNKNOWN] / n,
        "as_benign": c[BENIGN] / n,
        "not_benign_ci95": [round(lo, 4), round(hi, 4)],
        "trained_families": list(clf.families),
    }
