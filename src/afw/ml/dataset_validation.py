"""Checks on a captured dataset before it is used (P6 item 5; team attack runs).

A recorded run is only evidence if its labels are right and it cannot leak into the
data it is compared with. ``validate`` returns one finding per check; any FAIL means
the dataset must not be used until it is fixed (re-captured or relabelled), WARN means
the report must mention it. Nothing here edits a dataset.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network

from afw.domain.events import HttpObservation, Provenance
from afw.ml.datasets import DatasetManifest, Purpose, Role
from afw.ml.run_evaluation import is_synthetic

UNTRUSTED_MAX = 0.01  # share of observations without full provenance before WARN
_ADJUDICATION = (Purpose.TEST, Purpose.HOLDOUT)


class Level(StrEnum):
    PASS = "PASS"  # noqa: S105 (a check result, not a credential)
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True)
class Finding:
    check: str
    level: Level
    detail: str


def _overlaps(a: DatasetManifest, b: DatasetManifest) -> bool:
    return a.start < b.end and b.start < a.end


def validate(
    m: DatasetManifest,
    obs: Sequence[HttpObservation],
    others: Sequence[DatasetManifest] = (),
    attack_zone: IPv4Network | None = None,
) -> list[Finding]:
    """``obs`` must already have passed the store's integrity check (sha256)."""
    out: list[Finding] = []

    def add(check: str, ok: bool, detail: str, level: Level = Level.FAIL) -> None:
        out.append(Finding(check, Level.PASS if ok else level, detail))

    add(
        "count",
        len(obs) == m.n_observations,
        f"{len(obs)} observations, manifest {m.n_observations}",
    )
    outside = sum(1 for o in obs if not m.start <= o.observed_at <= m.end)
    add("time_range", outside == 0, f"{outside} observations outside {m.start}..{m.end}")
    dup = sum(c - 1 for c in Counter(o.request_id for o in obs).values() if c > 1)
    add("request_ids_unique", dup == 0, f"{dup} repeated request ids")
    apps = {o.app_id for o in obs}
    add("app_id", apps <= {m.app_id}, f"app ids {sorted(apps)}, manifest {m.app_id}")

    # -- labels
    by_ip: dict[IPv4Address, list[Role]] = {}
    for s in m.sources:
        by_ip.setdefault(s.ip, []).append(s.role)
    both = [str(ip) for ip in by_ip if Role.ATTACK in by_ip[ip] and Role.BENIGN in by_ip[ip]]
    add("roles_exclusive", not both, f"benign and attack on one address: {both or 'none'}")
    seen = Counter(o.client_ip for o in obs)
    unlabelled = sorted(str(ip) for ip in seen if ip not in by_ip)
    add("observations_labelled", not unlabelled, f"unlabelled sources: {unlabelled or 'none'}")
    silent = sorted(str(ip) for ip in by_ip if seen[ip] == 0)
    add(
        "labelled_sources_observed",
        not silent,
        f"labelled sources with no HTTP observation: {silent or 'none'} (an attack stopped "
        "before the application, e.g. by FW01, leaves none: say so in the report)",
        Level.WARN,
    )
    attack = [s for s in m.sources if s.role is Role.ATTACK]
    untyped = [str(s.ip) for s in attack if not s.attack_type]
    add("attack_type_set", not untyped, f"attack sources without attack_type: {untyped or 'none'}")
    if attack_zone is not None:
        stray = [str(s.ip) for s in attack if s.ip not in attack_zone]
        add(
            "attackers_in_attack_zone",
            not stray,
            f"attackers outside {attack_zone}: {stray or 'none'}",
        )
        benign_there = [
            str(s.ip) for s in m.sources if s.role is Role.BENIGN and s.ip in attack_zone
        ]
        add(
            "benign_outside_attack_zone",
            not benign_there,
            f"benign sources in {attack_zone}: {benign_there or 'none'}",
            Level.WARN,
        )
    if attack:
        add(
            "attack_purpose",
            m.purpose is not Purpose.TRAIN,
            f"purpose {m.purpose}: training data must be benign only",
        )
        unlab = 0
        for o in obs:
            spans = [s for s in attack if s.ip == o.client_ip]
            if spans and not any(
                (s.start is None or o.observed_at >= s.start)
                and (s.end is None or o.observed_at <= s.end)
                for s in spans
            ):
                unlab += 1
        add(
            "attacker_traffic_inside_label_window",
            unlab == 0,
            f"{unlab} attacker observations outside their labelled window (they count as "
            "unlabelled in metrics)",
            Level.WARN,
        )

    # -- provenance
    weak = sum(1 for o in obs if o.provenance is Provenance.UNVERIFIED or not o.app_joined)
    share = weak / len(obs) if obs else 0.0
    add(
        "provenance",
        share <= UNTRUSTED_MAX,
        f"{weak}/{len(obs)} observations unverified or not joined to the application",
        Level.WARN,
    )
    add(
        "not_synthetic",
        not is_synthetic(m) or m.purpose not in _ADJUDICATION,
        "synthetic data cannot be used as test or holdout evidence",
    )

    # -- run journal (team runs)
    try:
        notes = json.loads(m.notes) if m.notes.startswith("{") else {}
    except json.JSONDecodeError:
        notes = {}
    if attack:
        add("run_journal", bool(notes.get("run_id")), "manifest notes carry no run id", Level.WARN)
        if notes.get("status") == "aborted":
            out.append(
                Finding("run_aborted", Level.WARN, f"run aborted: {notes.get('abort_reason', '')}")
            )

    # -- other datasets: double capture and user leakage
    mine = set(by_ip)
    shared = [
        o
        for o in others
        if o.dataset_id != m.dataset_id and _overlaps(m, o) and mine & {s.ip for s in o.sources}
    ]
    cross = [o.dataset_id for o in shared if o.purpose is not m.purpose]
    add(
        "no_cross_split_overlap",
        not cross,
        f"same sources and overlapping time in another split: {cross or 'none'}",
    )
    same = [o.dataset_id for o in shared if o.purpose is m.purpose]
    add(
        "no_same_split_overlap",
        not same,
        f"same traffic as {same or 'none'} (e.g. a predeclared subset): never combine them",
        Level.WARN,
    )
    if m.purpose in _ADJUDICATION:
        benign = {s.ip for s in m.sources if s.role is Role.BENIGN}
        reused: dict[str, int] = {}
        for other in others:
            if other.purpose in (Purpose.TRAIN, Purpose.VALIDATION):
                n = len(benign & {s.ip for s in other.sources if s.role is Role.BENIGN})
                if n:
                    reused[other.dataset_id] = n
        add(
            "benign_users_unseen",
            not reused,
            "benign addresses also in training/validation datasets (address count): "
            f"{reused or 'none'}; results on them are 'unseen users' only for models not "
            "fitted on those datasets",
            Level.WARN,
        )
    return out


def failed(findings: Sequence[Finding]) -> bool:
    return any(f.level is Level.FAIL for f in findings)
