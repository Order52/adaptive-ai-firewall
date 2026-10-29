"""Offline replay experiment runner: compares M0 / M1 / M2 on labeled runs.

This is the reproducible comparison called for in ``docs/AI_RESEARCH.md``. It
replays one recorded, *labeled* traffic run (a :class:`DatasetManifest` plus its
observations) through the **exact live pipeline** — the same
:class:`InferenceEngine`, :class:`CorrelationEngine` and :class:`DecisionEngine`
the controller uses — under three strategies:

* **M0 (static)**  — firewall + WAF + IDS only; the adaptive controller proposes
  nothing. The static baseline is still credited with the WAF's own *inline*
  blocks recorded on the observations, so the comparison is fair.
* **M1 (statistical)** — M0 plus the robust-statistics behavioural detector.
* **M2 (ml)** — M1 plus the Isolation Forest.

All three arms replay the *identical* observation stream through the *identical*
windowing, and every arm's blocking threshold comes from the same trained
false-positive budget (``target_fpr``), so differences are attributable to the
detector set alone.

Ground-truth labels are read here (evaluation code) and never reach the
detectors. No metric is manufactured: a run with no attack windows reports
``recall = None``, not zero.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from typing import Any

from afw.config import LabConfig
from afw.correlation.auth import AuthTracker
from afw.correlation.engine import CorrelationEngine
from afw.domain.detection import DetectionResult
from afw.domain.events import HttpObservation, IdsAlert
from afw.domain.features import FeatureVector
from afw.domain.policy import PolicyIntent, PolicyKind, RateProfile
from afw.domain.profiles import BehaviorProfile
from afw.domain.risk import EvidenceCategory, RiskAssessment, RiskBand
from afw.features.extract import EndpointCatalog
from afw.features.windows import replay_windows
from afw.ml.datasets import DatasetManifest, LabelIndex, Role
from afw.ml.inference import InferenceEngine, LoadedModel, Strategy
from afw.policy.decision import DecisionEngine, LoginContext

# A source is "contained" by the adaptive controller when it proposes a policy
# that actually changes the source's traffic. WATCH is observation only.
_TRAFFIC_AFFECTING = {PolicyKind.SOURCE_BLOCK, PolicyKind.RATE_LIMIT, PolicyKind.LOGIN_CONTROL}

# (window, strategy) -> detections; see run_experiment
Scorer = Callable[[FeatureVector, Strategy], list[DetectionResult]]

# An evaluation-only arm (item 6): ``build(policed)`` returns its window scorer and an
# optional hook called with every window's assessment after the decision, e.g. to
# feed an online learner. ``policed(ip)`` tells whether this arm currently restricts
# the source, as the live learner's ``policed`` does.
Policed = Callable[[IPv4Address], bool]


@dataclass(frozen=True)
class ArmHooks:
    score: Callable[[FeatureVector], list[DetectionResult]]
    after: Callable[[FeatureVector, RiskAssessment], None] | None = None
    summary: Callable[[], dict[str, Any]] | None = None


@dataclass(frozen=True)
class ExtraArm:
    name: str
    label: str  # reported as ArmReport.strategy
    build: Callable[[Policed], ArmHooks]


_ARMS: tuple[tuple[str, Strategy], ...] = (
    ("M0", Strategy.STATIC),
    ("M1", Strategy.STATISTICAL),
    ("M2", Strategy.ML),
)


@dataclass
class _SourceTrack:
    """Per-source replay state within one arm (mirrors controller bookkeeping)."""

    first_seen: datetime | None = None
    block_until: datetime | None = None
    ratelimit_until: datetime | None = None
    first_contained_at: datetime | None = None
    # [start, end) of every traffic-affecting action, for per-request impact
    contained: list[tuple[datetime, datetime]] = field(default_factory=list)
    # A3 login controls, [start, end, profile); never counted as containment
    login: list[tuple[datetime, datetime, RateProfile]] = field(default_factory=list)

    def login_context(self, now: datetime, auth: AuthTracker, ip: IPv4Address) -> LoginContext:
        live = [c for c in self.login if c[0] <= now < c[1]]
        active = None
        since = None
        if live:
            deny = [c for c in live if c[2] is RateProfile.LOGIN_DENY]
            cur = deny[-1] if deny else live[-1]
            active, since = cur[2], cur[0]
        ended = sum(1 for c in self.login if c[1] <= now and now - c[1] <= timedelta(hours=1))
        return LoginContext(
            active=active,
            failures_since=auth.failures_since(ip, since, now) if since else 0,
            recent_repeats=ended,
        )


@dataclass
class ArmReport:
    """Controller-level outcome for one strategy on one dataset."""

    arm: str
    strategy: str
    n_windows: int = 0
    n_benign_windows: int = 0
    n_attack_windows: int = 0
    n_unlabeled_windows: int = 0
    # Window-level confusion on the *adaptive controller's* traffic-affecting action
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float | None = None
    recall: float | None = None
    fpr: float | None = None
    f1: float | None = None
    # Source-level containment (what an operator ultimately cares about)
    attack_sources: int = 0
    attack_sources_contained: int = 0
    benign_sources: int = 0
    benign_sources_flagged: int = 0
    benign_sources_flagged_ips: list[str] = field(default_factory=list)
    # of which a site-wide restriction (block or rate limit), A3 criterion B2
    benign_sources_site_restricted: int = 0
    benign_sources_site_restricted_ips: list[str] = field(default_factory=list)
    # Legitimate-traffic impact, per request (each benign observation counted once;
    # impacted if its source was rate limited or blocked at the request's own time)
    benign_requests: int = 0
    benign_requests_impacted: int = 0
    legit_request_success: float | None = None
    # A3 friction: legitimate login requests a login control would have refused
    # (nginx limit_req semantics on the recorded request times), and the users with
    # any login control
    benign_login_requests: int = 0
    benign_login_refused: int = 0
    benign_sources_login_controlled: int = 0
    benign_sources_login_controlled_ips: list[str] = field(default_factory=list)
    # Detection latency: first attack observation -> first traffic-affecting action
    detection_latency_s: dict[str, float] = field(default_factory=dict)
    mean_detection_latency_s: float | None = None
    median_detection_latency_s: float | None = None
    # Attack requests that reached the app because the source was NOT yet
    # contained (a real block would have dropped the rest). Lower is better; M0
    # contains nothing with the behavioural detectors off, so it is exposed to
    # the full attack volume.
    attack_requests_exposed: int = 0
    # Scoring cost of the adaptive detectors in this arm
    mean_score_latency_us: float | None = None
    p95_score_latency_us: float | None = None
    # Online learning inside the arm (streaming arms only): gate counts and exclusions
    learning: dict[str, Any] = field(default_factory=dict)
    decisions: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExperimentReport:
    dataset_id: str
    scenario: str
    purpose: str
    app_id: str
    profile_version: int
    model_versions: dict[str, str]
    fp_budget: float
    window_length_s: int
    window_hop_s: int
    n_observations: int
    duration_s: float
    # WAF inline blocking is identical across arms (the WAF runs in all of them);
    # reported once as the static ground floor every arm inherits.
    waf_inline_blocked_requests: int
    waf_inline_contained_attack_sources: int
    arms: list[ArmReport]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["arms"] = [a.to_dict() for a in self.arms]
        return d

    def arm_rows(self) -> list[dict[str, Any]]:
        """Flat one-row-per-arm records for the dashboard experiments table.

        Keys match the dashboard's `renderExperiments` contract exactly so real
        runs render without any client change. Shared report-level context
        (dataset, FP budget, WAF floor) is denormalised onto every row.
        """
        rows: list[dict[str, Any]] = []
        for a in self.arms:
            rows.append(
                {
                    "strategy": f"{a.arm} ({a.strategy})",
                    "scenario": self.scenario,
                    "datasets": [self.dataset_id],
                    "precision": a.precision,
                    "recall": a.recall,
                    "fpr": a.fpr,
                    "attack_sources_blocked": a.attack_sources_contained,
                    "benign_sources_restricted": a.benign_sources_flagged,
                    "median_first_attack_to_block_s": a.median_detection_latency_s,
                    "attack_requests_exposed": a.attack_requests_exposed,
                    "notes": (
                        f"{a.attack_sources_contained}/{a.attack_sources} attack src contained; "
                        f"legit success {a.legit_request_success}; "
                        f"score µs mean/p95 {a.mean_score_latency_us}/{a.p95_score_latency_us}; "
                        f"fp_budget {self.fp_budget}; purpose {self.purpose}; "
                        f"WAF inline floor {self.waf_inline_contained_attack_sources}"
                        f"/{self.arms[0].attack_sources} attack src"
                    ),
                }
            )
        return rows


def _catalog(cfg: LabConfig, profile: BehaviorProfile) -> EndpointCatalog:
    return EndpointCatalog(
        profile.known_routes(),
        profile.known_methods(),
        cfg.application(profile.app_id).login_routes(),
    )


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[k]


def _run_arm(
    arm: str,
    strategy: Strategy,
    *,
    cfg: LabConfig,
    profile: BehaviorProfile,
    models: Sequence[LoadedModel],
    observations: Sequence[HttpObservation],
    ids_alerts: Sequence[IdsAlert],
    labels: LabelIndex,
    scorer: Scorer | None = None,
    extra: ExtraArm | None = None,
    a3: bool = True,
) -> ArmReport:
    engine = InferenceEngine()
    engine.load(profile, list(models))
    engine.strategy = strategy
    score = engine.score if scorer is None else (lambda fv: scorer(fv, strategy))
    tracks: dict[IPv4Address, _SourceTrack] = {}
    clock: list[datetime | None] = [None]

    def policed(ip: IPv4Address) -> bool:
        t, now = tracks.get(ip), clock[0]
        return (
            t is not None
            and now is not None
            and any(u is not None and now < u for u in (t.block_until, t.ratelimit_until))
        )

    hooks = None if extra is None else extra.build(policed)
    if hooks is not None:
        score = hooks.score
    after = None if hooks is None else hooks.after

    login_routes = cfg.application(profile.app_id).login_routes()
    auth = AuthTracker(login_routes) if a3 else None
    correlation = CorrelationEngine(cfg.risk, auth=auth)
    for m in models:
        correlation.set_score_span(m.record.detector, m.record.benign_score_quantiles)
    for a in sorted(ids_alerts, key=lambda x: x.observed_at):
        correlation.add_ids(a)
    decisions = DecisionEngine(cfg)
    logins = [o for o in observations if o.route in login_routes and o.method == "POST"]
    fed = [0]

    def feed(until: datetime) -> None:
        if auth is None:
            return
        while fed[0] < len(logins) and logins[fed[0]].observed_at <= until:
            auth.add(logins[fed[0]])
            fed[0] += 1

    def act(ra: RiskAssessment, now: datetime, track: _SourceTrack) -> PolicyIntent | None:
        """The decision for one assessment, applied to the arm's bookkeeping."""
        block_active = track.block_until is not None and now < track.block_until
        rl_active = track.ratelimit_until is not None and now < track.ratelimit_until
        auth_ev = EvidenceCategory.AUTH in ra.corroborating_categories
        if strategy is Strategy.STATIC or block_active:
            return None
        if ra.band is RiskBand.NONE and not (auth is not None and auth_ev):
            return None
        prior = correlation.prior_enforcements(ra.source_ip, timedelta(hours=6), now)
        login = track.login_context(now, auth, ra.source_ip) if auth is not None else None
        candidate = decisions.decide(ra, prior, now, login=login)
        if candidate is None or (
            rl_active and candidate.kind in (PolicyKind.RATE_LIMIT, PolicyKind.WATCH)
        ):
            return None
        decision_counts[candidate.kind.value] = decision_counts.get(candidate.kind.value, 0) + 1
        if candidate.kind in _TRAFFIC_AFFECTING and track.first_contained_at is None:
            track.first_contained_at = now  # also for decisions from the AUTH-only view
        until = now + timedelta(seconds=candidate.duration_s or 0)
        if candidate.kind is PolicyKind.SOURCE_BLOCK:
            track.block_until = until
            track.contained.append((now, until))
            correlation.note_enforcement(ra.source_ip, now)
        elif candidate.kind is PolicyKind.RATE_LIMIT:
            track.ratelimit_until = until
            track.contained.append((now, until))
        elif candidate.kind is PolicyKind.LOGIN_CONTROL and candidate.rate_profile is not None:
            if candidate.rate_profile is RateProfile.LOGIN_DENY:  # replaces a throttle
                track.login = [(a, min(b, now), p) for a, b, p in track.login]
            track.login.append((now, until, candidate.rate_profile))
        return candidate

    first_attack_obs: dict[IPv4Address, datetime] = {}
    for o in observations:
        if labels.label_ip(o.client_ip) is Role.ATTACK and o.client_ip not in first_attack_obs:
            first_attack_obs[o.client_ip] = o.observed_at

    report = ArmReport(arm=arm, strategy=strategy.value if extra is None else extra.label)
    decision_counts: dict[str, int] = {}
    score_latencies_us: list[float] = []
    tick: list[datetime | None] = [None]
    at_tick: set[IPv4Address] = set()

    def auth_only(t: datetime) -> None:
        """A3 AUTH-only view at tick ``t`` for login activity without a window."""
        if auth is None:
            return
        for src in sorted(auth.active_sources(t) - at_tick):
            ra = correlation.assess_auth_only(profile.app_id, src, t)
            if ra is not None:
                act(ra, t, tracks.setdefault(src, _SourceTrack()))

    for fv in replay_windows(observations, cfg.window, _catalog(cfg, profile)):
        now = fv.window_end
        if tick[0] is not None and now != tick[0]:
            auth_only(tick[0])
            at_tick.clear()
        tick[0] = now
        at_tick.add(fv.source_ip)
        feed(now)
        clock[0] = now
        role = labels.label(fv)
        track = tracks.setdefault(fv.source_ip, _SourceTrack())
        if track.first_seen is None:
            track.first_seen = fv.window_start

        t0 = time.perf_counter_ns()
        detections = score(fv)
        score_latencies_us.append((time.perf_counter_ns() - t0) / 1000.0)

        ra = correlation.assess(fv, detections, now)

        block_active = track.block_until is not None and now < track.block_until
        rl_active = track.ratelimit_until is not None and now < track.ratelimit_until
        login_active = any(a <= now < b for a, b, _ in track.login)
        intent = act(ra, now, track)
        # login controls are traffic-affecting (on the login routes); B2 counts the
        # site-wide restrictions separately (benign_sources_site_restricted)
        contained_now = (
            block_active
            or rl_active
            or login_active
            or (intent is not None and intent.kind in _TRAFFIC_AFFECTING)
        )
        if contained_now and track.first_contained_at is None:
            track.first_contained_at = now
        if after is not None:
            after(fv, ra)

        # ---- window-level confusion (labeled windows only) ----
        report.n_windows += 1
        if role is Role.ATTACK:
            report.n_attack_windows += 1
            if contained_now:
                report.tp += 1
            else:
                report.fn += 1
        elif role is Role.BENIGN:
            report.n_benign_windows += 1
            if contained_now:
                report.fp += 1
            else:
                report.tn += 1
        elif role is None:
            report.n_unlabeled_windows += 1
        # Role.PROBE windows are deliberately ignored.

    if tick[0] is not None:
        auth_only(tick[0])
    _finalize_sources(report, tracks, labels, first_attack_obs)
    _login_friction(report, logins, tracks, labels)
    report.attack_requests_exposed = _exposed_attack_requests(observations, tracks, labels)
    report.benign_requests, report.benign_requests_impacted = _benign_request_impact(
        observations, tracks, labels
    )
    _finalize_rates(report)
    report.decisions = decision_counts
    if hooks is not None and hooks.summary is not None:
        report.learning = hooks.summary()
    if score_latencies_us and strategy is not Strategy.STATIC:
        report.mean_score_latency_us = round(sum(score_latencies_us) / len(score_latencies_us), 1)
        report.p95_score_latency_us = round(_percentile(score_latencies_us, 95), 1)
    return report


def _finalize_sources(
    report: ArmReport,
    tracks: dict[IPv4Address, _SourceTrack],
    labels: LabelIndex,
    first_attack_obs: dict[IPv4Address, datetime],
) -> None:
    latencies: list[float] = []
    for ip, track in tracks.items():
        role = labels.label_ip(ip)
        contained = track.first_contained_at is not None
        if role is Role.ATTACK:
            report.attack_sources += 1
            if contained:
                report.attack_sources_contained += 1
                first_obs = first_attack_obs.get(ip)
                if first_obs is not None and track.first_contained_at is not None:
                    lat = (track.first_contained_at - first_obs).total_seconds()
                    report.detection_latency_s[str(ip)] = round(lat, 1)
                    latencies.append(lat)
        elif role is Role.BENIGN:
            report.benign_sources += 1
            if contained:
                report.benign_sources_flagged += 1
                report.benign_sources_flagged_ips.append(str(ip))
            if track.contained:
                report.benign_sources_site_restricted += 1
                report.benign_sources_site_restricted_ips.append(str(ip))
    if latencies:
        report.mean_detection_latency_s = round(sum(latencies) / len(latencies), 1)
        report.median_detection_latency_s = round(_percentile(latencies, 50), 1)


def _exposed_attack_requests(
    observations: Sequence[HttpObservation],
    tracks: dict[IPv4Address, _SourceTrack],
    labels: LabelIndex,
) -> int:
    """Attack requests that reached the app before the source was contained.

    A request is "exposed" unless the source was already contained strictly
    before it (a real inline block would have dropped it). Sources never
    contained (e.g. all of M0's attackers) are exposed for every request.
    """
    total = 0
    for o in observations:
        if labels.role_at(o.client_ip, o.observed_at) is not Role.ATTACK:
            continue
        track = tracks.get(o.client_ip)
        dropped = (
            track is not None
            and track.first_contained_at is not None
            and o.observed_at > track.first_contained_at
        )
        if not dropped:
            total += 1
    return total


def _benign_request_impact(
    observations: Sequence[HttpObservation],
    tracks: dict[IPv4Address, _SourceTrack],
    labels: LabelIndex,
) -> tuple[int, int]:
    """(benign requests, of which impacted). Each observation counts once (overlapping
    windows would otherwise count a request several times); it is impacted if a rate
    limit or block on its source was in force at the time it was observed."""
    total = hit = 0
    for o in observations:
        if labels.role_at(o.client_ip, o.observed_at) is not Role.BENIGN:
            continue
        total += 1
        track = tracks.get(o.client_ip)
        if track is not None and any(a <= o.observed_at < b for a, b in track.contained):
            hit += 1
    return total, hit


LOGIN_RATE_PER_S = 3 / 60  # A3: 3 per minute
LOGIN_BURST = 4


def refused_logins(
    times: Sequence[datetime], controls: Sequence[tuple[datetime, datetime, RateProfile]]
) -> list[bool]:
    """Which of one source's login requests a login control would refuse: a deny
    refuses everything; a throttle applies nginx ``limit_req`` (rate 3/min, burst 4,
    nodelay): ``excess = max(excess - rate*dt, 0) + 1``, refused if above the burst
    (a refused request does not change the state). The limiter starts empty at each
    control's start, as the WAF's key only exists while the source is throttled."""
    out = []
    excess: float | None = None
    last: datetime | None = None
    current: tuple[datetime, datetime, RateProfile] | None = None
    for t in times:
        live = [c for c in controls if c[0] <= t < c[1]]
        if not live:
            out.append(False)
            current, excess, last = None, None, None
            continue
        if any(c[2] is RateProfile.LOGIN_DENY for c in live):
            out.append(True)
            continue
        c = live[-1]
        if c is not current:
            current, excess, last = c, None, None
        if excess is None or last is None:
            excess, last = 0.0, t  # the first request creates the key
            out.append(False)
            continue
        new = max(excess - LOGIN_RATE_PER_S * (t - last).total_seconds(), 0.0) + 1.0
        if new > LOGIN_BURST:
            out.append(True)
            continue
        excess, last = new, t
        out.append(False)
    return out


def _login_friction(
    report: ArmReport,
    logins: Sequence[HttpObservation],
    tracks: dict[IPv4Address, _SourceTrack],
    labels: LabelIndex,
) -> None:
    by_src: dict[IPv4Address, list[datetime]] = {}
    for o in logins:
        if labels.role_at(o.client_ip, o.observed_at) is Role.BENIGN:
            by_src.setdefault(o.client_ip, []).append(o.observed_at)
    for ip, times in by_src.items():
        report.benign_login_requests += len(times)
        t = tracks.get(ip)
        if t is not None and t.login:
            report.benign_login_refused += sum(refused_logins(times, t.login))
    for ip, t in tracks.items():
        if t.login and labels.label_ip(ip) is Role.BENIGN:
            report.benign_sources_login_controlled += 1
            report.benign_sources_login_controlled_ips.append(str(ip))


def _finalize_rates(report: ArmReport) -> None:
    tp, fp, fn = report.tp, report.fp, report.fn
    if tp + fp > 0:
        report.precision = round(tp / (tp + fp), 4)
    if report.n_attack_windows > 0:
        report.recall = round(tp / (tp + fn), 4) if (tp + fn) else None
    if report.n_benign_windows > 0:
        report.fpr = round(fp / report.n_benign_windows, 4)
    if report.precision is not None and report.recall:
        p, r = report.precision, report.recall
        report.f1 = round(2 * p * r / (p + r), 4) if (p + r) else None
    if report.benign_requests > 0:
        report.legit_request_success = round(
            1.0 - report.benign_requests_impacted / report.benign_requests, 4
        )


def _waf_inline(observations: Sequence[HttpObservation], labels: LabelIndex) -> tuple[int, int]:
    """Containment the static WAF provides on its own (same in every arm)."""
    blocked_requests = 0
    attack_sources_hit: set[IPv4Address] = set()
    for o in observations:
        if o.waf_blocked:
            blocked_requests += 1
            if labels.label_ip(o.client_ip) is Role.ATTACK:
                attack_sources_hit.add(o.client_ip)
    return blocked_requests, len(attack_sources_hit)


def run_experiment(
    *,
    cfg: LabConfig,
    profile: BehaviorProfile,
    models: Sequence[LoadedModel],
    manifest: DatasetManifest,
    observations: Sequence[HttpObservation],
    ids_alerts: Sequence[IdsAlert] = (),
    scorer: Scorer | None = None,
    extra_arms: Sequence[ExtraArm] = (),
    a3: bool = True,
) -> ExperimentReport:
    """Replay one labeled dataset through M0/M1/M2 and return a comparison.

    ``scorer`` replaces the default detector scoring (``InferenceEngine.score`` for the
    arm's strategy), so model variants that are not plain stored detectors can be
    compared through the same correlation and decision logic (P6). ``extra_arms`` are
    replayed after M0-M2 with the same correlation and decision logic."""
    if not observations:
        raise ValueError("no observations to replay")
    labels = LabelIndex(manifest)
    ordered = sorted(observations, key=lambda o: o.observed_at)
    duration = (ordered[-1].observed_at - ordered[0].observed_at).total_seconds()
    waf_requests, waf_sources = _waf_inline(ordered, labels)

    fp_budget = _fp_budget(models)
    arms = [
        _run_arm(
            arm,
            strategy,
            cfg=cfg,
            profile=profile,
            models=models,
            observations=ordered,
            ids_alerts=ids_alerts,
            labels=labels,
            scorer=scorer,
            a3=a3,
        )
        for arm, strategy in _ARMS
    ] + [
        _run_arm(
            x.name,
            Strategy.ML,
            cfg=cfg,
            profile=profile,
            models=models,
            observations=ordered,
            ids_alerts=ids_alerts,
            labels=labels,
            extra=x,
            a3=a3,
        )
        for x in extra_arms
    ]
    return ExperimentReport(
        dataset_id=manifest.dataset_id,
        scenario=manifest.scenario,
        purpose=manifest.purpose.value,
        app_id=manifest.app_id,
        profile_version=profile.version,
        model_versions={m.record.detector.value: m.record.version for m in models},
        fp_budget=fp_budget,
        window_length_s=cfg.window.length_s,
        window_hop_s=cfg.window.hop_s,
        n_observations=len(ordered),
        duration_s=round(duration, 1),
        waf_inline_blocked_requests=waf_requests,
        waf_inline_contained_attack_sources=waf_sources,
        arms=arms,
    )


def _fp_budget(models: Sequence[LoadedModel]) -> float:
    for m in models:
        tfpr = m.record.params.get("target_fpr")
        if isinstance(tfpr, (int, float)):
            return float(tfpr)
    return 0.0
