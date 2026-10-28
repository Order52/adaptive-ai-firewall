"""Command-line entry point: ``afw --help``."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import structlog
import typer
import yaml

from afw.config import get_settings, load_lab_config

if TYPE_CHECKING:
    from afw.lab.scenarios import Registry, RunJournal

app = typer.Typer(no_args_is_help=True, help="AI-Adaptive-Firewall control plane")
db_app = typer.Typer(no_args_is_help=True, help="Database migrations")
token_app = typer.Typer(no_args_is_help=True, help="API tokens")
ds_app = typer.Typer(no_args_is_help=True, help="Reproducible datasets")
train_app = typer.Typer(no_args_is_help=True, help="Training and profile lifecycle")
exp_app = typer.Typer(no_args_is_help=True, help="Offline M0/M1/M2 replay experiments")
ch_app = typer.Typer(
    no_args_is_help=True,
    help="Online challenger promotion gate (promotion/rollback: admin API only)",
)
app.add_typer(db_app, name="db")
app.add_typer(token_app, name="token")
app.add_typer(ds_app, name="dataset")
app.add_typer(train_app, name="train")
app.add_typer(exp_app, name="experiment")
app.add_typer(ch_app, name="challenger")
sc_app = typer.Typer(
    no_args_is_help=True,
    help="Attack-evaluation harness: ground truth, limits, kill switch (no traffic generation)",
)
app.add_typer(sc_app, name="scenario")
geo_app = typer.Typer(no_args_is_help=True, help="Real GeoIP (DB-IP Country Lite, CC BY 4.0)")
app.add_typer(geo_app, name="geoip")


def configure_logging(level: str = "INFO", as_json: bool = True) -> None:
    logging.basicConfig(level=level, stream=sys.stderr, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer() if as_json else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level)),
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one INFO line per device call


def _container(simulated: bool = False):  # type: ignore[no-untyped-def]
    from afw.container import build_container

    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    return build_container(s, simulated=simulated)


@app.command("config-check")
def config_check(path: Path = Path("config/lab.yaml")) -> None:
    """Validate the lab configuration file."""
    cfg = load_lab_config(path)
    typer.echo(f"OK: {cfg.name}: {len(cfg.zones)} zones, {len(cfg.applications)} app(s)")


@db_app.command("upgrade")
def db_upgrade() -> None:
    from afw.persistence.db import upgrade

    url = get_settings().db_url()
    upgrade(url)
    typer.echo(f"migrated {url}")


@token_app.command("issue")
def token_issue(
    name: str,
    role: Annotated[str, typer.Option(help="viewer|operator|admin")] = "viewer",
    channel: Annotated[str, typer.Option(help="api|mcp")] = "api",
) -> None:
    """Create a token; appends its hash to the tokens file and prints the secret once."""
    from afw.api.auth import TokenStore

    path = get_settings().api_tokens_file
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = yaml.safe_load(path.read_text()) if path.exists() else []
    token, entry = TokenStore.issue(name, role, channel)
    entries = [e for e in (entries or []) if e["name"] != name] + [entry]
    path.write_text(yaml.safe_dump(entries))
    path.chmod(0o600)
    typer.echo(token)


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8080,
    simulated: Annotated[bool, typer.Option(help="in-memory enforcement (no devices)")] = False,
    receiver: Annotated[bool, typer.Option(help="start the syslog receiver")] = True,
) -> None:
    """Run the controller (pipeline, reconciler, API, dashboard)."""
    import uvicorn

    from afw.api.app import create_app
    from afw.telemetry.receiver import SyslogReceiver

    c = _container(simulated)
    c.controller.reload()
    lines = None
    if receiver:
        rx = SyslogReceiver(c.cfg.telemetry, c.stats)
        rx.start()
        lines = rx.lines
    c.policy_service.reconcile()
    c.controller.start(lines)
    log = logging.getLogger("afw")
    cert = key = None
    if c.settings.tls_enabled():
        cert, key = str(c.settings.tls_cert), str(c.settings.tls_key)
        log.info("serving HTTPS on %s:%s (cert %s)", host, port, cert)
    else:
        log.warning("serving plain HTTP on %s:%s (no TLS cert configured)", host, port)
    uvicorn.run(
        create_app(c),
        host=host,
        port=port,
        log_level="warning",
        ssl_certfile=cert,
        ssl_keyfile=key,
    )


# ------------------------------------------------------------------ datasets
@ds_app.command("list")
def ds_list() -> None:
    c = _container()
    for m in c.datasets.list():
        typer.echo(
            f"{m.dataset_id:32} {m.purpose:10} {m.scenario:24} {m.n_observations:7} obs "
            f"{m.start:%Y-%m-%d %H:%M}..{m.end:%H:%M}"
        )


@ds_app.command("capture")
def ds_capture(
    dataset_id: str,
    manifest: Annotated[Path, typer.Option(help="run manifest from the traffic generator")],
    purpose: Annotated[str, typer.Option(help="train|validation|test|holdout|drift")],
) -> None:
    """Freeze observations of one recorded run (time range + labels from its manifest)."""
    from afw.correlation.engine import CorrelationEngine
    from afw.ml.datasets import DatasetManifest, Purpose, SourceLabel

    c = _container()
    raw = json.loads(manifest.read_text())
    start, end = datetime.fromisoformat(raw["start"]), datetime.fromisoformat(raw["end"])
    obs = c.events.observations_between(raw.get("app_id", "rental"), start, end)
    labelled = {IPv4Address(s["ip"]) for s in raw["sources"]}
    obs = [o for o in obs if o.client_ip in labelled]
    # IDS evidence looks back from each window end
    lookback = CorrelationEngine(c.cfg.risk).ids_lookback
    alerts = [a for a in c.events.ids_alerts_between(start - lookback, end) if a.src_ip in labelled]
    # network windows look back one long horizon; flows are reported when they end
    from afw.features.network import HORIZONS_S, LATENESS_S

    net = c.events.net_events_between(
        start - timedelta(seconds=max(HORIZONS_S)),
        end + timedelta(seconds=LATENESS_S),
        sources=sorted(labelled),
    )
    m = DatasetManifest(
        dataset_id=dataset_id,
        app_id=raw.get("app_id", "rental"),
        purpose=Purpose(purpose),
        scenario=raw["scenario"],
        seed=int(raw["seed"]),
        start=start,
        end=end,
        app_versions=tuple(sorted({o.app_version for o in obs if o.app_version})),
        sources=tuple(SourceLabel.model_validate(s) for s in raw["sources"]),
        generator=raw.get("generator", ""),
        notes=raw.get("notes", ""),
    )
    path = c.datasets.write(m, obs, alerts, net)
    typer.echo(
        f"wrote {len(obs)} observations, {len(alerts)} IDS alerts and {len(net)} network "
        f"events to {path}"
    )


@ds_app.command("validate")
def ds_validate(dataset_id: str) -> None:
    """Check a captured dataset (integrity, labels, attack zone, leakage); exit 1 on FAIL."""
    from afw.ml.dataset_validation import failed, validate

    c = _container()
    try:
        m = c.datasets.manifest(dataset_id)
    except FileNotFoundError as e:
        typer.echo(f"no dataset {dataset_id}")
        raise typer.Exit(2) from e
    try:
        obs = c.datasets.observations(dataset_id)
        alerts = c.datasets.ids_alerts(dataset_id)
    except ValueError as e:
        typer.echo(f"FAIL integrity: {e}")
        raise typer.Exit(1) from e
    zone = next((z.network for z in c.cfg.zones if z.name == "ATTACK"), None)
    findings = validate(m, obs, c.datasets.list(), zone)
    typer.echo(f"{dataset_id}: {m.purpose}, {m.scenario}, {len(obs)} observations")
    typer.echo(f"PASS integrity: sha256 matches the manifest ({len(alerts)} IDS alerts)")
    for f in findings:
        typer.echo(f"{f.level} {f.check}: {f.detail}")
    if failed(findings):
        raise typer.Exit(1)


# ------------------------------------------------------------------ scenarios
SCENARIOS = Path("config/scenarios.yaml")


def _harness() -> tuple[Registry, RunJournal]:
    from afw.lab.scenarios import RunJournal, load_registry

    settings = get_settings()
    cfg = load_lab_config(settings.config)
    reg = load_registry(SCENARIOS, cfg)
    return reg, RunJournal(Path.home() / ".config" / "afw" / "runs")


def _kill_atk01() -> list[str]:
    """Kill switch: stop the attack host through the GNS3 API."""
    from afw.lab.gns3 import Gns3Client

    c = Gns3Client.from_env()
    p = c.find_project("AI-Adaptive-Firewall")
    if p is None:
        return ["project not found: ATK01 NOT stopped"]
    out = []
    for name, n in c.node_by_name(p["project_id"]).items():
        if name == "ATK01" and n["status"] == "started":
            c.node_action(p["project_id"], n["node_id"], "stop")
            out.append("ATK01 stopped")
    return out or ["ATK01 was not running"]


@sc_app.command("list")
def scenario_list() -> None:
    reg, journal = _harness()
    for s in reg.scenarios:
        typer.echo(f"{s.id:<26} {s.family:<28} {s.purpose.value:<8} max {s.max_duration_s}s")
    act = journal.active()
    typer.echo(f"active run: {act.run_id} ({act.scenario_id})" if act else "no active run")


@sc_app.command("begin")
def scenario_begin(scenario_id: str, operator: str, notes: str = "") -> None:
    """Record ground truth: the team starts scenario SCENARIO_ID now."""
    from afw.domain.common import utcnow

    reg, journal = _harness()
    r = journal.begin(reg.get(scenario_id), operator, utcnow(), notes)
    spec = reg.get(scenario_id)
    typer.echo(f"{r.run_id} begun at {r.begun_at.isoformat()}; max {spec.max_duration_s}s")
    typer.echo("allowed targets: " + ", ".join(f"{t.ip}:{t.port}" for t in spec.targets))


@sc_app.command("mark")
def scenario_mark(run_id: str, label: str) -> None:
    from afw.domain.common import utcnow

    _, journal = _harness()
    journal.mark(run_id, label, utcnow())
    typer.echo("marked")


@sc_app.command("end")
def scenario_end(run_id: str) -> None:
    from afw.domain.common import utcnow

    _, journal = _harness()
    r = journal.end(run_id, utcnow())
    typer.echo(f"{r.run_id} ended at {r.ended_at}")


@sc_app.command("abort")
def scenario_abort(run_id: str, reason: str) -> None:
    """KILL SWITCH: stop ATK01 now, then record the abort."""
    from afw.domain.common import utcnow

    _, journal = _harness()
    r = journal.abort(run_id, reason, utcnow(), _kill_atk01)
    typer.echo(f"{r.run_id} {r.status.value}: {r.kill_result}")


@sc_app.command("watchdog")
def scenario_watchdog(every_s: float = 5.0) -> None:
    """Keep running during a team run: aborts it (stops ATK01) past its max duration."""
    import time as _time

    from afw.domain.common import utcnow

    reg, journal = _harness()
    while journal.active() is not None:
        r = journal.watchdog(reg, utcnow(), _kill_atk01)
        if r is not None:
            typer.echo(f"ABORTED {r.run_id}: {r.abort_reason}: {r.kill_result}")
            return
        _time.sleep(every_s)
    typer.echo("no active run")


@sc_app.command("manifest")
def scenario_manifest(
    run_id: str,
    out: Path,
    benign: Annotated[str, typer.Option(help="comma-separated benign background IPs")] = "",
) -> None:
    """Write the capture manifest (ground truth from the journal) for `afw dataset capture`."""
    from afw.lab.scenarios import manifest_for

    reg, journal = _harness()
    r = journal.get(run_id)
    ips = [IPv4Address(x) for x in benign.split(",") if x]
    out.write_text(json.dumps(manifest_for(r, reg.get(r.scenario_id), ips), indent=2))
    typer.echo(f"wrote {out}")


# ---------------------------------------------------------------- challenger
@ch_app.command("evaluate")
def challenger_evaluate(
    benign: Annotated[str, typer.Option(help="comma-separated benign holdout dataset ids")],
    attack: Annotated[str, typer.Option(help="comma-separated labelled attack dataset ids")] = "",
    actor: str = "cli",
    app_id: str = "rental",
) -> None:
    """Run the promotion gate on the newest challenger checkpoint (no promotion)."""
    c = _container()
    ev = c.challenger.evaluate(
        app_id, [d for d in benign.split(",") if d], [d for d in attack.split(",") if d], actor
    )
    for chk in ev.checks:
        typer.echo(
            f"{'PASS' if chk.passed else 'FAIL'}  {chk.name:<26} value={chk.value} "
            f"limit={chk.limit}  {chk.detail}"
        )
    typer.echo(f"evaluation {ev.evaluation_id}: {'PASSED' if ev.passed else 'FAILED'}")


@ch_app.command("status")
def challenger_status(app_id: str = "rental") -> None:
    typer.echo(json.dumps(_container().challenger.snapshot(app_id), indent=2, default=str))


# ------------------------------------------------------------------ training
@train_app.command("bootstrap")
def train_bootstrap(
    train: Annotated[str, typer.Option(help="comma-separated TRAIN dataset ids")],
    val: Annotated[str, typer.Option(help="comma-separated VALIDATION dataset ids")],
    app_id: str = "rental",
    seed: int = 42,
) -> None:
    c = _container()
    res = c.learning.bootstrap(app_id, train.split(","), val.split(","), seed=seed)
    typer.echo(f"candidate profile v{res.profile.version} ({res.profile.content_hash[:12]})")
    for m in res.models:
        vm = m.validation_metrics
        typer.echo(
            f"  {m.detector.value:18} thr={m.threshold:.4f} fpr={vm.fpr} recall={vm.recall} "
            f"auc={vm.roc_auc} latency_us={vm.mean_latency_us} bytes={vm.model_bytes}"
        )
    for chk in res.evaluation.checks:
        typer.echo(f"  [{'PASS' if chk.passed else 'FAIL'}] {chk.name} {chk.value} {chk.detail}")


@train_app.command("promote")
def train_promote(version: int, reviewer: str, note: str, app_id: str = "rental") -> None:
    c = _container()
    p = c.learning.promote(app_id, version, reviewer, note)
    typer.echo(f"profile v{p.version} is now TRUSTED")


@train_app.command("rollback")
def train_rollback(version: int, reviewer: str, note: str, app_id: str = "rental") -> None:
    c = _container()
    p = c.learning.rollback(app_id, version, reviewer, note)
    typer.echo(f"rolled back: profile v{p.version} is TRUSTED")


@train_app.command("status")
def train_status(app_id: str = "rental") -> None:
    c = _container()
    for p in c.profiles.list(app_id):
        typer.echo(
            f"profile v{p.version} {p.status:9} windows={p.provenance.n_windows} "
            f"sources={p.provenance.n_sources} hash={p.content_hash[:12]}"
        )
    for m in c.models.list(app_id):
        typer.echo(f"  {m.model_id} {m.detector.value:18} p{m.profile_version} {m.status}")


# --------------------------------------------------------------- experiments
@exp_app.command("benign-generalization")
def experiment_benign_generalization(
    versions: Annotated[str, typer.Option(help="comma-separated profile versions (frozen)")],
    datasets: Annotated[str, typer.Option(help="comma-separated all-benign dataset ids")],
    out: Annotated[Path, typer.Option(help="JSON report path")],
    app_id: str = "rental",
    seed: int = 0,
    sensitivity_ref: Annotated[
        int | None, typer.Option(help="also compare probe sensitivity against this version")
    ] = None,
) -> None:
    """P1: false positives of frozen profiles on held-out benign runs, per window
    (tumbling, source CIs), per user and per request, plus decision-level impact."""
    from afw.ml.benign_generalization import evaluate_benign, matched_probe_sensitivity

    c = _container()
    vs = [int(x) for x in versions.split(",") if x]
    dss = [d for d in datasets.split(",") if d]
    loaded = {
        v: c.learning.load_version(app_id, v)
        for v in {*vs, *([sensitivity_ref] if sensitivity_ref else [])}
    }
    obs = {ds: c.datasets.observations(ds) for ds in dss}
    wins = {
        (v, ds): c.learning.windows(obs[ds], c.learning.catalog(app_id, loaded[v][0]))
        for v in loaded
        for ds in dss
    }
    rows = []
    for v in vs:
        profile, models = loaded[v]
        for ds in dss:
            res = evaluate_benign(
                cfg=c.cfg,
                profile=profile,
                models=models,
                manifest=c.datasets.manifest(ds),
                observations=obs[ds],
                windows=wins[(v, ds)],
                seed=seed,
            )
            if sensitivity_ref is not None and v != sensitivity_ref:
                r = sensitivity_ref
                res[f"sensitivity_vs_v{r}"] = matched_probe_sensitivity(
                    (*loaded[r], wins[(r, ds)]), (profile, models, wins[(v, ds)])
                )
            rows.append(res)
            dets = " ".join(
                f"{k}={d['rate']}[{d['users']['with_any_flag']}/{d['users']['n']}u]"
                for k, d in res["detectors"].items()
            )
            typer.echo(f"v{v} {ds}: {dets}")
    out.write_text(json.dumps(rows, indent=1, default=str))
    typer.echo(f"wrote {out}")


@exp_app.command("replay")
def experiment_replay(
    datasets: Annotated[str, typer.Option(help="comma-separated labeled dataset ids")],
    app_id: str = "rental",
    store: Annotated[bool, typer.Option(help="persist each report to the DB")] = True,
) -> None:
    """Replay labeled runs through M0/M1/M2 against the active trusted profile."""
    from afw.ml.experiments import run_experiment

    c = _container()
    loaded = c.learning.load_active(app_id)
    if loaded is None:
        typer.echo(f"no trusted profile for {app_id}; bootstrap and promote one first")
        raise typer.Exit(1)
    profile, models = loaded
    for ds in [d for d in datasets.split(",") if d]:
        manifest = c.datasets.manifest(ds)
        obs = c.datasets.observations(ds)
        report = run_experiment(
            cfg=c.cfg, profile=profile, models=models, manifest=manifest, observations=obs
        )
        if store:
            for row in report.arm_rows():
                c.experiments.add("replay", row)
        typer.echo(
            f"\n{ds}  scenario={report.scenario} purpose={report.purpose} "
            f"obs={report.n_observations} windows={report.arms[0].n_windows} "
            f"fp_budget={report.fp_budget}"
        )
        typer.echo(
            f"  WAF inline: blocked {report.waf_inline_blocked_requests} req, "
            f"contained {report.waf_inline_contained_attack_sources} attack source(s)"
        )
        header = (
            f"  {'arm':4} {'prec':>6} {'recall':>7} {'fpr':>7} {'f1':>6} "
            f"{'atk_hit':>8} {'legit%':>7} {'det_s':>7} {'score_us':>9}"
        )
        typer.echo(header)
        for a in report.arms:
            typer.echo(
                f"  {a.arm:4} {_f(a.precision):>6} {_f(a.recall):>7} {_f(a.fpr):>7} "
                f"{_f(a.f1):>6} {a.attack_sources_contained}/{a.attack_sources:>6} "
                f"{_f(a.legit_request_success):>7} {_f(a.mean_detection_latency_s):>7} "
                f"{_f(a.mean_score_latency_us):>9}"
            )


@exp_app.command("supervised")
def experiment_supervised(
    train: Annotated[str, typer.Option(help="comma-separated labelled dataset ids")],
    test: Annotated[str, typer.Option(help="comma-separated dataset ids never trained on")],
    withhold: Annotated[str, typer.Option(help="attack family to leave out (novelty)")] = "",
    allow_synthetic: bool = False,
    app_id: str = "rental",
) -> None:
    """N3/N4: known-threat classifier on labelled runs, split by run."""
    from afw.features.windows import replay_windows
    from afw.ml.experiments import _catalog
    from afw.ml.supervised import (
        KnownThreatClassifier,
        evaluate,
        labelled_windows,
        split_by_dataset,
        withheld_family,
    )

    c = _container()
    loaded = c.learning.load_active(app_id)
    if loaded is None:
        typer.echo(f"no trusted profile for {app_id}; its endpoint catalog is needed")
        raise typer.Exit(1)
    catalog = _catalog(c.cfg, loaded[0])
    tr, te = [d for d in train.split(",") if d], [d for d in test.split(",") if d]
    windows = []
    for ds in tr + te:
        obs = sorted(c.datasets.observations(ds), key=lambda o: o.observed_at)
        vecs = replay_windows(obs, c.cfg.window, catalog)
        windows += labelled_windows(c.datasets.manifest(ds), vecs, allow_synthetic)
    if withhold:
        out: dict[str, object] = withheld_family(windows, withhold, te)
    else:
        fit, held = split_by_dataset(windows, te)
        out = evaluate(KnownThreatClassifier().fit(fit), held).as_dict()
    out |= {"train": tr, "test": te}
    typer.echo(json.dumps(out, indent=2, default=str))


@exp_app.command("online-replay")
def experiment_online_replay(
    learn: Annotated[str, typer.Option(help="comma-separated dataset ids to learn from")],
    probe: Annotated[str, typer.Option(help="comma-separated held-out dataset ids to score")],
    app_id: str = "rental",
    relax_rate_caps: Annotated[
        bool,
        typer.Option(help="lift the per-source hourly cap and tenure (labelled in the report)"),
    ] = False,
    out: Annotated[Path | None, typer.Option(help="write the JSON report here")] = None,
) -> None:
    """Replay recorded runs through the live online-learning path (shadow challenger)."""
    import json

    from afw.ml.datasets import assert_disjoint
    from afw.ml.online_replay import replay_online

    c = _container()
    loaded = c.learning.load_active(app_id)
    if loaded is None:
        typer.echo(f"no trusted profile for {app_id}")
        raise typer.Exit(1)
    profile, models = loaded
    learn_ids = [d for d in learn.split(",") if d]
    probe_ids = [d for d in probe.split(",") if d]
    assert_disjoint(learn_ids, probe_ids)
    lc = c.cfg.learning
    if relax_rate_caps:
        lc = lc.model_copy(
            update={"max_windows_per_source_per_hour": 10_000, "min_source_tenure_s": 0}
        )
    report = replay_online(
        cfg=c.cfg,
        profile=profile,
        models=models,
        catalog=c.learning.catalog(app_id, profile),
        learn=[o for d in learn_ids for o in c.datasets.observations(d)],
        probe=[o for d in probe_ids for o in c.datasets.observations(d)],
        learning=lc,
    )
    report = {"learn_datasets": learn_ids, "probe_datasets": probe_ids, **report}
    text = json.dumps(report, indent=2, default=str)
    if out:
        out.write_text(text)
    typer.echo(text)


@exp_app.command("evaluate")
def experiment_evaluate(
    datasets: Annotated[str, typer.Option(help="comma-separated labelled attack runs")],
    app_id: str = "rental",
    allow_synthetic: Annotated[
        bool, typer.Option(help="permit synthetic data (output labelled NOT A RESULT)")
    ] = False,
    out: Annotated[Path | None, typer.Option(help="write the JSON report here")] = None,
    version: Annotated[
        int | None, typer.Option(help="evaluate this stored profile version (default: trusted)")
    ] = None,
    streaming: Annotated[
        bool, typer.Option(help="also replay the streaming-ML (S-ML) and hybrid (HYB) arms")
    ] = False,
    warmup: Annotated[
        str,
        typer.Option(help="comma-separated benign datasets streamed through the learner first"),
    ] = "",
) -> None:
    """M6: M0/M1/M2 across labelled attack runs with run-level confidence intervals."""
    from afw.ml.experiments import run_experiment
    from afw.ml.run_evaluation import aggregate, is_synthetic
    from afw.ml.streaming_arms import streaming_arms

    c = _container()
    loaded = (
        c.learning.load_active(app_id)
        if version is None
        else c.learning.load_version(app_id, version)
    )
    if loaded is None:
        typer.echo(f"no trusted profile for {app_id}")
        raise typer.Exit(1)
    profile, models = loaded
    ids = [d for d in datasets.split(",") if d]
    manifests = [c.datasets.manifest(d) for d in ids]
    bad = [m.dataset_id for m in manifests if is_synthetic(m)]
    if bad and not allow_synthetic:
        typer.echo(f"refusing synthetic datasets {bad} (use --allow-synthetic for a labelled demo)")
        raise typer.Exit(2)
    warm_ids = [d for d in warmup.split(",") if d]
    warm_m = [c.datasets.manifest(d) for d in warm_ids]
    late = [w.dataset_id for w in warm_m for m in manifests if w.end >= m.start or w.has_attack()]
    if late:
        typer.echo(
            f"warm-up must be benign and end before every evaluated run: {sorted(set(late))}"
        )
        raise typer.Exit(2)
    warm_obs = [o for d in warm_ids for o in c.datasets.observations(d)]
    reports = [
        run_experiment(
            cfg=c.cfg,
            profile=profile,
            models=models,
            manifest=m,
            observations=c.datasets.observations(m.dataset_id),
            ids_alerts=c.datasets.ids_alerts(m.dataset_id),
            extra_arms=streaming_arms(c.cfg, profile, models, warmup=warm_obs) if streaming else (),
        )
        for m in manifests
    ]
    result = aggregate(reports, manifests, allow_synthetic=allow_synthetic)
    text = json.dumps({**result, "per_run": [r.to_dict() for r in reports]}, indent=2, default=str)
    if out:
        out.write_text(text)
    typer.echo(json.dumps(result, indent=2, default=str))


@exp_app.command("adaptation")
def experiment_adaptation(
    learn: Annotated[str, typer.Option(help="comma-separated recorded benign drift runs")],
    hold: Annotated[str, typer.Option(help="comma-separated later, disjoint benign runs")],
    app_id: str = "rental",
    seed: int = 0,
    out: Annotated[Path | None, typer.Option(help="write the JSON report here")] = None,
) -> None:
    """M4: drift adaptation, poisoning resistance and injected-regression rollback."""
    import json

    from afw.ml.adaptation_experiment import run_adaptation
    from afw.ml.datasets import assert_disjoint

    c = _container()
    loaded = c.learning.load_active(app_id)
    if loaded is None:
        typer.echo(f"no trusted profile for {app_id}")
        raise typer.Exit(1)
    profile, models = loaded
    learn_ids = [d for d in learn.split(",") if d]
    hold_ids = [d for d in hold.split(",") if d]
    assert_disjoint(learn_ids, hold_ids)
    report = run_adaptation(
        cfg=c.cfg,
        profile=profile,
        models=models,
        catalog=c.learning.catalog(app_id, profile),
        learn=[o for d in learn_ids for o in c.datasets.observations(d)],
        hold=[o for d in hold_ids for o in c.datasets.observations(d)],
        learn_ids=learn_ids,
        hold_ids=hold_ids,
        seed=seed,
    )
    text = json.dumps(report, indent=2, default=str)
    if out:
        out.write_text(text)
    typer.echo(text)


def _f(x: float | None) -> str:
    return "-" if x is None else f"{x:g}"


if __name__ == "__main__":
    app()


@geo_app.command("install")
def geoip_install(
    file: Path,
    release: Annotated[str, typer.Option(help="DB-IP release month, YYYY-MM")],
    source: Annotated[str, typer.Option(help="download URL, recorded as provenance")],
) -> None:
    """Install a downloaded dbip-country-lite CSV (.csv.gz) into <data_dir>/geo."""
    from afw.config import get_settings
    from afw.domain.common import utcnow
    from afw.geoip import install

    meta = install(file, Path(get_settings().data_dir) / "geo", release, source, utcnow())
    typer.echo(json.dumps(meta.__dict__, indent=2))


@geo_app.command("lookup")
def geoip_lookup(ip: str) -> None:
    from ipaddress import IPv4Address

    from afw.config import get_settings
    from afw.domain.common import utcnow
    from afw.geoip import load_optional

    db, err = load_optional(Path(get_settings().data_dir) / "geo")
    if db is None:
        typer.echo(err)
        raise typer.Exit(1)
    typer.echo(json.dumps({"ip": ip, "country": db.lookup(IPv4Address(ip))}))
    typer.echo(json.dumps(db.status(utcnow())))


lab_app = typer.Typer(no_args_is_help=True, help="GNS3 lab automation (API v2)")
app.add_typer(lab_app, name="lab")


@lab_app.command("build")
def lab_build(
    topology: Path = Path("lab/gns3/topology.yaml"),
    pubkey: Path = Path("~/.config/afw/lab_ed25519.pub"),
) -> None:
    """Create/complete the GNS3 project from the declarative topology."""
    from afw.lab.gns3 import Gns3Client
    from afw.lab.topology import apply, load_topology

    pid = apply(
        Gns3Client.from_env(),
        load_topology(topology),
        pubkey.expanduser().read_text().strip(),
        log=typer.echo,
    )
    typer.echo(f"project {pid} ready")


@lab_app.command("start")
def lab_start(
    nodes: Annotated[list[str] | None, typer.Argument()] = None,
    project: str = "AI-Adaptive-Firewall",
) -> None:
    """Start the given nodes (default: all)."""
    from afw.lab.gns3 import Gns3Client, Gns3Error

    c = Gns3Client.from_env()
    p = c.find_project(project)
    if p is None:
        raise Gns3Error(f"project {project} not found; run `afw lab build`")
    for name, n in c.node_by_name(p["project_id"]).items():
        if (not nodes or name in nodes) and n["status"] != "started":
            c.node_action(p["project_id"], n["node_id"], "start")
            typer.echo(f"started {name}")


@lab_app.command("stop")
def lab_stop(
    nodes: Annotated[list[str] | None, typer.Argument()] = None,
    project: str = "AI-Adaptive-Firewall",
) -> None:
    """Stop the given nodes (default: all)."""
    from afw.lab.gns3 import Gns3Client, Gns3Error

    c = Gns3Client.from_env()
    p = c.find_project(project)
    if p is None:
        raise Gns3Error(f"project {project} not found")
    for name, n in c.node_by_name(p["project_id"]).items():
        if (not nodes or name in nodes) and n["status"] == "started":
            c.node_action(p["project_id"], n["node_id"], "stop")
            typer.echo(f"stopped {name}")


@lab_app.command("status")
def lab_status(project: str = "AI-Adaptive-Firewall") -> None:
    """Show node status and console ports."""
    from afw.lab.gns3 import Gns3Client

    c = Gns3Client.from_env()
    p = c.find_project(project)
    if p is None:
        typer.echo("project not found")
        raise typer.Exit(1)
    for name, n in sorted(c.node_by_name(p["project_id"]).items()):
        typer.echo(f"{name:10} {n['node_type']:16} {n['status']:8} console={n.get('console')}")


@lab_app.command("provision-fw")
def lab_provision_fw(project: str = "AI-Adaptive-Firewall", force: bool = False) -> None:
    """Configure FW01 over its serial console (idempotent)."""
    from afw.lab.gns3 import Gns3Client, Gns3Error
    from afw.lab.provision_fw import provision

    c = Gns3Client.from_env()
    p = c.find_project(project)
    if p is None:
        raise Gns3Error(f"project {project} not found")
    fw = c.node_by_name(p["project_id"])["FW01"]
    if fw["status"] != "started":
        raise Gns3Error("FW01 is not started (afw lab start FW01)")
    provision(
        fw.get("console_host") or "127.0.0.1", int(fw["console"]), log=typer.echo, force=force
    )


@lab_app.command("provision-geo")
def lab_provision_geo(
    project: str = "AI-Adaptive-Firewall",
    api_only: Annotated[bool, typer.Option(help="aliases and rules only")] = False,
) -> None:
    """Install real-country enforcement on FW01: tables, rules, pull job (ADR-036)."""
    from afw.config import load_lab_config
    from afw.lab.gns3 import Gns3Client, Gns3Error
    from afw.lab.provision_geo import provision_api, provision_console
    from afw.lab.provision_ids import client
    from afw.lab.secrets import ensure_lab_secrets

    g = load_lab_config(Path("config/lab.yaml")).geo_enforcement
    ensure_lab_secrets()
    with client() as c:
        provision_api(c, g, log=typer.echo)
    if api_only:
        return
    gc = Gns3Client.from_env()
    p = gc.find_project(project)
    if p is None:
        raise Gns3Error(f"project {project} not found")
    fw = gc.node_by_name(p["project_id"])["FW01"]
    provision_console(fw.get("console_host") or "127.0.0.1", int(fw["console"]), typer.echo)


@lab_app.command("recreate")
def lab_recreate(
    nodes: list[str],
    project: str = "AI-Adaptive-Firewall",
    topology: Path = Path("lab/gns3/topology.yaml"),
    pubkey: Path = Path("~/.config/afw/lab_ed25519.pub"),
) -> None:
    """Delete nodes (and their disks/links) and rebuild them from the golden image."""
    from afw.lab.gns3 import Gns3Client, Gns3Error
    from afw.lab.topology import apply, load_topology

    c = Gns3Client.from_env()
    p = c.find_project(project)
    if p is None:
        raise Gns3Error(f"project {project} not found")
    existing = c.node_by_name(p["project_id"])
    for name in nodes:
        if name in existing:
            if existing[name]["status"] == "started":
                c.node_action(p["project_id"], existing[name]["node_id"], "stop")
            c.delete_node(p["project_id"], existing[name]["node_id"])
            typer.echo(f"deleted {name}")
    apply(c, load_topology(topology), pubkey.expanduser().read_text().strip(), log=typer.echo)


@lab_app.command("layout")
def lab_layout() -> None:
    """Apply the professional zone-based GNS3 canvas layout + annotations (idempotent)."""
    from afw.lab.layout import apply_layout

    result = apply_layout()
    typer.echo(
        f"nodes moved: {result['nodes_moved']}, annotations drawn: {result['annotations_drawn']}"
    )


@lab_app.command("verify")
def lab_verify() -> None:
    """Check zone isolation from inside the guests against the intended policy."""
    from afw.lab.verify import verify

    results = verify()
    for c, got, ok in results:
        want = "allow" if c.allowed else "deny"
        port = c.port if c.port else "icmp"
        typer.echo(
            f"{'PASS' if ok else 'FAIL'}  {c.src:7} -> {c.dst}:{port:<5} "
            f"want={want:5} got={got:9} {c.why}"
        )
    failed = sum(not ok for *_, ok in results)
    typer.echo(f"{len(results) - failed}/{len(results)} checks passed")
    if failed:
        raise typer.Exit(1)


@lab_app.command("deploy")
def lab_deploy(
    limit: Annotated[str | None, typer.Option(help="Ansible --limit pattern")] = None,
    check: bool = False,
) -> None:
    """Ensure host-side secrets, then run the Ansible site playbook."""
    import subprocess

    from afw.lab.secrets import ensure_lab_secrets

    for item in ensure_lab_secrets():
        typer.echo(f"created {item}")
    cmd = ["ansible-playbook", "site.yaml"]
    if limit:
        cmd += ["--limit", limit]
    if check:
        cmd += ["--check", "--diff"]
    raise typer.Exit(subprocess.run(cmd, cwd=Path("lab/ansible"), check=False).returncode)  # noqa: S603


@lab_app.command("provision-ids")
def lab_provision_ids(
    plaintext: Annotated[bool, typer.Option(help="old plaintext feed to 5515")] = False,
    feed_only: Annotated[bool, typer.Option(help="only (re)apply the syslog feed")] = False,
    relp_only: Annotated[bool, typer.Option(help="only the sensor RELP pass rules")] = False,
) -> None:
    """Enable Suricata IDS on FW01 and forward its alerts to CTRL01 (API, idempotent)."""
    from afw.lab.provision_ids import client, destination, provision, relp_rules

    with client() as c:
        relp_rules(c, log=typer.echo)
        if relp_only:
            return
        if feed_only:
            destination(c, plaintext, log=typer.echo)
        else:
            provision(c, log=typer.echo, plaintext=plaintext)
