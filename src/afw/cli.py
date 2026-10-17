"""Command-line entry point: ``afw --help``."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated

import structlog
import typer
import yaml

from afw.config import get_settings, load_lab_config

app = typer.Typer(no_args_is_help=True, help="AI-Adaptive-Firewall control plane")
db_app = typer.Typer(no_args_is_help=True, help="Database migrations")
token_app = typer.Typer(no_args_is_help=True, help="API tokens")
ds_app = typer.Typer(no_args_is_help=True, help="Reproducible datasets")
train_app = typer.Typer(no_args_is_help=True, help="Training and profile lifecycle")
exp_app = typer.Typer(no_args_is_help=True, help="Offline M0/M1/M2 replay experiments")
app.add_typer(db_app, name="db")
app.add_typer(token_app, name="token")
app.add_typer(ds_app, name="dataset")
app.add_typer(train_app, name="train")
app.add_typer(exp_app, name="experiment")


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
    from afw.ml.datasets import DatasetManifest, Purpose, SourceLabel

    c = _container()
    raw = json.loads(manifest.read_text())
    start, end = datetime.fromisoformat(raw["start"]), datetime.fromisoformat(raw["end"])
    obs = c.events.observations_between(raw.get("app_id", "rental"), start, end)
    labelled = {IPv4Address(s["ip"]) for s in raw["sources"]}
    obs = [o for o in obs if o.client_ip in labelled]
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
    path = c.datasets.write(m, obs)
    typer.echo(f"wrote {len(obs)} observations to {path}")


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


def _f(x: float | None) -> str:
    return "-" if x is None else f"{x:g}"


if __name__ == "__main__":
    app()


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
def lab_provision_ids() -> None:
    """Enable Suricata IDS on FW01 and forward its alerts to CTRL01 (API, idempotent)."""
    from afw.lab.provision_ids import client, provision

    with client() as c:
        provision(c, log=typer.echo)
