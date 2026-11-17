"""Operational endpoints: readiness and Prometheus metrics.

* ``/api/health``  liveness: the process answers (``app.py``).
* ``/api/readyz``  readiness: the controller can do its job (database, reconciled, sensors
  fresh, models loaded, enforcement backends reachable, certificate not about to expire).
  Anonymous callers get only ``{"ready": bool}`` with 200/503; a viewer token gets the checks.
* ``/api/metrics`` Prometheus text exposition (viewer token), see ``docs/SLO.md``.
"""

from __future__ import annotations

import shutil
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509

from afw import __version__
from afw.container import Container

CERT_WARN_DAYS = 30  # readiness fails inside this window: rotate (SECURITY_CHECKLIST.md)
DISK_MAX_USED = 0.90  # readiness fails above this: see runbooks/database-maintenance.md
DISK_MIN_FREE_BYTES = 500 * 2**20


def cert_days_left(cert_path: Path | None, now: datetime | None = None) -> float | None:
    """Days until the server certificate expires, or None when TLS is not in use."""
    if cert_path is None or not cert_path.exists():
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (OSError, ValueError):
        return None
    return (cert.not_valid_after_utc - (now or datetime.now(UTC))).total_seconds() / 86400


def disk_state(path: Path) -> tuple[float, int]:
    """(used fraction, free bytes) of the filesystem holding the controller's data."""
    target = path if path.exists() else path.parent
    du = shutil.disk_usage(target)
    return (du.total - du.free) / du.total, du.free


def readiness(c: Container) -> dict[str, Any]:
    checks: dict[str, dict[str, Any]] = {}

    def check(name: str, ok: bool, detail: Any = None) -> None:
        checks[name] = {"ok": bool(ok), **({} if detail is None else {"detail": detail})}

    try:
        c.settings_repo.get_mode()
        check("database", True)
    except Exception as exc:  # any failure to read means not ready
        check("database", False, type(exc).__name__)

    check("reconciled", c.policy_service.reconciled_since_start)
    sensors = c.controller.sensor_health()
    stale = sorted(k for k, v in sensors.items() if v["stale"])
    check("sensors_fresh", not stale, {"stale": stale} if stale else None)
    check("telemetry_not_degraded", not c.controller.degraded())
    check("models_loaded", c.controller.model_error is None, c.controller.model_error)

    if c.simulated:  # in-memory backends are always "reachable"; nothing to probe
        check("backends_reachable", True, "simulated")
    else:
        rep = c.policy_service.last_report
        down = sorted(o.backend for o in rep.observed if not o.reachable) if rep else ["unknown"]
        check("backends_reachable", not down, {"unreachable": down} if down else None)

    used, free = disk_state(c.settings.data_dir)
    check(
        "disk_space",
        used <= DISK_MAX_USED and free >= DISK_MIN_FREE_BYTES,
        {"used_pct": round(used * 100, 1), "free_mb": round(free / 2**20)},
    )

    days = cert_days_left(c.settings.tls_cert if c.settings.tls_enabled() else None)
    if days is not None:
        check("certificate_valid", days > CERT_WARN_DAYS, {"days_left": round(days, 1)})

    return {
        "ready": all(v["ok"] for v in checks.values()),
        "version": __version__,
        "checks": checks,
    }


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class _Metrics:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self._declared: set[str] = set()

    def add(
        self, name: str, value: float | int, help_: str, kind: str = "gauge", **labels: str
    ) -> None:
        if name not in self._declared:
            self._declared.add(name)
            self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}"]
        lab = ",".join(f'{k}="{_esc(v)}"' for k, v in sorted(labels.items()))
        self.lines.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")


def render_metrics(c: Container, started: float) -> str:
    m = _Metrics()
    ctl = c.controller
    m.add("afw_info", 1, "Build information.", version=__version__)
    m.add("afw_uptime_seconds", round(time.time() - started), "Seconds since the API started.")
    ready = readiness(c)
    m.add("afw_ready", int(ready["ready"]), "1 when every readiness check passes.")
    for name, chk in ready["checks"].items():
        m.add("afw_ready_check", int(chk["ok"]), "Readiness check result (1 = ok).", check=name)
    m.add("afw_telemetry_degraded", int(ctl.degraded()), "1 when evidence is degraded.")

    snap = c.stats.snapshot()
    counts, ages = snap["counts"], snap["age_s"]
    assert isinstance(counts, dict) and isinstance(ages, dict)
    for key, n in sorted(counts.items()):
        m.add("afw_telemetry_events_total", n, "Telemetry events by type.", "counter", type=key)
    for key, age in sorted(ages.items()):
        m.add("afw_sensor_age_seconds", age, "Seconds since the sensor was last seen.", sensor=key)
    for role, h in sorted(ctl.sensor_health().items()):
        m.add("afw_sensor_stale", int(bool(h["stale"])), "1 when a sensor heartbeat is stale.",
              sensor=role)  # fmt: skip

    ticks = sorted(ctl.tick_ms)
    if ticks:
        m.add("afw_tick_milliseconds", round(ticks[len(ticks) // 2], 3),
              "Pipeline tick duration.", quantile="0.5")  # fmt: skip
        m.add("afw_tick_milliseconds", round(ticks[-1], 3), "Pipeline tick duration.",
              quantile="max")  # fmt: skip
    m.add("afw_tracked_sources", ctl.windows.tracked_sources, "Sources currently tracked.")
    m.add("afw_pending_joins", ctl.correlator.pending, "Unjoined telemetry records.")

    by_state: dict[str, int] = {}
    for p in c.policy_service.active():
        by_state[p.state.value] = by_state.get(p.state.value, 0) + 1
    for state, n in sorted(by_state.items()):
        m.add("afw_active_policies", n, "Policies owning enforcement state.", state=state)
    if not by_state:
        m.add("afw_active_policies", 0, "Policies owning enforcement state.", state="none")

    rep = c.policy_service.last_report
    for o in rep.observed if rep else []:
        m.add("afw_backend_reachable", int(o.reachable), "Enforcement backend reachable.",
              backend=o.backend)  # fmt: skip
    used, free = disk_state(c.settings.data_dir)
    m.add("afw_data_disk_used_ratio", round(used, 4), "Fraction of the data filesystem in use.")
    m.add("afw_data_disk_free_bytes", free, "Free bytes on the data filesystem.")
    if c.geoip is None:
        m.add("afw_geoip_loaded", 0, "1 when a GeoIP database is loaded.")
    else:
        geo = c.geoip.status(datetime.now(UTC))
        m.add("afw_geoip_loaded", 1, "1 when a GeoIP database is loaded.")
        m.add("afw_geoip_stale", int(bool(geo["stale"])), "1 when the release is over 45 days old.")
        if geo.get("age_days") is not None:
            m.add("afw_geoip_age_days", geo["age_days"], "Age of the installed GeoIP release.")
    days = cert_days_left(c.settings.tls_cert if c.settings.tls_enabled() else None)
    if days is not None:
        m.add("afw_tls_certificate_days_left", round(days, 1), "Days until the API cert expires.")

    import os

    import psutil

    proc = psutil.Process(os.getpid())
    m.add("afw_process_resident_bytes", proc.memory_info().rss, "Controller resident memory.")
    m.add("afw_system_memory_available_bytes", psutil.virtual_memory().available,
          "Host memory available.")  # fmt: skip
    return "\n".join(m.lines) + "\n"
