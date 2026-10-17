"""Client for the WAF-local policy helper (waf/helper/afw_waf_helper.py).

The helper accepts only the typed desired state and renders it through
reviewed templates; there is no channel for free-form Nginx/ModSecurity text.
"""

from __future__ import annotations

from ipaddress import IPv4Address

import httpx

from afw.config import WafHelperConfig
from afw.domain.policy import ContractTarget, PolicyKind, RateProfile
from afw.ports.enforcement import ApplyReport, DesiredState, ObservedState


class WafHelperBackend:
    name = "waf"
    handles = frozenset({PolicyKind.WAF_DENY, PolicyKind.RATE_LIMIT, PolicyKind.HTTP_CONTRACT})

    def __init__(self, cfg: WafHelperConfig) -> None:
        verify: bool | str = str(cfg.ca_file) if cfg.ca_file and cfg.verify_tls else cfg.verify_tls
        self.client = httpx.Client(
            base_url=cfg.base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {cfg.token_file.read_text().strip()}"},
            verify=verify,
            timeout=cfg.timeout_s,
        )

    def observe(self) -> ObservedState:
        try:
            r = self.client.get("/v1/state")
            r.raise_for_status()
            d = r.json()
            if d.get("revision") and not d.get("revision_active"):
                # Stored state is not what nginx serves: do not report it as enforced.
                return ObservedState(
                    backend=self.name,
                    reachable=False,
                    revision=str(d.get("revision")),
                    error="served policy revision does not match the helper's state",
                )
            return ObservedState(
                backend=self.name,
                reachable=True,
                waf_denied_sources=frozenset(IPv4Address(i) for i in d["denied_sources"]),
                rate_limited={IPv4Address(k): RateProfile(v) for k, v in d["rate_limited"].items()},
                contracts=tuple(ContractTarget.model_validate(c) for c in d["contracts"]),
                revision=str(d.get("revision")),
            )
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            return ObservedState(backend=self.name, reachable=False, error=str(exc))

    def reconcile(self, desired: DesiredState) -> ApplyReport:
        body = {
            "denied_sources": sorted(map(str, desired.waf_denied_sources)),
            "rate_limited": {str(k): v.value for k, v in sorted(desired.rate_limited.items())},
            "contracts": [c.model_dump(mode="json") for c in desired.contracts],
        }
        try:
            r = self.client.put("/v1/state", json=body)
        except httpx.TimeoutException as exc:
            return ApplyReport(backend=self.name, ok=False, error=f"timeout: {exc}", ambiguous=True)
        except httpx.HTTPError as exc:
            return ApplyReport(backend=self.name, ok=False, error=str(exc), ambiguous=True)
        if r.status_code != 200:
            return ApplyReport(
                backend=self.name, ok=False, error=f"{r.status_code}: {r.text[:300]}"
            )
        d = r.json()
        return ApplyReport(
            backend=self.name,
            ok=bool(d.get("ok")),
            error=None if d.get("ok") else str(d.get("error")),
        )

    def kill_states(self, source: IPv4Address) -> int:
        return 0
