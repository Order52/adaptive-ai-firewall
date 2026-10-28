"""Response-policy states and the shared-address guard (N6, ADR-043).

``ResponseState`` names *how well supported* the case against a source is. It is
derived from the assessment alone and recorded on every proposed intent
(``state:<name>`` reason code), so an operator can see why a response was or was not
traffic-affecting:

* ``normal``: below the watch band.
* ``unfamiliar``: only behavioural anomaly evidence. Unusual is not malicious, so
  this never authorizes more than observation (except the legacy two-detector
  agreement rule while ``safety.behavior_only_rate_limit`` is on).
* ``suspicious``: corroborated evidence at the watch or rate-limit level.
* ``strongly_supported``: block band with the required independent categories.
* ``high_risk``: escalate band with the required independent categories.

**Shared addresses.** One address can carry many people (NAT, proxy, campus
gateway). Blocking it for what one account did punishes everyone behind it. An
address is treated as shared when several distinct accounts logged in successfully
from it recently; a block proposed for a shared address is downgraded to a strict
rate limit that always needs human approval (never automatic). A human can still
block it explicitly.

Limitation (documented in ADR-043): an attacker who has taken over several accounts
from one address also looks "shared". The downgrade still contains the source and
puts the decision in front of a human, which is the intended failure mode.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta
from enum import StrEnum

from afw.config import LabConfig
from afw.domain.events import AuthOutcome, HttpObservation
from afw.domain.risk import EvidenceCategory, RiskAssessment

SHARED_ADDRESS_GUARD = "shared_address_guard"


class ResponseState(StrEnum):
    NORMAL = "normal"
    UNFAMILIAR = "unfamiliar"
    SUSPICIOUS = "suspicious"
    STRONGLY_SUPPORTED = "strongly_supported"
    HIGH_RISK = "high_risk"


def response_state(ra: RiskAssessment, cfg: LabConfig) -> ResponseState:
    r = cfg.risk
    cats = set(ra.corroborating_categories)
    if ra.score < r.watch:
        return ResponseState.NORMAL
    if cats <= {EvidenceCategory.BEHAVIOR_ML} or ra.view == "ids_only":
        return ResponseState.UNFAMILIAR
    corroborated = len(cats) >= cfg.safety.require_corroboration_for_block
    if corroborated and ra.score >= r.escalate:
        return ResponseState.HIGH_RISK
    if corroborated and ra.score >= r.block:
        return ResponseState.STRONGLY_SUPPORTED
    return ResponseState.SUSPICIOUS


def accounts_behind(source_obs: Iterable[HttpObservation], now: datetime, window: timedelta) -> int:
    """Distinct accounts that logged in successfully from one address within ``window``."""
    return len(
        {
            o.username_hash
            for o in source_obs
            if o.auth_outcome is AuthOutcome.SUCCESS
            and o.username_hash
            and now - window <= o.observed_at <= now
        }
    )
