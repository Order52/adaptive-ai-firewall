"""Account-aware authentication evidence (A3, ADR-044).

Per source address and per account, the controller keeps the login outcomes the
application reported within a lookback. An account's *streak* is the number of failed
logins from the source since that account last logged in successfully from it. A user
who mistypes and then logs in clears their streak; a guesser who never gets in keeps
building it at any speed slower than the lookback allows.

Only attempts the application answered count (they carry an ``auth_outcome``). Requests
the WAF refused (429/403) never reached the application and are counted separately, so
a login control cannot feed its own escalation. An answered attempt without a username
hash counts under one pseudo-account: missing telemetry cannot hide guessing.

Evidence (protocol ``A3_AUTH_CONTROLS.md`` §2.1), only for a source that had a failed
or successful login in the last ``recent`` interval:

* ``account_guessing``: some account's streak >= 5;
* ``credential_spraying``: >= 3 accounts with a streak, together >= 5 failures;
* ``success_after_guessing``: a recent success for an account whose streak was >= 5.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address

from afw.domain.events import AuthOutcome, HttpObservation
from afw.domain.risk import EvidenceCategory, EvidenceItem

LOOKBACK_S = 900
RECENT_S = 30
GUESSING_STREAK = 5
SPRAY_ACCOUNTS = 3
SPRAY_FAILURES = 5
_UNKNOWN_ACCOUNT = "?"
_MAX_EVENTS_PER_SOURCE = 5000


@dataclass(frozen=True)
class _Attempt:
    at: datetime
    account: str
    success: bool
    request_id: str


@dataclass
class _Source:
    attempts: deque[_Attempt] = field(default_factory=lambda: deque(maxlen=_MAX_EVENTS_PER_SOURCE))
    rejected: deque[datetime] = field(default_factory=lambda: deque(maxlen=_MAX_EVENTS_PER_SOURCE))


class AuthTracker:
    def __init__(
        self,
        login_routes: Iterable[str],
        lookback_s: int = LOOKBACK_S,
        recent_s: int = RECENT_S,
    ) -> None:
        self.routes = frozenset(login_routes)
        self.lookback = timedelta(seconds=lookback_s)
        self.recent = timedelta(seconds=recent_s)
        self._src: dict[IPv4Address, _Source] = defaultdict(_Source)

    # -- input -----------------------------------------------------------------
    def add(self, o: HttpObservation) -> None:
        """Feed observations in time order (per source)."""
        if o.route not in self.routes or o.method != "POST":
            return
        s = self._src[o.client_ip]
        if o.auth_outcome is None:
            if o.status in (403, 429) and not o.reached_backend:
                s.rejected.append(o.observed_at)
            return
        s.attempts.append(
            _Attempt(
                at=o.observed_at,
                account=o.username_hash or _UNKNOWN_ACCOUNT,
                success=o.auth_outcome is AuthOutcome.SUCCESS,
                request_id=o.request_id,
            )
        )

    def prune(self, now: datetime) -> None:
        cut = now - self.lookback
        for ip in list(self._src):
            s = self._src[ip]
            while s.attempts and s.attempts[0].at < cut:
                s.attempts.popleft()
            while s.rejected and s.rejected[0] < cut:
                s.rejected.popleft()
            if not s.attempts and not s.rejected:
                del self._src[ip]

    # -- queries ---------------------------------------------------------------
    def _window(self, src: IPv4Address, now: datetime) -> list[_Attempt]:
        s = self._src.get(src)
        if s is None:
            return []
        lo = now - self.lookback
        return sorted((a for a in s.attempts if lo <= a.at <= now), key=lambda a: a.at)

    @staticmethod
    def _streaks(attempts: list[_Attempt]) -> dict[str, int]:
        streak: dict[str, int] = {}
        for a in attempts:
            streak[a.account] = 0 if a.success else streak.get(a.account, 0) + 1
        return {k: v for k, v in streak.items() if v > 0}

    def streaks(self, src: IPv4Address, now: datetime) -> dict[str, int]:
        return self._streaks(self._window(src, now))

    def failures_since(self, src: IPv4Address, since: datetime, now: datetime) -> int:
        s = self._src.get(src)
        if s is None:
            return 0
        return sum(1 for a in s.attempts if since <= a.at <= now and not a.success)

    def active_sources(self, now: datetime) -> set[IPv4Address]:
        """Sources with an answered login attempt in the recent interval."""
        lo = now - self.recent
        return {ip for ip, s in self._src.items() if s.attempts and lo < s.attempts[-1].at <= now}

    def evidence(self, src: IPv4Address, now: datetime) -> list[EvidenceItem]:
        attempts = self._window(src, now)
        recent_lo = now - self.recent
        if not any(a.at > recent_lo for a in attempts):
            return []
        candidates: list[tuple[float, str, str]] = []
        # success after guessing: streak just before a recent success
        streak: dict[str, int] = {}
        for a in attempts:
            if a.success:
                if a.at > recent_lo and streak.get(a.account, 0) >= GUESSING_STREAK:
                    candidates.append(
                        (
                            25.0,
                            "success_after_guessing",
                            f"account logged in after {streak[a.account]} failed attempts",
                        )
                    )
                streak[a.account] = 0
            else:
                streak[a.account] = streak.get(a.account, 0) + 1
        open_ = {k: v for k, v in streak.items() if v > 0}
        failed_recently = any(a.at > recent_lo and not a.success for a in attempts)
        if failed_recently and open_:
            top = max(open_.values())
            if top >= GUESSING_STREAK:
                candidates.append(
                    (
                        15.0 + min(10.0, top - GUESSING_STREAK),
                        "account_guessing",
                        f"{top} consecutive failed logins on one account",
                    )
                )
            total = sum(open_.values())
            if len(open_) >= SPRAY_ACCOUNTS and total >= SPRAY_FAILURES:
                candidates.append(
                    (
                        20.0 + min(10.0, total - SPRAY_FAILURES),
                        "credential_spraying",
                        f"{total} failed logins across {len(open_)} accounts without success",
                    )
                )
        if not candidates:
            return []
        points, code, why = max(candidates)
        refs = tuple(a.request_id for a in attempts if not a.success or a.at > recent_lo)[-10:]
        return [
            EvidenceItem(
                category=EvidenceCategory.AUTH,
                code=code,
                points=points,
                detail=f"{why} within {int(self.lookback.total_seconds())}s (account-aware, A3)",
                observed={
                    "max_streak": float(max(open_.values(), default=0)),
                    "accounts_failing": float(len(open_)),
                    "failures_open": float(sum(open_.values())),
                },
                refs=refs,
            )
        ]
