"""Map concrete request paths to declared route templates."""

from __future__ import annotations

import re
from collections.abc import Iterable

UNKNOWN_ROUTE_PREFIX = "?"
_PARAM = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F\-]{16,})$")


class RouteMatcher:
    """Exact template matching; unknown paths are coarsened so that novel routes
    remain countable without creating unbounded cardinality."""

    def __init__(self, templates: Iterable[str]) -> None:
        self._exact: set[str] = set()
        self._patterns: list[tuple[re.Pattern[str], str]] = []
        for tpl in sorted(set(templates), key=lambda t: (t.count("{"), -len(t))):
            if "{" in tpl:
                segments = [
                    "[^/]+" if _PARAM.fullmatch(seg) else re.escape(seg) for seg in tpl.split("/")
                ]
                self._patterns.append((re.compile("^" + "/".join(segments) + "$"), tpl))
            else:
                self._exact.add(tpl)

    def match(self, path: str) -> str:
        path = path.split("?", 1)[0] or "/"
        if len(path) > 1:
            path = path.rstrip("/")
        if path in self._exact:
            return path
        for pattern, tpl in self._patterns:
            if pattern.match(path):
                return tpl
        return UNKNOWN_ROUTE_PREFIX + coarsen(path)


def coarsen(path: str) -> str:
    parts = [p for p in path.split("/") if p][:3]
    norm = ["{id}" if _ID_SEGMENT.match(p) else p[:24] for p in parts]
    return "/" + "/".join(norm)


def is_unknown(route: str) -> bool:
    return route.startswith(UNKNOWN_ROUTE_PREFIX)
