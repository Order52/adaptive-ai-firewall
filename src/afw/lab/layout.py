"""Professional, reproducible GNS3 canvas layout + zone annotations.

Idempotent: re-running places every node at the same coordinates, assigns a
role-appropriate symbol, and redraws the zone boxes/labels. The logical flow is

    MANAGEMENT (top: CTRL01 = AI-Adaptive-Firewall)
        |
      FW01 (OPNsense, centre) --- ATTACK (left) / USERS (right)
        |
      DMZ / WAF01
        |
      APPLICATION / APP01 (bottom)

so the canvas reads top-to-bottom as the real traffic path, with the management
plane visually separated. This only moves/labels existing nodes; it never
creates, deletes or rewires devices.
"""

from __future__ import annotations

from afw.lab.gns3 import Gns3Client

PROJECT = "AI-Adaptive-Firewall"

_SRV = ":/symbols/server.svg"
_SW = ":/symbols/ethernet_switch.svg"
_PC = ":/symbols/computer.svg"
_FW = ":/symbols/firewall.svg"
_CLOUD = ":/symbols/cloud.svg"

# name -> (x, y, symbol); origin centre, y grows downward.
LAYOUT: dict[str, tuple[int, int, str]] = {
    "CTRL01": (-30, -540, _SRV),
    "SW-MGMT": (-20, -360, _SW),
    "HOST-MGMT": (-250, -360, _CLOUD),
    "MAINT-NAT": (190, -360, _CLOUD),
    "FW01": (-20, -180, _FW),
    "SW-ATTACK": (-330, -180, _SW),
    "ATK01": (-550, -185, _PC),
    "SW-USERS": (290, -180, _SW),
    "USR01": (510, -185, _PC),
    "SW-DMZ": (-20, -20, _SW),
    "WAF01": (-30, 120, _SRV),
    "SW-APP": (-20, 260, _SW),
    "APP01": (-30, 400, _SRV),
    "SW-DB": (-20, 540, _SW),
    "DB01": (-30, 680, _SRV),
}

_BLUE, _RED, _GREEN, _AMBER, _TEAL, _VIOLET, _GREY, _INK = (
    "#2a78d6",
    "#d03b3b",
    "#0ca30c",
    "#e08a1e",
    "#1b9e9e",
    "#6250d6",
    "#555555",
    "#0b0b0b",
)


def _rect_svg(w: int, h: int, color: str) -> str:
    return (
        f'<svg height="{h}" width="{w}"><rect height="{h}" width="{w}" '
        f'fill="{color}" fill-opacity="0.10" stroke="{color}" stroke-width="2" '
        f'stroke-dasharray="12,6" rx="12"/></svg>'
    )


def _text_svg(text: str, color: str, size: int, weight: str) -> str:
    w = max(220, int(len(text) * size * 0.62))
    h = size + 12
    return (
        f'<svg height="{h}" width="{w}"><text x="4" y="{size}" font-family="Noto Sans" '
        f'font-size="{size}" font-weight="{weight}" fill="{color}">{text}</text></svg>'
    )


# (x, y, w, h, color) zone boxes
_ZONES = [
    (-360, -600, 640, 320, _BLUE),
    (-640, -270, 360, 185, _RED),
    (240, -270, 360, 185, _GREEN),
    (-170, -90, 320, 300, _AMBER),
    (-170, 215, 320, 260, _TEAL),
    (-170, 505, 320, 250, _VIOLET),
]
# (x, y, text, color, size, weight) labels
_LABELS = [
    (-360, -680, "AI-ADAPTIVE-FIREWALL — ISOLATED GNS3 LABORATORY", _INK, 22, "bold"),
    (
        -360,
        -650,
        "Flow: clients -> FW01 -> WAF (DMZ) -> APP -> DB. Management plane isolated (top).",
        _GREY,
        12,
        "normal",
    ),
    (-352, -596, "MANAGEMENT ZONE  (10.77.50.0/24)", _BLUE, 18, "bold"),
    (-130, -572, "CTRL01 — AI-Adaptive-Firewall  (AI / ML / MCP / Dashboard)", _BLUE, 13, "bold"),
    (-632, -266, "ATTACK ZONE (10.77.10.0/24)", _RED, 14, "bold"),
    (248, -266, "USERS ZONE (10.77.20.0/24)", _GREEN, 14, "bold"),
    (-162, -86, "DMZ (10.77.30.0/24) — WAF01 / OWASP CRS", _AMBER, 13, "bold"),
    (-162, 219, "APPLICATION (10.77.40.0/24) — APP01", _TEAL, 13, "bold"),
    (-162, 509, "DATABASE (10.77.60.0/24) — DB01 (PostgreSQL)", _VIOLET, 13, "bold"),
    (80, -176, "FW01 — OPNsense (pf + Suricata)", _GREY, 13, "bold"),
]


def apply_layout(client: Gns3Client | None = None, project: str = PROJECT) -> dict[str, int]:
    """Reposition nodes and redraw zone annotations. Returns counts."""
    c = client or Gns3Client.from_env()
    proj = c.find_project(project)
    if proj is None:
        raise RuntimeError(f"GNS3 project {project!r} not found")
    pid = str(proj["project_id"])
    nodes = c.node_by_name(pid)
    moved = 0
    for name, (x, y, sym) in LAYOUT.items():
        n = nodes.get(name)
        if n is None:
            continue
        c.update_node(pid, str(n["node_id"]), {"x": x, "y": y, "symbol": sym})
        moved += 1
    for d in c._call("GET", f"/projects/{pid}/drawings"):
        c._call("DELETE", f"/projects/{pid}/drawings/{d['drawing_id']}")
    drawn = 0
    for x, y, w, h, color in _ZONES:
        c._call(
            "POST",
            f"/projects/{pid}/drawings",
            {"svg": _rect_svg(w, h, color), "x": x, "y": y, "z": 0},
        )
        drawn += 1
    for x, y, text, color, size, weight in _LABELS:
        c._call(
            "POST",
            f"/projects/{pid}/drawings",
            {"svg": _text_svg(text, color, size, weight), "x": x, "y": y, "z": 2},
        )
        drawn += 1
    return {"nodes_moved": moved, "annotations_drawn": drawn}
