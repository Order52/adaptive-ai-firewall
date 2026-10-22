"""Zone-isolation verification run from inside the lab guests (gate G1).

Each check opens a TCP connection (or ICMP echo) from a guest. "open" and
"refused" both prove the packet crossed FW01; "filtered" (timeout) proves it was
dropped. Results are compared with the intended policy, not just printed.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

SSH_CONFIG = Path("~/.config/afw/ssh_config").expanduser()


@dataclass(frozen=True)
class Check:
    src: str
    dst: str
    port: int | None  # None = ICMP echo
    allowed: bool
    why: str


CHECKS: list[Check] = [
    # client zones → only the WAF's HTTPS
    Check("atk01", "10.77.30.10", 443, True, "ATTACK to WAF HTTPS"),
    Check("usr01", "10.77.30.10", 443, True, "USERS to WAF HTTPS"),
    Check("atk01", "10.77.40.10", 8000, False, "ATTACK bypassing WAF to APP"),
    Check("usr01", "10.77.40.10", 8000, False, "USERS bypassing WAF to APP"),
    Check("atk01", "10.77.30.10", 22, False, "ATTACK to WAF SSH"),
    Check("atk01", "10.77.50.10", 22, False, "ATTACK to CTRL01"),
    Check("atk01", "10.77.50.10", 5514, False, "ATTACK forging telemetry"),
    Check("atk01", "10.77.10.1", 443, False, "ATTACK to FW web GUI"),
    Check("atk01", "10.77.20.10", 22, False, "ATTACK to USERS"),
    Check("usr01", "10.77.10.10", 22, False, "USERS to ATTACK"),
    Check("atk01", "10.77.10.1", None, True, "ATTACK ping own gateway"),
    Check("atk01", "1.1.1.1", 443, True, "ATTACK to Internet (egress allowed)"),
    Check("atk01", "10.77.30.10", None, False, "ATTACK ping WAF (only HTTPS allowed)"),
    # DMZ
    Check("waf01", "10.77.40.10", 8000, True, "WAF to APP"),
    Check("waf01", "10.77.50.10", 5514, True, "WAF telemetry to CTRL01"),
    Check("waf01", "10.77.50.10", 22, False, "WAF to CTRL01 SSH"),
    Check("waf01", "10.77.20.10", 22, False, "WAF to USERS"),
    Check("waf01", "1.1.1.1", 443, True, "WAF to Internet (egress allowed)"),
    # APP
    Check("app01", "10.77.50.10", 5514, True, "APP telemetry to CTRL01"),
    Check("app01", "10.77.30.10", 443, False, "APP to WAF"),
    Check("app01", "10.77.50.10", 22, False, "APP to CTRL01 SSH"),
    Check("app01", "1.1.1.1", 443, True, "APP to Internet (egress allowed)"),
    Check("app01", "10.77.60.10", 5432, True, "APP to DB (only path to the database)"),
    # DB tier — reachable only from APP, initiates nothing
    Check("usr01", "10.77.60.10", 5432, False, "USERS bypassing app to DB"),
    Check("atk01", "10.77.60.10", 5432, False, "ATTACK bypassing app to DB"),
    Check("waf01", "10.77.60.10", 5432, False, "WAF bypassing app to DB"),
    Check("db01", "10.77.40.10", 8000, False, "DB back-connecting to APP"),
    Check("db01", "10.77.50.10", 5514, False, "DB forging telemetry"),
    Check("db01", "1.1.1.1", 443, True, "DB to Internet (egress allowed)"),
    Check("db01", "10.77.60.1", None, True, "DB ping own gateway"),
    # MGMT reaches everything it manages
    Check("ctrl01", "10.77.30.10", 22, True, "CTRL01 to WAF SSH"),
    Check("ctrl01", "10.77.40.10", 22, True, "CTRL01 to APP SSH"),
    Check("ctrl01", "10.77.20.10", 22, True, "CTRL01 to USERS (probe agent path)"),
    Check("ctrl01", "10.77.60.10", 22, True, "CTRL01 to DB SSH (management)"),
    Check("ctrl01", "10.77.50.1", 443, True, "CTRL01 to FW API"),
]

_PROBE = (
    # ICMP via a raw socket: the minimal image has no ping binary.
    'if [ -z "$P" ]; then sudo python3 -c "$ICMP" $D && echo open || echo filtered; '
    'else out=$(timeout 4 bash -c "exec 3<>/dev/tcp/$D/$P" 2>&1); rc=$?; '
    'if [ $rc -eq 0 ]; then echo open; elif echo "$out" | grep -qi refused; then echo refused; '
    "else echo filtered; fi; fi"
)


_ICMP = (
    "import socket,struct,sys\n"
    "def ck(b):\n"
    " s=sum(struct.unpack('!4H',b));s=(s&0xffff)+(s>>16);s+=s>>16;return ~s&0xffff\n"
    "h=struct.pack('!BBHHH',8,0,0,0x4146,1);h=struct.pack('!BBHHH',8,0,ck(h),0x4146,1)\n"
    "s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP);s.settimeout(3)\n"
    "s.sendto(h,(sys.argv[1],0))\n"
    "try:\n while True:\n  d,a=s.recvfrom(1024)\n"
    "  if a[0]==sys.argv[1] and d[20]==0: sys.exit(0)\n"
    "except OSError: sys.exit(1)\n"
)


def run_check(c: Check) -> str:
    cmd = f"ICMP={shlex.quote(_ICMP)}; D={c.dst} P={c.port or ''}; {_PROBE}"
    res = subprocess.run(  # noqa: S603
        ["/usr/bin/ssh", "-F", str(SSH_CONFIG), "-o", "BatchMode=yes", c.src, cmd],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return res.stdout.strip() or f"error: {res.stderr.strip()[:80]}"


def verify() -> list[tuple[Check, str, bool]]:
    out = []
    for c in CHECKS:
        got = run_check(c)
        reached = got in ("open", "refused")
        ok = reached == c.allowed and not got.startswith("error")
        out.append((c, got, ok))
    return out
