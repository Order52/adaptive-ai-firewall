"""Provision FW01 (OPNsense 26.7 nano) over its serial console.

Flow: log in → /bin/sh → dump factory config.xml → transform on the host →
upload (base64 heredoc, sha256-verified) → back up and install → install the
heartbeat watchdog → reboot → wait for the login prompt.

Secrets are generated once into ``~/.config/afw/opnsense`` (outside Git).
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from afw.lab.console import SerialConsole
from afw.lab.opnsense_config import FwParams, transform
from afw.lab.pki import ensure_leaf

SECRETS = Path("~/.config/afw/opnsense").expanduser()
ASSETS = Path(__file__).resolve().parents[3] / "lab" / "opnsense"
PROMPT = r"AFWSH# $"
# Guest swap + boot hook (FW01 is a no-swap nano image; Suricata was OOM-killed under load).
RESOURCE_HOOK = "/usr/local/etc/rc.syshook.d/start/99-afw-resources"
SWAP_FILE = "/swap0"
SWAP_FSTAB = "md99 none swap sw,file=/swap0,late 0 0"


def _secret(name: str, nbytes: int) -> str:
    SECRETS.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = SECRETS / name
    if not p.exists():
        p.write_text(secrets.token_urlsafe(nbytes))
        p.chmod(0o600)
    return p.read_text().strip()


def _sha512_crypt(secret: str) -> str:
    out = subprocess.run(
        ["/usr/bin/openssl", "passwd", "-6", "-stdin"],
        input=secret,
        text=True,
        capture_output=True,
        check=True,
    )
    return out.stdout.strip()


def fw_params() -> FwParams:
    crt, key = ensure_leaf("FW01", ["10.77.50.1"])
    return FwParams(
        root_hash=_sha512_crypt(_secret("root.password", 18)),
        controller_key=_secret("controller.key", 60),
        controller_secret_hash=_sha512_crypt(_secret("controller.secret", 60)),
        provisioner_key=_secret("provisioner.key", 60),
        provisioner_secret_hash=_sha512_crypt(_secret("provisioner.secret", 60)),
        cert_pem=crt.read_text(),
        key_pem=key.read_text(),
    )


# Lab-owned Suricata includes (OPNsense renders conf.d/*.yaml into suricata.yaml):
# engine liveness for the watchdog (ADR-041) and network metadata export (ADR-042).
SURICATA_CONF_D = (
    ("afw-suricata-liveness.yaml", "afw-liveness.yaml"),
    ("afw-suricata-netflow.yaml", "afw-netflow.yaml"),
)


class FwShell:
    def __init__(self, con: SerialConsole, log: Callable[[str], None]) -> None:
        self.c = con
        self.log = log

    def login(self) -> None:
        self.c.send("\x03")  # abandon any half-entered command or heredoc
        self.c.sendline("")
        passwords = ["opnsense", _secret("root.password", 18)]
        for _ in range(6):
            i, _out = self.c.expect(
                [r"login: $", r"Password:", r"Enter an option: $", r"# $", PROMPT], 900
            )
            if i == 0:
                self.c.sendline("root")
            elif i == 1:
                self.c.sendline(passwords.pop(0) if passwords else "")
            elif i == 2:
                self.c.sendline("8")
            else:
                self.c.sendline("exec /bin/sh")
                self.c.expect([r"\$ $", r"# $"], 20)  # typed-ahead input is lost on exec
                self.c.sendline("PS1='AFWSH''# '")
                self.c.expect([PROMPT], 20)
                return
        raise RuntimeError("could not reach a root shell on FW01")

    def logout(self) -> None:
        """Leave the console at a login prompt rather than an open root shell. Best effort:
        a failure here must never fail provisioning. Exiting the shell usually goes straight
        to 'login:'; if the console menu is shown first, option 0 logs out."""
        try:
            self.c.sendline("exit")
            for _ in range(3):
                i, _out = self.c.expect([r"login: $", r"Enter an option: $"], 15)
                if i == 0:
                    return
                self.c.sendline("0")
        except Exception as exc:
            self.log(f"FW01: console logout skipped ({exc})")

    def run(self, cmd: str, timeout: float = 120, check: bool = True) -> str:
        self.c.sendline(f"{cmd}; echo __RC''=$?")
        _, out = self.c.expect([r"__RC=(\d+)\r?\n"], timeout)
        self.c.expect([PROMPT], 20)
        rc = int(re.findall(r"__RC=(\d+)", out)[-1])
        if check and rc != 0:
            raise RuntimeError(f"FW01 command failed ({rc}): {cmd}\n{out[-800:]}")
        body = out.split("\n", 1)[1] if "\n" in out else ""
        return body.rsplit("__RC=", 1)[0]

    def read_file(self, path: str) -> bytes:
        out = self.run(f"echo __B''S; openssl base64 -in {path}; echo __B''E")
        m = re.search(r"__BS\r?\n(.*?)__BE", out, re.S)
        if m is None:
            raise RuntimeError(f"could not read {path}")
        return base64.b64decode("".join(m.group(1).split()))

    def write_file(self, path: str, data: bytes, mode: str = "0644") -> None:
        tmp = f"{path}.afw-upload"
        lines = base64.encodebytes(data).decode().splitlines()
        # Line-by-line with echo wait: the FreeBSD tty drops bulk pasted input.
        self.c.sendline(f"cat > {tmp}.b64 <<'__AFW_EOF'")
        self.c.expect([r"> $"], 20)
        for line in lines:
            self.c.sendline(line)
            self.c.expect([re.escape(line[-16:]) + r"\r?\n> $"], 20)
        self.c.sendline("__AFW_EOF")
        self.c.expect([PROMPT], 60)
        digest = hashlib.sha256(data).hexdigest()
        out = self.run(f"openssl base64 -d -in {tmp}.b64 -out {tmp} && sha256 -q {tmp}")
        if digest not in out:
            raise RuntimeError(f"upload checksum mismatch for {path}")
        self.run(f"chmod {mode} {tmp} && mv {tmp} {path} && rm -f {tmp}.b64")


def ensure_resources(sh: FwShell, log: Callable[[str], None]) -> None:
    """Persistent guest swap + the boot hook that mounts it and keeps cron (the heartbeat
    watchdog) running. Idempotent. Short commands only: the serial console drops long lines."""
    sh.run("mkdir -p /usr/local/etc/rc.syshook.d/start")
    sh.write_file(RESOURCE_HOOK, (ASSETS / "afw-resources.syshook").read_bytes(), "0755")
    sh.run(f"[ -f {SWAP_FILE} ] || dd if=/dev/zero of={SWAP_FILE} bs=1m count=1024")
    sh.run(f"chmod 600 {SWAP_FILE}")
    sh.run(f"grep -q '^md99 ' /etc/fstab || echo '{SWAP_FSTAB}' >> /etc/fstab")
    sh.run(RESOURCE_HOOK)
    log("FW01: guest swap + boot hook installed")


def _suricata_healthy(sh: FwShell, old_pid: str, wait_s: int = 180) -> bool:
    """A *new* suricata process (pid != ``old_pid``) that has written stats.log (30 s
    interval, ADR-041) after it was first seen. The stopping process also writes
    stats.log, so a fresh file alone proves nothing (2026-10-28 18:52Z).
    Short commands only: the serial console drops long lines."""
    seen_at: int | None = None
    for _ in range(wait_s // 10):
        pid = sh.run("pgrep -x suricata || true", check=False).strip()
        if pid and pid != old_pid:
            if seen_at is None:
                seen_at = int(sh.run("date +%s").strip())
            else:
                mtime = sh.run("stat -f %m /var/log/suricata/stats.log", check=False).strip()
                if mtime.isdigit() and int(mtime) > seen_at:
                    return True
        time.sleep(10)
    return False


def provision(
    host: str, port: int, log: Callable[[str], None] = print, force: bool = False
) -> None:
    con = SerialConsole(host, port)
    try:
        sh = FwShell(con, log)
        sh.login()
        log("FW01: root shell")
        current = sh.read_file("/conf/config.xml")
        already = b"<hostname>FW01</hostname>" in current
        if already and not force:
            log("FW01: config already provisioned; refreshing watchdog only")
        else:
            new = transform(current, fw_params())
            sh.run("mkdir -p /conf/backup && cp /conf/config.xml /conf/backup/config-pre-afw.xml")
            sh.write_file("/conf/afw-config.xml", new, "0640")
            sh.run("php -r 'exit(simplexml_load_file(\"/conf/afw-config.xml\") ? 0 : 1);'")
            sh.run("mv /conf/afw-config.xml /conf/config.xml && rm -f /tmp/config.cache")
            log(f"FW01: config installed ({len(new)} bytes)")
        sh.write_file(
            "/usr/local/sbin/afw-watchdog.sh", (ASSETS / "afw-watchdog.sh").read_bytes(), "0755"
        )
        sh.run("mkdir -p /usr/local/etc/cron.d")
        sh.write_file(
            "/usr/local/etc/cron.d/afw-watchdog",
            (ASSETS / "afw-watchdog.cron").read_bytes(),
            "0644",
        )
        log("FW01: watchdog installed")
        ensure_resources(sh, log)
        changed = []
        for asset, name in SURICATA_CONF_D:
            body = (ASSETS / asset).read_bytes()
            conf = f"/usr/local/etc/suricata/conf.d/{name}"
            have = sh.run(f"[ -f {conf} ] && sha256 -q {conf} || echo none").strip()
            if have != hashlib.sha256(body).hexdigest():
                sh.write_file(conf, body, "0644")
                changed.append(name)
        if changed:
            sh.run("configctl template reload OPNsense/IDS", timeout=120)  # renders conf.d
            old_pid = sh.run("pgrep -x suricata || true", check=False).strip()
            sh.run("configctl ids restart", timeout=300)
            if not _suricata_healthy(sh, old_pid):
                # never leave the IDS down: drop what changed and go back
                for name in changed:
                    sh.run(f"rm -f /usr/local/etc/suricata/conf.d/{name}")
                sh.run("configctl template reload OPNsense/IDS", timeout=120)
                sh.run("configctl ids restart", timeout=300)
                raise RuntimeError(
                    f"Suricata unhealthy after {', '.join(changed)}; removed and restarted "
                    f"(healthy now: {_suricata_healthy(sh, '')})"
                )
            log(f"FW01: Suricata conf.d updated ({', '.join(changed)}), IDS restarted")
        if not already or force:
            con.sendline("reboot")
            log("FW01: rebooting")
            con.expect([r"login: $"], 900)
            log("FW01: back at login prompt")
        else:
            sh.logout()
    finally:
        con.close()
