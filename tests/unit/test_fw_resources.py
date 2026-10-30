"""FW01 resource fix must survive a rebuild or firmware upgrade (OOM, 2026-10-29).

The running fix (2560 MB RAM + 1 GB swap + boot hook) used to exist only on the live VM:
the topology still said 1536 MB and the hook was a hand-written file. These tests pin the
source of truth so a rebuild cannot silently bring the Suricata OOM back.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from afw.lab import provision_fw as pf

ROOT = Path(__file__).resolve().parents[2]


class FakeShell:
    def __init__(self) -> None:
        self.cmds: list[str] = []
        self.files: dict[str, tuple[bytes, str]] = {}

    def run(self, cmd: str, timeout: float = 120, check: bool = True) -> str:
        self.cmds.append(cmd)
        return ""

    def write_file(self, path: str, data: bytes, mode: str = "0644") -> None:
        self.files[path] = (data, mode)


def test_fw01_ram_in_the_topology_source_is_not_the_oom_value():
    topo = yaml.safe_load((ROOT / "lab/gns3/topology.yaml").read_text())
    assert topo["nodes"]["FW01"]["ram"] >= 2560  # 1536 MB OOM-killed Suricata under load


def test_boot_hook_mounts_swap_and_keeps_cron_running():
    body = (ROOT / "lab/opnsense/afw-resources.syshook").read_text()
    assert body.startswith("#!/bin/sh")
    assert "swapon -aL" in body
    assert "pgrep -q cron || service cron onestart" in body


def test_ensure_resources_installs_hook_swapfile_and_fstab_idempotently():
    sh, logged = FakeShell(), []
    pf.ensure_resources(sh, logged.append)  # type: ignore[arg-type]
    data, mode = sh.files[pf.RESOURCE_HOOK]
    assert mode == "0755" and b"swapon -aL" in data
    joined = "\n".join(sh.cmds)
    # the 1 GB swap file is only created when absent, and kept private
    assert f"[ -f {pf.SWAP_FILE} ] || dd if=/dev/zero of={pf.SWAP_FILE} bs=1m count=1024" in joined
    assert f"chmod 600 {pf.SWAP_FILE}" in joined
    # the fstab line is only appended when no md99 entry exists
    assert f"grep -q '^md99 ' /etc/fstab || echo '{pf.SWAP_FSTAB}' >> /etc/fstab" in joined
    # and the hook is run once so the swap is live without a reboot
    assert sh.cmds[-1] == pf.RESOURCE_HOOK
    assert logged and "swap" in logged[0]


def test_provisioning_calls_ensure_resources_and_logs_out_when_not_rebooting():
    src = (ROOT / "src/afw/lab/provision_fw.py").read_text()
    assert "ensure_resources(sh, log)" in src
    assert "sh.logout()" in src


class ScriptedConsole:
    """Feeds expect() results in order; records what was sent."""

    def __init__(self, replies: list[int]) -> None:
        self.replies, self.sent = list(replies), []

    def sendline(self, s: str) -> None:
        self.sent.append(s)

    def expect(self, patterns: list[str], timeout: float = 0):
        return self.replies.pop(0), ""


def _shell(replies):
    msgs: list[str] = []
    return pf.FwShell(ScriptedConsole(replies), msgs.append), msgs  # type: ignore[arg-type]


def test_logout_goes_straight_to_the_login_prompt():
    sh, msgs = _shell([0])  # 'login:' right after exit
    sh.logout()
    assert sh.c.sent == ["exit"] and not msgs


def test_logout_uses_menu_option_zero_when_the_menu_appears_first():
    sh, msgs = _shell([1, 0])  # menu, then 'login:'
    sh.logout()
    assert sh.c.sent == ["exit", "0"] and not msgs


def test_logout_failure_never_fails_provisioning():
    class Boom(ScriptedConsole):
        def expect(self, patterns, timeout=0):
            raise TimeoutError("no prompt")

    msgs: list[str] = []
    sh = pf.FwShell(Boom([]), msgs.append)  # type: ignore[arg-type]
    sh.logout()  # must not raise
    assert msgs and "skipped" in msgs[0]
