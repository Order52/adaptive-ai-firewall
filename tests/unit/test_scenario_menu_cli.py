"""`afw scenario menu`: a picker over the registry that only records ground truth
(begin/end via the journal) -- it never runs a tool itself. The actual attack
command stays the operator's, typed by hand on ATK01; the menu just prints the
scenario's `team_tooling` hint and the run window.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from afw.cli import app

runner = CliRunner()


def _isolate_home(monkeypatch, tmp_path: Path) -> None:
    # The journal lives under $HOME/.config/afw/runs; keep tests off the real one.
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".config" / "afw").mkdir(parents=True)


def test_menu_cancel_lists_scenarios_and_takes_no_action(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    result = runner.invoke(app, ["scenario", "menu"], input="0\n")
    assert result.exit_code == 0
    assert "web-bruteforce-login" in result.output
    assert "cancelled" in result.output
    # No run was recorded.
    assert not list((tmp_path / ".config" / "afw" / "runs").glob("*")) or not any(
        p.is_file() for p in (tmp_path / ".config" / "afw" / "runs").rglob("*")
    )


def test_menu_begin_prints_tooling_hint_and_run_window_not_a_command_it_runs(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    # scenario 1 = web-bruteforce-login; confirm begin; don't end from here.
    result = runner.invoke(
        app,
        ["scenario", "menu"],
        input="1\noperator-x\nnotes here\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert "Suggested tooling" in result.output
    assert "hydra" in result.output.lower()  # from config/scenarios.yaml's own hint
    assert "Now, on ATK01, run the tool above" in result.output
    assert "afw scenario end" in result.output
    # Ground truth was recorded; the CLI itself launched nothing.
    list_result = runner.invoke(app, ["scenario", "list"])
    assert "active run:" in list_result.output
    assert "web-bruteforce-login" in list_result.output


def test_menu_refuses_second_run_while_one_is_active(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    runner.invoke(app, ["scenario", "menu"], input="1\nop\nnotes\ny\n")
    # Re-entering the menu offers to end the active run; decline, then it stops.
    result = runner.invoke(app, ["scenario", "menu"], input="n\n")
    assert "Run already active" in result.output
    assert "Leave it running" in result.output
