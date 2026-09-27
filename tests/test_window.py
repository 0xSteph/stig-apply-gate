from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from findings.cli import main
from findings.window import rehearse

LAB = Path("fixtures/lab")
TODAY = "2026-09-27"


def _case(report: dict, case_id: str) -> dict:
    return next(item for item in report["cases"] if item["id"] == case_id)


def _row(case: dict, control: str) -> dict:
    return next(item for item in case["rows"] if item["control"] == control)


def test_rehearse_moves_the_three_facts_and_holds_operations():
    report = rehearse(LAB, today=date(2026, 9, 27))
    assert report["handoff_ready"] is False
    stories = {(item["host_short"], item["control"]): item for item in report["stories"]}
    assert stories[("rhel-repo01", "RHEL-08-010370")]["action"] == "probe"
    assert stories[("wsus01", "WN22-00-000380")]["action"] == "refuse"
    assert stories[("ad01", "WN22-DC-000060")]["action"] == "refuse"
    assert stories[("esxi01", "ESXI-80-000124")]["action"] == "refuse"
    assert stories[("rhel-mission01", "RHEL-08-010550")]["action"] == "bundle"

    backup = _row(_case(report, "wsus-backup"), "WN22-00-000380")
    assert backup["before_action"] == "refuse"
    assert "backup" in backup["before_reason"].lower()
    assert backup["after_action"] == "window"
    assert "console" in backup["after_reason"].lower()

    expired = _row(_case(report, "exception-lapsed"), "ESXI-80-000193")
    assert expired["before_action"] == "refuse"
    assert "EX-014" in expired["before_reason"]
    assert expired["after_action"] == "refuse"
    assert "EX-014" not in expired["after_reason"]

    signed = _row(_case(report, "signing-key"), "RHEL-08-010370")
    assert signed["before_action"] == "probe"
    assert signed["after_action"] == "allow"
    localpkg = _row(_case(report, "signing-key"), "RHEL-08-010371")
    assert localpkg["after_action"] == "allow"

    held = _row(_case(report, "operations-hold"), "RHEL-08-010370")
    assert held["after_action"] == "refuse"
    assert "operations" in held["after_reason"].lower()


def test_rpo_alone_does_not_lift_the_wsus_stop():
    from findings.window import _load_inputs, _ledger

    inputs = _load_inputs(LAB)
    for item in inputs["backups"]:
        if item["host"].lower().startswith("wsus"):
            item["last_success"] = "2026-09-27T02:00:00Z"
    ledger = _ledger(LAB, inputs, date(2026, 9, 27))
    decision = next(
        item
        for item in ledger["apply_gate"]["decisions"]
        if item["host_short"] == "wsus01" and item["control"] == "WN22-00-000380"
    )
    assert decision["action"] == "refuse"
    assert "restore test" in decision["reason"].lower()


def test_rehearse_does_not_write_the_lab_record(tmp_path: Path):
    before = {
        path: path.read_bytes()
        for path in LAB.rglob("*")
        if path.is_file()
    }
    ledger_path = Path("web/src/data/ledger.json")
    gate_path = Path("ansible/generated/apply-gate.json")
    ledger_before = ledger_path.read_bytes()
    gate_before = gate_path.read_bytes()

    code = main(["rehearse", "--out", str(tmp_path / "window"), "--today", TODAY])
    assert code == 0
    assert (tmp_path / "window" / "report.md").is_file()
    assert json.loads((tmp_path / "window" / "report.json").read_text(encoding="utf-8"))["isolated"] is True

    after = {path: path.read_bytes() for path in LAB.rglob("*") if path.is_file()}
    assert before == after
    assert ledger_path.read_bytes() == ledger_before
    assert gate_path.read_bytes() == gate_before


def test_rehearse_refuses_to_overwrite_the_ledger(tmp_path: Path):
    code = main(["rehearse", "--out", "web/src/data/ledger.json", "--today", TODAY])
    assert code == 2
    code = main(["rehearse", "--out", "fixtures/lab", "--today", TODAY])
    assert code == 2
