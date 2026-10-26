from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path

import pytest

from findings.evidence import write_evidence
from findings.ledger import evaluate_backups, handoff_gates

TODAY = date(2026, 9, 27)
LAB = Path("fixtures/lab")


def _record(**overrides) -> dict:
    row = {
        "host": "app01.test.local",
        "method": "Nightly archive",
        "rpo_hours": 24,
        "rto_hours": 4,
        "last_success": "2026-09-26T23:00:00Z",
        "last_restore_test": "2026-09-01",
        "restore_test_max_days": 90,
        "notes": "",
        "restore_tests": [_test()],
    }
    row.update(overrides)
    return row


def _test(**overrides) -> dict:
    entry = {
        "date": "2026-09-01",
        "duration_minutes": 120,
        "restored": "Application data to a scratch VM",
        "scope": "full",
        "tester": "Systems administrator",
        "result": "pass",
        "notes": "",
    }
    entry.update(overrides)
    return entry


def _one(record: dict) -> dict:
    (row,) = evaluate_backups([record], TODAY)
    return row


def _write_json(path: Path, data) -> Path:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def test_clean_record_is_ok(tmp_path: Path):
    source = _write_json(tmp_path / "backups.json", [_record()])
    row = _one(json.loads(source.read_text(encoding="utf-8"))[0])
    assert row["status"] == "ok"
    assert row["rto_met"] is True and row["restore_scope_ok"] is True and row["restore_met"] is True
    assert row["reasons"] == [] and row["flags"] == []
    assert row["restore_tests"][0]["rto_met"] is True


def test_rto_breach_names_duration_and_rto():
    row = _one(_record(restore_tests=[_test(duration_minutes=300)]))
    assert row["status"] == "breach"
    assert row["rto_met"] is False
    assert row["restore_met"] is True and row["rpo_met"] is True and row["restore_scope_ok"] is True
    assert row["reasons"] == ["The newest restore test (2026-09-01) took 5 hours. RTO is 4 hours."]


def test_stored_rto_met_is_ignored():
    row = _one(_record(restore_tests=[_test(duration_minutes=300, rto_met=True)]))
    assert row["restore_tests"][0]["rto_met"] is False
    assert row["status"] == "breach"


def test_config_only_newest_falls_back_to_older_full_test():
    record = _record(
        last_restore_test="2026-09-10",
        restore_tests=[
            _test(date="2026-09-10", scope="config-only", duration_minutes=20),
            _test(date="2026-08-01", scope="full", duration_minutes=90),
        ],
    )
    row = _one(record)
    assert row["qualifying_test"]["date"] == "2026-08-01"
    assert row["restore_age_days"] == (TODAY - date(2026, 8, 1)).days
    assert row["restore_met"] is True
    assert row["restore_scope_ok"] is False
    assert row["status"] == "breach"
    assert row["reasons"] == [
        "The newest restore test (2026-09-10) was config-only. Only a full restore that passed counts as a restore test."
    ]


def test_stale_qualifying_test_keeps_the_existing_reason_text():
    record = _record(
        last_restore_test="2026-09-10",
        restore_tests=[
            _test(date="2026-09-10", scope="partial"),
            _test(date="2026-05-01", scope="full"),
        ],
    )
    row = _one(record)
    assert row["restore_met"] is False
    assert row["reasons"][0] == "Last restore test was 149 days ago. Policy is 90 days."
    assert "was partial" in row["reasons"][1]


def test_failed_full_test_does_not_count():
    record = _record(
        last_restore_test="2026-09-10",
        restore_tests=[_test(date="2026-09-10", result="fail"), _test(date="2026-08-20")],
    )
    row = _one(record)
    assert row["qualifying_test"]["date"] == "2026-08-20"
    assert row["restore_scope_ok"] is False
    assert any("(2026-09-10, full) failed" in reason for reason in row["reasons"])


def test_no_qualifying_test():
    record = _record(
        last_restore_test="2026-09-10",
        restore_tests=[
            _test(date="2026-09-10", scope="config-only"),
            _test(date="2026-07-01", scope="full", result="fail"),
        ],
    )
    row = _one(record)
    assert row["qualifying_test"] is None
    assert row["restore_age_days"] is None
    assert row["restore_met"] is False
    assert row["status"] == "breach"
    assert (
        "None of the 2 recorded restore tests was a full restore that passed, so no restore test counts against the 90-day policy."
        in row["reasons"]
    )


def test_no_restore_test_at_all():
    row = _one(_record(last_restore_test=None, restore_tests=[]))
    assert row["restore_met"] is False
    assert row["reasons"] == ["No restore test is on record."]


def test_date_only_record_still_reads():
    record = _record()
    del record["restore_tests"]
    row = _one(record)
    assert row["status"] == "ok"
    assert row["rto_met"] is None and row["restore_scope_ok"] is None
    assert row["restore_age_days"] == 26


def test_date_mismatch_flag_and_entries_win():
    record = _record(last_restore_test="2026-06-01", restore_tests=[_test(date="2026-09-01")])
    row = _one(record)
    assert row["flags"] == ["restore_date_mismatch"]
    assert row["last_restore_test"] == "2026-09-01"
    assert row["restore_met"] is True
    assert row["status"] == "ok"


def test_entries_are_ordered_newest_first():
    record = _record(restore_tests=[_test(date="2026-07-01"), _test(date="2026-09-01")])
    row = _one(record)
    assert [item["date"] for item in row["restore_tests"]] == ["2026-09-01", "2026-07-01"]
    assert row["flags"] == []


def test_unknown_scope_is_refused():
    with pytest.raises(ValueError, match="scope"):
        _one(_record(restore_tests=[_test(scope="snapshot")]))


def test_handoff_detail_names_host_and_reason():
    rows = evaluate_backups(
        [
            _record(),
            _record(host="slow01.test.local", restore_tests=[_test(duration_minutes=300)]),
        ],
        TODAY,
    )
    gates = handoff_gates([], rows, [])
    gate = next(item for item in gates["gates"] if item["id"] == "backups")
    assert gate["status"] == "fail"
    assert gate["detail"] == "slow01.test.local: The newest restore test (2026-09-01) took 5 hours. RTO is 4 hours."
    assert "app01" not in gate["detail"]


def test_evidence_files_written(tmp_path: Path):
    rows = evaluate_backups(
        [
            _record(),
            _record(
                host="cfg01.test.local",
                last_restore_test="2026-09-10",
                restore_tests=[_test(date="2026-09-10", scope="config-only"), _test(date="2026-08-01")],
            ),
        ],
        TODAY,
    )
    ledger = {
        "tool": "findings-register",
        "version": "test",
        "generated_for": TODAY.isoformat(),
        "site": {"name": "Test"},
        "sources": [],
        "findings": [],
        "controls": [],
        "brief": {"paragraphs": []},
        "drift": {name: [] for name in ("regressed", "new", "closed", "persistent", "opened_since_baseline")},
        "exceptions": [],
        "handoff": handoff_gates([], rows, []),
        "backups": rows,
    }
    out = tmp_path / "evidence"
    write_evidence(ledger, out)
    with (out / "backups.csv").open(encoding="utf-8", newline="") as handle:
        table = list(csv.DictReader(handle))
    assert [row["host"] for row in table] == ["app01.test.local", "cfg01.test.local"]
    cfg = table[1]
    assert cfg["status"] == "breach"
    assert cfg["qualifying_test_date"] == "2026-08-01"
    assert cfg["qualifying_test_scope"] == "full"
    assert cfg["newest_test_scope"] == "config-only"
    assert cfg["restore_scope_ok"] == "no"
    assert "was config-only" in cfg["reasons"]
    markdown = (out / "backups.md").read_text(encoding="utf-8")
    assert "## cfg01.test.local — breach" in markdown
    assert "| 2026-09-10 | config-only |" in markdown


def test_lab_backups_story():
    rows = {
        row["host"].split(".")[0]: row
        for row in evaluate_backups(json.loads((LAB / "backups.json").read_text(encoding="utf-8")), TODAY)
    }
    assert rows["ad01"]["status"] == "ok" and rows["rhel-mission01"]["status"] == "ok"
    assert rows["rhel-repo01"]["status"] == "ok"
    for row in rows.values():
        assert row["flags"] == []
    wsus = rows["wsus01"]
    assert wsus["rto_met"] is False
    assert wsus["reasons"][-1] == "The newest restore test (2026-06-01) took 10 hours 10 minutes. RTO is 8 hours."
    esxi = rows["esxi01"]
    assert esxi["newest_test"]["scope"] == "config-only"
    assert esxi["qualifying_test"]["date"] == "2026-01-22"
    assert esxi["restore_scope_ok"] is False and esxi["status"] == "breach"
