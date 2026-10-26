from __future__ import annotations

import copy
import json
import shutil
from datetime import date
from pathlib import Path

from findings.cli import _ledger_from_dir, main
from findings.delta import compute_delta, render_delta
from findings.window import _ledger, _load_inputs

LAB = Path("fixtures/lab")


def _lab_ledger(today: str) -> dict:
    """The lab as it stands, every scan, with the clock set to `today`."""
    return _ledger(LAB, _load_inputs(LAB), date.fromisoformat(today))


def _august_ledger(tmp_path: Path) -> dict:
    """The lab as it stood before the September scans: a copy without them."""
    scans = tmp_path / "august-scans"
    scans.mkdir()
    for path in (LAB / "scans").iterdir():
        if "2026-09" not in path.name:
            shutil.copy(path, scans / path.name)
    inputs = _load_inputs(LAB)
    inputs["milestones"] = {"baseline": "2026-07-15", "previous": "2026-07-15", "current": "2026-08-20"}
    return _ledger_from_dir(scan_dir=scans, policy_path=Path("policy/default.json"), today=date(2026, 8, 27), **inputs)


def _write(path: Path, ledger: dict) -> Path:
    path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    return path


def _keys(items: list[dict]) -> set[tuple[str, str]]:
    return {(item["row"]["host_short"], item["row"]["control"]) for item in items}


def _section(text: str, title: str) -> str:
    start = text.index(f"## {title}")
    end = text.find("\n## ", start + 1)
    return text[start : end if end != -1 else len(text)]


def test_august_to_september_on_the_lab(tmp_path: Path, capsys):
    before = _write(tmp_path / "before.json", _august_ledger(tmp_path))
    after = _write(tmp_path / "after.json", _lab_ledger("2026-09-27"))
    out = tmp_path / "report" / "delta.md"
    assert main(["delta", "--before", str(before), "--after", str(after), "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    text = out.read_text(encoding="utf-8")
    assert text in printed
    first = text.splitlines()[2]
    assert first.startswith("Findings delta 2026-08-27 to 2026-09-27: 4 new open rows, 1 closed, 0 closed without a rescan, 1 regression")

    delta = compute_delta(json.loads(before.read_text()), json.loads(after.read_text()))
    # The audit row was closed in August and failed again in September: new open and a regression.
    # The vCenter and VM snapshots are dated 2026-09-20, so their open rows are new in September.
    assert _keys(delta["new_open"]) == {
        ("rhel-mission01", "CVE-2024-6387"),
        ("rhel-mission01", "RHEL-08-030180"),
        ("rhel-mission01", "VMCH-80-000197"),
        ("vcenter01", "VCSA-80-000089"),
    }
    assert "Closed in the earlier ledger." in _section(text, "New open rows")
    assert _keys(delta["closed"]) == {("rhel-repo01", "RHEL-08-010550")}
    assert delta["closed_without_rescan"] == []
    assert _keys(delta["regressions"]) == {("rhel-mission01", "RHEL-08-030180")}
    clocks = {(item["row"]["host_short"], item["row"]["control"]): (item["was"], item["row"]["clock"]) for item in delta["clock_changes"]}
    assert clocks[("rhel-repo01", "RHEL-08-010371")] == ("on_track", "overdue")
    assert clocks[("wsus01", "WN22-00-000380")] == ("excepted", "overdue")
    assert delta["due_within"] == 21
    assert ("rhel-mission01", "CVE-2024-6387") in _keys(delta["due"])
    assert [item["id"] for item in delta["exceptions_expiring"]] == ["EX-014"]
    assert [item["id"] for item in delta["exceptions_expired"]] == ["EX-007"]
    # vcenter01 has a September snapshot now, so no host is missing from the period.
    assert delta["hosts_missing"] == []
    # wsus01 is a breach in both periods: its newest restore test took longer than its RTO,
    # and that does not depend on the date. esxi01 is past its restore-test age in both.
    assert delta["backup_changes"] == []
    assert _section(text, "Backups that changed status").strip().endswith("none")
    assert _section(text, "Closed without a rescan").strip().endswith("none")
    assert "EX-007" in _section(text, "Exceptions that expired between")


def test_same_scans_a_month_later(tmp_path: Path, capsys):
    before = _write(tmp_path / "before.json", _lab_ledger("2026-09-27"))
    after = _write(tmp_path / "after.json", _lab_ledger("2026-10-27"))
    assert main(["delta", "--before", str(before), "--after", str(after), "--due-within", "30", "--expiring-within", "60"]) == 0
    text = capsys.readouterr().out
    delta = compute_delta(json.loads(before.read_text()), json.loads(after.read_text()), due_within=30, expiring_within=60)
    assert delta["new_open"] == [] and delta["closed"] == [] and delta["regressions"] == []
    clocks = {(item["row"]["host_short"], item["row"]["control"]): (item["was"], item["row"]["clock"]) for item in delta["clock_changes"]}
    assert clocks[("rhel-mission01", "CVE-2024-6387")] == ("due_soon", "overdue")
    assert clocks[("esxi01", "ESXI-80-000193")] == ("excepted", "overdue")
    assert [item["id"] for item in delta["exceptions_expired"]] == ["EX-014"]
    # EX-021 ends inside the window but is pending, not approved, so it is not listed.
    assert delta["exceptions_expiring"] == []
    # Nothing was scanned between the two dates, so every scanned host is missing from the period.
    missing = {item["host"] for item in delta["hosts_missing"]}
    assert {"ad01.lab.local", "esxi01.lab.local", "wsus01.lab.local", "vcenter01.lab.local"} <= missing
    assert "Due within 30 days" in text
    assert "Exceptions expiring within 60 days" in text
    assert "## New open rows\n\nnone" in text


def test_hand_edited_after_fills_every_section(tmp_path: Path, capsys):
    base = _august_ledger(tmp_path)
    after = copy.deepcopy(_lab_ledger("2026-09-27"))
    rows = {(item["host_short"], item["control"]): item for item in after["findings"]}

    # ad01 was not scanned in September. Its time row is marked closed anyway.
    for row in after["findings"]:
        if row["host_short"] == "ad01":
            row["history"] = [point for point in row["history"] if point["date"] <= "2026-08-27"]
            row["last_seen"] = row["history"][-1]["date"]
    hidden = rows[("ad01", "WN22-DC-000060")]
    hidden["clock"], hidden["result"], hidden["due"], hidden["regression"] = "closed", "pass", None, False

    # A row that was open in August drops out of the later ledger entirely.
    after["findings"] = [row for row in after["findings"] if row["slug"] != "wsus01--WN22-AC-000070"]

    # Gate moved: the signing key was imported.
    for decision in after["apply_gate"]["decisions"]:
        if decision["slug"] == "rhel-repo01--RHEL-08-010370":
            decision["action"], decision["reason"] = "allow", "The lab signing key is imported. Run with --check --diff first."

    # The esxi01 backup came back inside policy.
    for backup in after["backups"]:
        if backup["host"].startswith("esxi01"):
            backup["status"], backup["reasons"] = "ok", []

    before_path = _write(tmp_path / "before.json", base)
    after_path = _write(tmp_path / "after.json", after)
    out = tmp_path / "delta.md"
    assert main(["delta", "--before", str(before_path), "--after", str(after_path), "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    capsys.readouterr()

    suspicious = _section(text, "Closed without a rescan")
    assert "ad01 WN22-DC-000060" in suspicious and "2026-08-20" in suspicious
    assert "ad01 WN22-DC-000060" not in _section(text, "Closed since")
    assert "0 closed without a rescan" not in text.splitlines()[2]
    assert "wsus01 WN22-AC-000070" in _section(text, "Open rows gone from the later ledger")
    missing = _section(text, "Hosts missing from the period")
    assert "ad01.lab.local" in missing
    gate = _section(text, "Gate decisions that changed")
    assert "rhel-repo01 RHEL-08-010370: probe -> allow" in gate
    assert "Before: " in gate and "signing key is imported" in gate
    backups = _section(text, "Backups that changed status")
    assert "esxi01.lab.local: breach -> ok." in backups
    for title in (
        "New open rows",
        "Closed since",
        "Regressions",
        "Clock changes",
        "Due within 21 days",
        "Exceptions expiring within 30 days",
        "Exceptions that expired between",
    ):
        assert not _section(text, title).rstrip().endswith("none"), title

    # A regression flag set in the later ledger counts even when the row was open before.
    flagged = copy.deepcopy(after)
    for row in flagged["findings"]:
        if row["slug"] == "rhel-repo01--RHEL-08-010370":
            row["regression"] = True
    delta = compute_delta(base, flagged)
    assert ("rhel-repo01", "RHEL-08-010370") in _keys(delta["regressions"])


def test_identical_ledgers_print_none(tmp_path: Path, capsys):
    ledger = _write(tmp_path / "same.json", _lab_ledger("2026-09-27"))
    assert main(["delta", "--before", str(ledger), "--after", str(ledger), "--expiring-within", "1"]) == 0
    text = capsys.readouterr().out
    for title in ("New open rows", "Closed since", "Closed without a rescan", "Regressions", "Clock changes",
                  "Exceptions expiring within 1 days", "Exceptions that expired between",
                  "Gate decisions that changed", "Backups that changed status"):
        assert _section(text, title).rstrip().endswith("none"), title
    assert "Open rows gone from the later ledger" not in text
    report = render_delta(compute_delta(json.loads(ledger.read_text()), json.loads(ledger.read_text())))
    assert report.startswith("# What moved since last period\n\nFindings delta 2026-09-27 to 2026-09-27: 0 new open rows")


def test_unreadable_ledger_exits_2(tmp_path: Path, capsys):
    good = _write(tmp_path / "good.json", _lab_ledger("2026-09-27"))
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    not_ledger = _write(tmp_path / "list.json", {"generated_for": "2026-09-27"})
    out = tmp_path / "delta.md"
    assert main(["delta", "--before", str(broken), "--after", str(good), "--out", str(out)]) == 2
    assert main(["delta", "--before", str(good), "--after", str(tmp_path / "absent.json")]) == 2
    assert main(["delta", "--before", str(not_ledger), "--after", str(good)]) == 2
    err = capsys.readouterr().err
    assert "broken.json" in err and "absent.json" in err and "no findings list" in err
    assert not out.exists()
