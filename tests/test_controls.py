from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

from findings.evidence import write_evidence
from findings.ledger import build_ledger, normalize_control
from findings.models import Observation
from findings.policy import DEFAULT_POLICY

TODAY = date(2026, 9, 27)
MILESTONES = {"baseline": "2026-07-15", "previous": "2026-08-20", "current": "2026-09-20"}


def _ledger(observations, **kwargs):
    defaults = dict(
        policy=DEFAULT_POLICY,
        today=TODAY,
        hosts=[],
        exceptions=[],
        backups=[],
        services=[],
        site={"name": "Test"},
        milestones=MILESTONES,
    )
    defaults.update(kwargs)
    return build_ledger(observations, **defaults)


def _obs(host, day, rule, result, *, severity="medium", cci=(), nist=()):
    return Observation(
        host=host,
        observed_at=date.fromisoformat(day),
        source="xccdf",
        source_file=f"{host}_{day}.xml",
        rule_ver=rule,
        title=f"{rule} title",
        severity=severity,
        cci=list(cci),
        nist=list(nist),
        result=result,
    )


def _by_control(ledger):
    return {row["control"]: row for row in ledger["controls"]}


def test_control_ids_normalize():
    assert normalize_control("AC-2 (1)") == "AC-2(1)"
    assert normalize_control("AC-2(1)") == "AC-2(1)"
    assert normalize_control("AC-02 (01)") == "AC-2(1)"
    assert normalize_control("ac-17(2)") == "AC-17(2)"
    assert normalize_control("CM-7 a") == "CM-7"
    assert normalize_control("SP 800-53 Revision 4 :: CM-5 (3)") == "CM-5(3)"
    assert normalize_control("not a control") is None


def test_spellings_merge_and_controls_sort_by_number():
    observations = [
        _obs("a.lab.local", "2026-09-20", "R-1", "fail", cci=["CCI-000015"], nist=["AC-2 (1)"]),
        _obs("b.lab.local", "2026-09-20", "R-2", "fail", cci=["CCI-000016"], nist=["AC-02 (01)"]),
        _obs("a.lab.local", "2026-09-20", "R-3", "fail", cci=["CCI-000054"], nist=["AC-10"]),
        _obs("a.lab.local", "2026-09-20", "R-4", "fail", cci=["CCI-000015"], nist=["AC-2"]),
        _obs("a.lab.local", "2026-09-20", "R-5", "fail", cci=["CCI-000169"], nist=["AU-12"]),
    ]
    ledger = _ledger(observations)
    order = [row["control"] for row in ledger["controls"]]
    assert order == ["AC-2", "AC-2(1)", "AC-10", "AU-12"]
    merged = _by_control(ledger)["AC-2(1)"]
    assert merged["family"] == "AC"
    assert merged["ccis"] == ["CCI-000015", "CCI-000016"]
    assert sorted(item["slug"] for item in merged["findings"]) == ["a--R-1", "b--R-2"]
    assert {item["host"] for item in merged["findings"]} == {"a.lab.local", "b.lab.local"}


def test_counts_worst_clock_and_earliest_due():
    observations = [
        # CAT I failing since July: overdue, due 2026-08-14.
        _obs("repo.lab.local", "2026-07-15", "R-GPG", "fail", severity="high", cci=["CCI-001749"], nist=["CM-5"]),
        _obs("repo.lab.local", "2026-09-20", "R-GPG", "fail", severity="high", cci=["CCI-001749"], nist=["CM-5"]),
        # CAT II failing since July: due soon, 2026-10-13.
        _obs("mission.lab.local", "2026-07-15", "R-LOCAL", "fail", cci=["CCI-001749"], nist=["CM-5"]),
        _obs("mission.lab.local", "2026-09-20", "R-LOCAL", "fail", cci=["CCI-001749"], nist=["CM-5"]),
        # Fixed: closed.
        _obs("mission.lab.local", "2026-08-20", "R-GPG", "fail", severity="high", cci=["CCI-001749"], nist=["CM-5"]),
        _obs("mission.lab.local", "2026-09-20", "R-GPG", "pass", severity="high", cci=["CCI-001749"], nist=["CM-5"]),
        # A different control that is only on track.
        _obs("mission.lab.local", "2026-09-20", "R-AUDIT", "fail", cci=["CCI-000169"], nist=["AU-12"]),
    ]
    controls = _by_control(_ledger(observations))
    cm5 = controls["CM-5"]
    assert (cm5["open"], cm5["overdue"], cm5["due_soon"], cm5["excepted"], cm5["closed"]) == (2, 1, 1, 0, 1)
    assert cm5["worst_clock"] == "overdue"
    assert cm5["earliest_due"] == "2026-08-14"
    assert [item["clock"] for item in cm5["findings"]] == ["overdue", "due_soon", "closed"]
    assert cm5["open_all_excepted"] is False
    au12 = controls["AU-12"]
    assert au12["worst_clock"] == "on_track"
    assert au12["earliest_due"] == "2026-12-19"


def test_findings_without_a_control_land_in_unmapped():
    observations = [
        # No CCI at all.
        _obs("dc.lab.local", "2026-09-20", "R-TIME", "fail"),
        # A CCI no scanner tied to a control.
        _obs("esxi.lab.local", "2026-09-20", "R-NEW", "fail", cci=["CCI-004923"]),
        # A checklist-style row: CCI but no control. Another row reported the control for that CCI.
        _obs("wsus.lab.local", "2026-09-20", "R-SMB", "fail", cci=["CCI-000381"]),
        _obs("esxi.lab.local", "2026-09-20", "R-SLP", "fail", cci=["CCI-000381"], nist=["CM-7 a"]),
    ]
    ledger = _ledger(observations)
    controls = _by_control(ledger)
    assert ledger["controls"][-1]["control"] == "unmapped"
    unmapped = controls["unmapped"]
    assert unmapped["family"] == "unmapped"
    assert unmapped["ccis"] == ["CCI-004923"]
    mapped_by = {item["slug"]: item["mapped_by"] for item in unmapped["findings"]}
    assert mapped_by == {"dc--R-TIME": "no_cci", "esxi--R-NEW": "no_control"}
    cm7 = controls["CM-7"]
    assert {item["slug"]: item["mapped_by"] for item in cm7["findings"]} == {
        "wsus--R-SMB": "same_cci",
        "esxi--R-SLP": "reported",
    }
    every_slug = {item["slug"] for row in ledger["controls"] for item in row["findings"]}
    assert every_slug == {item["slug"] for item in ledger["findings"]}


def test_exception_coverage():
    observations = [
        _obs("esxi.lab.local", "2026-09-20", "R-SSH", "fail", cci=["CCI-000381"], nist=["CM-7"]),
        _obs("esxi.lab.local", "2026-09-20", "R-SHELL", "fail", cci=["CCI-000381"], nist=["CM-7"]),
        _obs("esxi.lab.local", "2026-09-20", "R-LOCK", "fail", cci=["CCI-000015"], nist=["AC-2"]),
        _obs("esxi.lab.local", "2026-09-20", "R-ACCT", "fail", cci=["CCI-000015"], nist=["AC-2"]),
    ]
    exceptions = [
        {"id": "EX-1", "host": "esxi.lab.local", "control": "R-SSH", "status": "approved", "expires": "2026-12-31"},
        {"id": "EX-2", "host": "esxi.lab.local", "control": "R-SHELL", "status": "approved", "expires": "2026-11-30"},
        {"id": "EX-3", "host": "esxi.lab.local", "control": "R-LOCK", "status": "approved", "expires": "2026-12-31"},
        {"id": "EX-4", "host": "esxi.lab.local", "control": "R-ACCT", "status": "pending", "expires": "2026-12-31"},
    ]
    controls = _by_control(_ledger(observations, exceptions=exceptions))
    cm7 = controls["CM-7"]
    assert cm7["open"] == 2 and cm7["excepted"] == 2
    assert cm7["worst_clock"] == "excepted"
    assert cm7["open_all_excepted"] is True
    assert cm7["earliest_due"] == "2026-11-30"
    ac2 = controls["AC-2"]
    assert ac2["excepted"] == 1
    assert ac2["open_all_excepted"] is False
    assert ac2["worst_clock"] == "on_track"


def test_nothing_open_is_not_reported_as_covered():
    observations = [
        _obs("a.lab.local", "2026-08-20", "R-1", "fail", cci=["CCI-000054"], nist=["AC-10"]),
        _obs("a.lab.local", "2026-09-20", "R-1", "pass", cci=["CCI-000054"], nist=["AC-10"]),
    ]
    ac10 = _by_control(_ledger(observations))["AC-10"]
    assert ac10["worst_clock"] == "closed"
    assert ac10["open"] == 0
    assert ac10["open_all_excepted"] is False
    assert ac10["earliest_due"] is None


def test_evidence_writes_controls_csv_and_md(tmp_path: Path):
    observations = [
        _obs("repo.lab.local", "2026-07-15", "R-GPG", "fail", severity="high", cci=["CCI-001749"], nist=["CM-5"]),
        _obs("mission.lab.local", "2026-09-20", "R-GPG", "fail", severity="high", cci=["CCI-001749"], nist=["CM-5"]),
        _obs("mission.lab.local", "2026-09-20", "R-ACCT", "fail", cci=["CCI-000015"], nist=["AC-2"]),
        _obs("dc.lab.local", "2026-09-20", "R-TIME", "fail"),
    ]
    ledger = _ledger(observations)
    out = tmp_path / "evidence"
    write_evidence(ledger, out)

    with (out / "controls.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["control"] for row in rows] == ["AC-2", "CM-5", "unmapped"]
    cm5 = rows[1]
    assert cm5["family"] == "CM"
    assert cm5["ccis"] == "CCI-001749"
    assert (cm5["open"], cm5["overdue"], cm5["closed"]) == ("2", "1", "0")
    assert cm5["worst_clock"] == "overdue"
    assert cm5["findings"] == "repo--R-GPG;mission--R-GPG"
    assert rows[2]["findings"] == "dc--R-TIME"

    text = (out / "controls.md").read_text(encoding="utf-8")
    assert "## AC" in text and "## CM" in text and "## unmapped" in text
    assert text.index("## AC") < text.index("## CM") < text.index("## unmapped")
    assert "### CM-5 — overdue" in text
    assert "- R-GPG on repo.lab.local — CAT I — overdue, due 2026-08-14" in text
    assert "- R-TIME on dc.lab.local — CAT II — on_track" in text
