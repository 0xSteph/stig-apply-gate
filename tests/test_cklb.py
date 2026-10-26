from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from findings.annotate import annotate_checklist
from findings.cli import main
from findings.ledger import build_ledger
from findings.parsers import load_scans, parse_ckl, parse_cklb, parse_scan
from findings.policy import DEFAULT_POLICY

TODAY = date(2026, 9, 27)
MILESTONES = {"baseline": "2026-07-15", "previous": "2026-08-20", "current": "2026-09-20"}
HOST = "rhel-mission01.lab.local"


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


def _rule(**overrides) -> dict:
    rule = {
        "group_id": "V-230296",
        "group_id_src": "V-230296",
        "rule_id": "SV-230296r858711_rule",
        "rule_id_src": "SV-230296r858711_rule",
        "rule_version": "RHEL-08-010550",
        "rule_title": "Direct SSH logons as root must be disabled.",
        "severity": "medium",
        "status": "open",
        "finding_details": "",
        "comments": "",
        "ccis": ["CCI-000770"],
        "overrides": {},
        "uuid": "6e3c7a1e-0000-4000-8000-000000000001",
        "check_content": "Check sshd_config.",
        "fix_text": "Set PermitRootLogin no.",
        "discussion": "Root logons are not attributable.",
    }
    rule.update(overrides)
    return rule


def _cklb(rules: list[dict], *, host_name: str = "rhel-mission01", fqdn: str = HOST) -> dict:
    return {
        "title": "rhel-mission01",
        "id": "0b1c2d3e-0000-4000-8000-000000000000",
        "cklb_version": "1.0",
        "active": False,
        "mode": 1,
        "has_path": True,
        "target_data": {
            "target_type": "Computing",
            "host_name": host_name,
            "ip_address": "10.10.20.15",
            "mac_address": "",
            "fqdn": fqdn,
            "comments": "",
            "role": "Member Server",
            "is_web_database": False,
            "technology_area": "",
            "web_db_site": "",
            "web_db_instance": "",
        },
        "stigs": [
            {
                "stig_name": "Red Hat Enterprise Linux 8 Security Technical Implementation Guide",
                "display_name": "Red Hat Enterprise Linux 8",
                "stig_id": "RHEL_8_STIG",
                "release_info": "Release: 14",
                "version": "1",
                "uuid": "0b1c2d3e-0000-4000-8000-0000000000aa",
                "reference_identifier": "2921",
                "size": len(rules),
                "rules": rules,
            }
        ],
    }


def _write_cklb(path: Path, document: dict) -> Path:
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


CKL = """<?xml version="1.0" encoding="UTF-8"?><!--DISA STIG Viewer :: 2.17-->
<CHECKLIST>
  <ASSET>
    <ROLE>Member Server</ROLE>
    <HOST_NAME>rhel-mission01</HOST_NAME>
    <HOST_FQDN>rhel-mission01.lab.local</HOST_FQDN>
  </ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO><SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Red Hat Enterprise Linux 8 Security Technical Implementation Guide</SID_DATA></SI_DATA></STIG_INFO>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-230296</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-230296r858711_rule</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>RHEL-08-010550</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Direct SSH logons as root must be disabled.</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-000770</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>Open</STATUS>
        <FINDING_DETAILS>PermitRootLogin yes in /etc/ssh/sshd_config.</FINDING_DETAILS>
        <COMMENTS></COMMENTS>
        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
      </VULN>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-230264</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-230264r880711_rule</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>RHEL-08-010370</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Repository packages must be GPG-checked.</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS attr="kept">NotAFinding</STATUS>
        <FINDING_DETAILS>gpgcheck=1 everywhere.</FINDING_DETAILS>
        <COMMENTS>Checked by hand.</COMMENTS>
        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>
"""


def test_cklb_parses_to_the_same_identifiers_as_ckl(tmp_path: Path):
    ckl = tmp_path / "mission_2026-09-20.ckl"
    ckl.write_text(CKL, encoding="utf-8")
    cklb = _write_cklb(
        tmp_path / "mission_2026-09-20.cklb",
        _cklb([_rule(finding_details="PermitRootLogin yes in /etc/ssh/sshd_config.")]),
    )
    from_ckl = parse_ckl(ckl)[0]
    from_cklb = parse_scan(cklb)[0]
    assert from_cklb.source == "cklb"
    assert from_cklb.identifiers() == from_ckl.identifiers()
    for field in ("host", "observed_at", "rule_ver", "vuln_num", "rule_id", "title", "severity", "cci", "result", "detail", "platform", "benchmark"):
        assert getattr(from_cklb, field) == getattr(from_ckl, field), field


def test_cklb_status_values_and_rule_id_without_suffix(tmp_path: Path):
    rules = [
        _rule(status="open"),
        _rule(rule_version="R-2", group_id="V-2", rule_id="SV-2r1", status="not_a_finding"),
        _rule(rule_version="R-3", group_id="V-3", rule_id="SV-3r1_rule", status="not_applicable"),
        _rule(rule_version="R-4", group_id="V-4", rule_id="SV-4r1_rule", status="not_reviewed"),
    ]
    found = parse_cklb(_write_cklb(tmp_path / "m_2026-09-20.cklb", _cklb(rules)))
    assert [item.result for item in found] == ["fail", "pass", "notapplicable", "notchecked"]
    assert found[1].rule_id == "SV-2r1_rule"


def test_ckl_and_cklb_for_one_host_merge(tmp_path: Path):
    ckl = tmp_path / "mission_2026-08-20.ckl"
    ckl.write_text(CKL, encoding="utf-8")
    _write_cklb(tmp_path / "mission_2026-09-20.cklb", _cklb([_rule(status="open")]))
    observations, problems = load_scans(tmp_path)
    assert problems == []
    ledger = _ledger(observations)
    matches = [item for item in ledger["findings"] if item["control"] == "RHEL-08-010550"]
    assert len(matches) == 1
    assert matches[0]["host"] == HOST
    assert [point["date"] for point in matches[0]["history"]] == ["2026-08-20", "2026-09-20"]
    assert matches[0]["history"][-1]["sources"] == ["cklb"]


def test_cklb_severity_override_is_honored(tmp_path: Path):
    rule = _rule(overrides={"severity": {"severity": "high", "reason": "ISSO elevated this for the mission host."}})
    found = parse_cklb(_write_cklb(tmp_path / "m_2026-09-20.cklb", _cklb([rule])))
    assert found[0].severity == "medium"
    assert found[0].severity_override == "high"
    assert "ISSO elevated" in found[0].detail
    finding = _ledger(found)["findings"][0]
    assert finding["cat"] == "I"
    assert "severity_override" in finding["flags"]


def test_cklb_without_rules_or_host_is_a_problem(tmp_path: Path):
    _write_cklb(tmp_path / "empty_2026-09-20.cklb", _cklb([]))
    _write_cklb(tmp_path / "nohost_2026-09-20.cklb", _cklb([_rule()], host_name="", fqdn=" "))
    (tmp_path / "broken_2026-09-20.cklb").write_text("{not json", encoding="utf-8")
    observations, problems = load_scans(tmp_path)
    assert observations == []
    assert len(problems) == 3
    assert any("empty_2026-09-20.cklb" in item and "no rules" in item for item in problems)
    assert any("nohost_2026-09-20.cklb" in item and "no host name" in item for item in problems)
    assert any("broken_2026-09-20.cklb" in item and "not valid JSON" in item for item in problems)


def test_cklb_host_falls_back_to_host_name(tmp_path: Path):
    found = parse_cklb(_write_cklb(tmp_path / "m_2026-09-20.cklb", _cklb([_rule()], fqdn="")))
    assert found[0].host == "rhel-mission01"


def _annotated_ledger(tmp_path: Path) -> dict:
    scan = tmp_path / "scan"
    scan.mkdir()
    _write_cklb(scan / "mission_2026-09-20.cklb", _cklb([_rule(status="open")]))
    observations, problems = load_scans(scan)
    assert problems == []
    ledger = _ledger(
        observations,
        exceptions=[{"id": "EX-031", "host": HOST, "control": "RHEL-08-010550", "status": "pending", "expires": "2026-12-31"}],
    )
    finding = next(item for item in ledger["findings"] if item["control"] == "RHEL-08-010550")
    ledger["apply_gate"]["decisions"] = [
        {
            "host": HOST,
            "host_short": "rhel-mission01",
            "control": "RHEL-08-010550",
            "slug": finding["slug"],
            "action": "bundle",
            "reason": "One sshd restart with the OpenSSH findings.",
        }
    ]
    return ledger


def _vulns(path: Path) -> dict[str, ET.Element]:
    root = ET.parse(path).getroot()
    found = {}
    for vuln in root.iter("VULN"):
        for data in vuln.iter("STIG_DATA"):
            if data.findtext("VULN_ATTRIBUTE") == "Rule_Ver":
                found[data.findtext("ATTRIBUTE_DATA")] = vuln
    return found


def test_annotate_ckl_fills_matched_row_and_keeps_the_rest(tmp_path: Path):
    ledger = _annotated_ledger(tmp_path)
    checklist = tmp_path / "mission_2026-09-20.ckl"
    checklist.write_text(CKL, encoding="utf-8")
    out = tmp_path / "out" / "mission_annotated.ckl"

    summary = annotate_checklist(ledger, checklist, out)
    assert summary["matched"] == 1
    assert summary["rules"] == 2

    text = out.read_text(encoding="utf-8")
    assert text.startswith('<?xml version="1.0" encoding="UTF-8"?><!--DISA STIG Viewer :: 2.17-->')
    after = _vulns(out)
    before = _vulns(checklist)

    matched = after["RHEL-08-010550"]
    assert matched.findtext("STATUS") == "Open"
    details = matched.findtext("FINDING_DETAILS")
    assert details.startswith("PermitRootLogin yes in /etc/ssh/sshd_config.\n\n--- findings register 2026-09-27 ---")
    assert "CAT II" in details
    assert "Exception: EX-031." in details
    assert "Apply gate: bundle. One sshd restart with the OpenSSH findings." in details
    assert "Clock: " in details and "Due: " in details
    assert matched.findtext("COMMENTS").startswith("--- findings register 2026-09-27 ---")

    untouched = after["RHEL-08-010370"]
    assert ET.tostring(untouched) == ET.tostring(before["RHEL-08-010370"])
    assert untouched.find("STATUS").attrib == {"attr": "kept"}
    assert after.keys() == before.keys()
    assert ET.parse(out).getroot().findtext("ASSET/ROLE") == "Member Server"

    # Annotating the annotated copy again on the same day does not stack a second block.
    again = tmp_path / "out" / "again.ckl"
    annotate_checklist(ledger, out, again)
    assert _vulns(again)["RHEL-08-010550"].findtext("FINDING_DETAILS") == details


def test_annotate_cklb_appends_and_leaves_status(tmp_path: Path):
    ledger = _annotated_ledger(tmp_path)
    other = _rule(rule_version="RHEL-08-010370", group_id="V-230264", rule_id="SV-230264r880711_rule", status="not_a_finding", finding_details="kept", comments="hand note")
    original = _cklb([_rule(status="open", finding_details="Seen on the console.", comments=""), other])
    checklist = _write_cklb(tmp_path / "mission_2026-09-20.cklb", original)
    out = tmp_path / "annotated.cklb"

    summary = annotate_checklist(ledger, checklist, out)
    assert summary["matched"] == 1
    written = json.loads(out.read_text(encoding="utf-8"))
    matched, unmatched = written["stigs"][0]["rules"]
    assert matched["status"] == "open"
    assert matched["finding_details"].startswith("Seen on the console.\n\n--- findings register 2026-09-27 ---\n")
    assert "Apply gate: bundle." in matched["finding_details"]
    assert matched["comments"].startswith("--- findings register 2026-09-27 ---")
    assert unmatched == other
    for key in ("check_content", "fix_text", "discussion", "uuid", "ccis", "overrides"):
        assert matched[key] == original["stigs"][0]["rules"][0][key]
    assert {key: value for key, value in written.items() if key != "stigs"} == {
        key: value for key, value in original.items() if key != "stigs"
    }
    assert written["stigs"][0]["stig_name"] == original["stigs"][0]["stig_name"]


def test_annotate_refuses_to_write_over_the_input(tmp_path: Path):
    ledger = _annotated_ledger(tmp_path)
    checklist = tmp_path / "mission_2026-09-20.ckl"
    checklist.write_text(CKL, encoding="utf-8")
    with pytest.raises(ValueError, match="Refusing"):
        annotate_checklist(ledger, checklist, tmp_path / "." / "mission_2026-09-20.ckl")
    assert checklist.read_text(encoding="utf-8") == CKL

    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    code = main(["annotate", "--ledger", str(ledger_path), "--checklist", str(checklist), "--out", str(checklist)])
    assert code == 2
    assert checklist.read_text(encoding="utf-8") == CKL

    out = tmp_path / "copy.ckl"
    assert main(["annotate", "--ledger", str(ledger_path), "--checklist", str(checklist), "--out", str(out)]) == 0
    assert "--- findings register 2026-09-27 ---" in out.read_text(encoding="utf-8")
