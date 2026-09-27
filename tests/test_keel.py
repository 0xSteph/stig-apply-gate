from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from findings.evidence import write_evidence
from findings.lab import write_lab_scans
from findings.ledger import build_ledger
from findings.cli import main
from findings.parsers import load_scans, parse_acas, parse_ckl, parse_scan, parse_xccdf
from findings.policy import DEFAULT_POLICY, Policy
from findings.vsphere import checks_from_snapshot, snapshot_from_govc_outputs

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


def test_xccdf_joins_rule_metadata(tmp_path: Path):
    path = tmp_path / "repo_2026-09-20.xml"
    path.write_text(
        """<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
          <title>Red Hat Enterprise Linux 8 STIG</title>
          <Rule id="xccdf_mil.disa.stig_rule_SV-230264r880711_rule" severity="high">
            <version>RHEL-08-010370</version>
            <title>Repository packages must be GPG-checked before they are installed.</title>
            <ident system="http://cyber.mil/cci">CCI-001749</ident>
            <ident system="http://cyber.mil/legacy">V-230264</ident>
          </Rule>
          <TestResult id="r" start-time="2026-09-20T02:10:00">
            <target>rhel-repo01.lab.local</target>
            <rule-result idref="xccdf_mil.disa.stig_rule_SV-230264r880711_rule">
              <result>fail</result>
            </rule-result>
          </TestResult>
        </Benchmark>
        """,
        encoding="utf-8",
    )
    found = parse_xccdf(path)
    assert len(found) == 1
    assert found[0].rule_ver == "RHEL-08-010370"
    assert found[0].vuln_num == "V-230264"
    assert found[0].cci == ["CCI-001749"]
    assert found[0].result == "fail"
    assert found[0].host == "rhel-repo01.lab.local"


def test_ckl_override_and_statuses(tmp_path: Path):
    path = tmp_path / "wsus_2026-09-20.ckl"
    path.write_text(
        """<?xml version="1.0"?>
        <CHECKLIST>
          <ASSET><HOST_FQDN>wsus01.lab.local</HOST_FQDN></ASSET>
          <STIGS><iSTIG>
            <STIG_INFO><SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Windows</SID_DATA></SI_DATA></STIG_INFO>
            <VULN>
              <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>WN22-00-000380</ATTRIBUTE_DATA></STIG_DATA>
              <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
              <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>No SMBv1</ATTRIBUTE_DATA></STIG_DATA>
              <STATUS>Open</STATUS>
              <SEVERITY_OVERRIDE>high</SEVERITY_OVERRIDE>
              <SEVERITY_JUSTIFICATION>ISSO elevated this.</SEVERITY_JUSTIFICATION>
              <COMMENTS></COMMENTS>
              <FINDING_DETAILS></FINDING_DETAILS>
            </VULN>
            <VULN>
              <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>WN22-AC-000070</ATTRIBUTE_DATA></STIG_DATA>
              <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
              <STATUS>NotAFinding</STATUS>
              <COMMENTS></COMMENTS>
              <FINDING_DETAILS></FINDING_DETAILS>
              <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
              <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
            </VULN>
          </iSTIG></STIGS>
        </CHECKLIST>
        """,
        encoding="utf-8",
    )
    found = parse_ckl(path)
    assert found[0].result == "fail"
    assert found[0].severity_override == "high"
    assert found[1].result == "pass"
    ledger = _ledger(found)
    elevated = next(item for item in ledger["findings"] if item["control"] == "WN22-00-000380")
    assert elevated["cat"] == "I"
    assert "severity_override" in elevated["flags"]


def test_xccdf_and_ckl_merge(tmp_path: Path):
    xml = tmp_path / "host_2026-08-20.xml"
    xml.write_text(
        """<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
          <title>RHEL 8</title>
          <Rule id="xccdf_mil.disa.stig_rule_SV-230296r858711_rule" severity="medium">
            <version>RHEL-08-010550</version>
            <title>Direct SSH logons as root must be disabled.</title>
            <ident system="http://cyber.mil/legacy">V-230296</ident>
          </Rule>
          <TestResult id="r" start-time="2026-08-20T01:00:00">
            <target>rhel-mission01.lab.local</target>
            <rule-result idref="xccdf_mil.disa.stig_rule_SV-230296r858711_rule"><result>fail</result></rule-result>
          </TestResult>
        </Benchmark>
        """,
        encoding="utf-8",
    )
    ckl = tmp_path / "host_2026-09-20.ckl"
    ckl.write_text(
        """<?xml version="1.0"?>
        <CHECKLIST><ASSET><HOST_FQDN>rhel-mission01.lab.local</HOST_FQDN></ASSET>
        <STIGS><iSTIG><VULN>
          <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-230296</ATTRIBUTE_DATA></STIG_DATA>
          <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-230296r858711_rule</ATTRIBUTE_DATA></STIG_DATA>
          <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>RHEL-08-010550</ATTRIBUTE_DATA></STIG_DATA>
          <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
          <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Direct SSH logons as root must be disabled.</ATTRIBUTE_DATA></STIG_DATA>
          <STATUS>Open</STATUS>
          <COMMENTS>bench</COMMENTS>
          <FINDING_DETAILS></FINDING_DETAILS>
          <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
          <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
        </VULN></iSTIG></STIGS></CHECKLIST>
        """,
        encoding="utf-8",
    )
    observations = parse_xccdf(xml) + parse_ckl(ckl)
    ledger = _ledger(observations)
    matches = [item for item in ledger["findings"] if item["control"] == "RHEL-08-010550"]
    assert len(matches) == 1
    assert matches[0]["vuln_num"] == "V-230296"
    assert [point["date"] for point in matches[0]["history"]] == ["2026-08-20", "2026-09-20"]


def test_acas_drop_closes_and_return_regresses(tmp_path: Path):
    first = tmp_path / "acas_2026-08-20.csv"
    second = tmp_path / "acas_2026-09-20.csv"
    header = "Plugin ID,CVE,CVSS,Risk,Host,Name\n"
    first.write_text(
        header + "187315,CVE-2023-48795,5.9,Medium,mission.lab,Terrapin\n201194,CVE-2024-6387,8.1,High,mission.lab,regreSSHion\n",
        encoding="utf-8",
    )
    second.write_text(header + "201194,CVE-2024-6387,8.1,High,mission.lab,regreSSHion\n", encoding="utf-8")
    observations = parse_acas(first) + parse_acas(second)
    ledger = _ledger(observations)
    terrapin = next(item for item in ledger["findings"] if item["control"] == "CVE-2023-48795")
    race = next(item for item in ledger["findings"] if item["control"] == "CVE-2024-6387")
    assert terrapin["clock"] == "closed"
    assert race["cat"] == "I"
    assert race["clock"] != "closed"


def test_exception_expiry_and_pending(tmp_path: Path):
    path = tmp_path / "host_2026-07-15.ckl"
    path.write_text(
        """<?xml version="1.0"?>
        <CHECKLIST><ASSET><HOST_FQDN>wsus01.lab.local</HOST_FQDN></ASSET><STIGS><iSTIG>
        <VULN>
          <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>WN22-00-000380</ATTRIBUTE_DATA></STIG_DATA>
          <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
          <STATUS>Open</STATUS>
          <COMMENTS></COMMENTS><FINDING_DETAILS></FINDING_DETAILS>
          <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE><SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
        </VULN>
        </iSTIG></STIGS></CHECKLIST>""",
        encoding="utf-8",
    )
    later = tmp_path / "host_2026-09-20.ckl"
    later.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    observations = parse_scan(path) + parse_scan(later)
    expired = _ledger(
        observations,
        exceptions=[
            {
                "id": "EX-007",
                "host": "wsus01.lab.local",
                "control": "WN22-00-000380",
                "status": "approved",
                "expires": "2026-09-01",
                "rationale": "old",
                "compensating": "vlan",
            }
        ],
    )
    finding = expired["findings"][0]
    assert finding["clock"] == "overdue"
    assert finding["due"] == "2026-09-01"
    assert "exception_expired" in finding["flags"]

    pending = _ledger(
        observations,
        exceptions=[
            {
                "id": "EX-1",
                "host": "wsus01.lab.local",
                "control": "WN22-00-000380",
                "status": "pending",
                "expires": "2026-12-01",
                "rationale": "waiting",
                "compensating": "",
            }
        ],
    )
    assert pending["findings"][0]["clock"] == "due_soon"
    assert "exception_pending" in pending["findings"][0]["flags"]

    approved = _ledger(
        observations,
        exceptions=[
            {
                "id": "EX-2",
                "host": "wsus01.lab.local",
                "control": "WN22-00-000380",
                "status": "approved",
                "expires": "2026-10-15",
                "rationale": "still good",
                "compensating": "recorded",
            }
        ],
    )
    assert approved["findings"][0]["clock"] == "excepted"


def test_regression_restarts_clock():
    from findings.models import Observation

    def obs(day: str, result: str) -> Observation:
        return Observation(
            host="mission.lab",
            observed_at=date.fromisoformat(day),
            source="xccdf",
            source_file="x",
            rule_ver="RHEL-08-030180",
            title="audit",
            severity="medium",
            result=result,
        )

    restarted = _ledger([obs("2026-07-15", "fail"), obs("2026-08-20", "pass"), obs("2026-09-20", "fail")])
    finding = restarted["findings"][0]
    assert finding["regression"] is True
    assert finding["first_seen"] == "2026-09-20"
    assert finding["due"] == "2026-12-19"
    assert finding["clock"] == "on_track"

    held = _ledger(
        [obs("2026-07-15", "fail"), obs("2026-08-20", "pass"), obs("2026-09-20", "fail")],
        policy=Policy(sla_days={"I": 30, "II": 90, "III": 365}, regression_restarts_clock=False),
    )
    assert held["findings"][0]["due"] == "2026-10-13"


def test_vsphere_snapshot_and_incomplete_govc():
    checks = checks_from_snapshot(
        {
            "host": "esxi01.lab.local",
            "observed_at": "2026-09-20",
            "lockdown_mode": "lockdownNormal",
            "ssh_running": False,
            "ntp_running": True,
            "ntp_servers": ["ad01.lab.local"],
            "ntp_circular_with": ["ad01.lab.local"],
            "syslog_log_host": "",
        }
    )
    by_rule = {item["rule_ver"]: item["result"] for item in checks}
    assert by_rule["ESXI-80-000008"] == "pass"
    assert by_rule["ESXI-80-000193"] == "pass"
    assert by_rule["ESXI-80-000124"] == "fail"
    assert by_rule["ESXI-80-000114"] == "fail"
    try:
        snapshot_from_govc_outputs("esxi01", "2026-09-20", "[]", "{}", "")
    except ValueError as exc:
        assert "refusing" in str(exc)
    else:
        raise AssertionError("incomplete govc output should fail closed")


def test_lab_story(tmp_path: Path):
    root = Path("fixtures/lab")
    scans = tmp_path / "scans"
    write_lab_scans(scans)
    observations = []
    for path in sorted(scans.iterdir()):
        observations.extend(parse_scan(path))
    ledger = _ledger(
        observations,
        hosts=json.loads((root / "hosts.json").read_text(encoding="utf-8")),
        exceptions=json.loads((root / "exceptions.json").read_text(encoding="utf-8")),
        backups=json.loads((root / "backups.json").read_text(encoding="utf-8")),
        services=json.loads((root / "services.json").read_text(encoding="utf-8")),
        site=json.loads((root / "site.json").read_text(encoding="utf-8")),
        milestones=json.loads((root / "milestones.json").read_text(encoding="utf-8")),
        duties=json.loads((root / "duties.json").read_text(encoding="utf-8")),
    )
    by_control = {(item["host_short"], item["control"]): item for item in ledger["findings"]}
    gpg = by_control[("rhel-repo01", "RHEL-08-010370")]
    assert gpg["cat"] == "I" and gpg["clock"] == "overdue" and gpg["days_overdue"] == 44
    assert gpg["remediation"]["class"] == "automate"
    localpkg = by_control[("rhel-mission01", "RHEL-08-010371")]
    assert localpkg["clock"] == "overdue" and localpkg["due"] == "2026-09-19"
    smb = by_control[("wsus01", "WN22-00-000380")]
    assert smb["clock"] == "overdue" and "exception_expired" in smb["flags"]
    ssh = by_control[("esxi01", "ESXI-80-000193")]
    assert ssh["clock"] == "excepted"
    audit = by_control[("rhel-mission01", "RHEL-08-030180")]
    assert audit["regression"] is True and audit["drift"] == "regressed"
    assert by_control[("rhel-repo01", "RHEL-08-010550")]["clock"] == "closed"
    assert by_control[("wsus01", "WN22-AC-000070")]["remediation"]["class"] == "gpo"
    assert "severity_unverified" in by_control[("ad01", "WN22-DC-000060")]["flags"]
    assert by_control[("ad01", "WN22-DC-000060")]["remediation"]["class"] == "do-not-automate"
    race = by_control[("rhel-mission01", "CVE-2024-6387")]
    assert race["cat"] == "I" and race["clock"] == "due_soon" and race["drift"] == "new"
    wsus = next(item for item in ledger["backups"] if item["host"].startswith("wsus"))
    assert wsus["status"] == "breach" and wsus["rpo_met"] is False and wsus["restore_met"] is False
    ad = next(item for item in ledger["backups"] if item["host"].startswith("ad01"))
    assert ad["status"] == "ok"
    assert ledger["handoff"]["ready"] is False
    assert ledger["stats"]["regressions"] == 1
    gate = {(item["host_short"], item["control"]): item for item in ledger["apply_gate"]["decisions"]}
    assert gate[("esxi01", "ESXI-80-000193")]["action"] == "refuse"
    assert "EX-014" in gate[("esxi01", "ESXI-80-000193")]["reason"]
    assert gate[("esxi01", "ESXI-80-000124")]["action"] == "refuse"
    assert "take time from each other" in gate[("esxi01", "ESXI-80-000124")]["reason"]
    assert gate[("ad01", "WN22-DC-000060")]["action"] == "refuse"
    assert gate[("esxi01", "ESXI-80-000114")]["action"] == "refuse"
    assert gate[("wsus01", "WN22-00-000380")]["action"] == "refuse"
    assert "backup" in gate[("wsus01", "WN22-00-000380")]["reason"].lower()
    assert gate[("wsus01", "WN22-AC-000070")]["action"] == "refuse"
    assert gate[("rhel-repo01", "RHEL-08-010370")]["action"] == "probe"
    assert gate[("rhel-mission01", "RHEL-08-010550")]["action"] == "bundle"
    assert gate[("rhel-mission01", "RHEL-08-010370")]["action"] == "hollow"
    assert "hollow_pass" in by_control[("rhel-mission01", "RHEL-08-010370")]["flags"]
    assert "vcenter01.lab.local" in ledger["apply_gate"]["unscanned"]
    assert gate[("rhel-repo01", "RHEL-08-020230")]["action"] == "allow"
    evidence = tmp_path / "evidence"
    write_evidence(ledger, evidence)
    poam = (evidence / "poam.csv").read_text(encoding="utf-8")
    assert "RHEL-08-010370" in poam
    assert "Risk accepted" in poam
    assert "ESXI-80-000193" in poam


def test_signed_exception_blocks_until_the_day_after():
    from findings.gate import build_apply_gate

    def row(today: date):
        finding = {
            "host": "esxi01.lab.local",
            "host_short": "esxi01",
            "control": "ESXI-80-000193",
            "slug": "esxi01--ESXI-80-000193",
            "clock": "excepted" if today <= date(2026, 10, 15) else "overdue",
            "due": "2026-10-15" if today <= date(2026, 10, 15) else "2026-10-15",
            "result": "fail",
            "exception_id": "EX-014",
            "flags": [] if today <= date(2026, 10, 15) else ["exception_expired"],
            "remediation": {"class": "do-not-automate", "why": "Leave SSH.", "summary": "", "avoid": "", "verify": ""},
        }
        if today > date(2026, 10, 15):
            finding["clock"] = "overdue"
        gate = build_apply_gate(findings=[finding], hosts=[], backups=[], duties={}, today=today, current=None)
        return gate["decisions"][0]

    assert row(date(2026, 10, 15))["action"] == "refuse"
    assert "EX-014" in row(date(2026, 10, 15))["reason"]
    later = row(date(2026, 10, 16))
    assert later["action"] == "refuse"
    assert "EX-014" not in later["reason"]


def test_bad_export_does_not_write_a_ledger(tmp_path: Path):
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "broken.xml").write_text("<Benchmark><unclosed>", encoding="utf-8")
    (scans / "nohost_2026-09-20.csv").write_text("Plugin ID,Risk,Name\n201194,High,Example\n", encoding="utf-8")
    (scans / "results.nessus").write_text("<NessusClientData_v2></NessusClientData_v2>", encoding="utf-8")
    (scans / "repo_2026-09-20.xml").write_text(
        """<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
          <TestResult id="r" start-time="2026-09-20T02:10:00">
            <target>rhel-repo01.lab.local</target>
            <rule-result idref="xccdf_mil.disa.stig_rule_SV-230264r880711_rule">
              <result>fail</result>
            </rule-result>
          </TestResult>
        </Benchmark>
        """,
        encoding="utf-8",
    )
    observations, problems = load_scans(scans)
    assert observations
    assert any("not valid XML" in item for item in problems)
    assert any("no Host column" in item for item in problems)
    assert any(".nessus" in item for item in problems)

    out = tmp_path / "ledger.json"
    code = main(
        [
            "ingest",
            "--scan",
            str(scans),
            "--hosts",
            "fixtures/lab/hosts.json",
            "--exceptions",
            "fixtures/lab/exceptions.json",
            "--backups",
            "fixtures/lab/backups.json",
            "--services",
            "fixtures/lab/services.json",
            "--site",
            "fixtures/lab/site.json",
            "--milestones",
            "fixtures/lab/milestones.json",
            "--out",
            str(out),
        ]
    )
    assert code == 2
    assert not out.exists()


def test_empty_directory_and_unknown_result_are_problems(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    observations, problems = load_scans(empty)
    assert observations == []
    assert any("no scan exports" in item for item in problems)

    weird = tmp_path / "weird_2026-09-20.ckl"
    weird.write_text(
        """<?xml version="1.0"?>
        <CHECKLIST>
          <ASSET><HOST_FQDN>wsus01.lab.local</HOST_FQDN></ASSET>
          <STIGS><iSTIG><VULN>
            <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>WN22-00-000380</ATTRIBUTE_DATA></STIG_DATA>
            <STATUS>Maybe</STATUS>
          </VULN></iSTIG></STIGS>
        </CHECKLIST>
        """,
        encoding="utf-8",
    )
    observations, problems = load_scans(weird)
    assert observations == []
    assert any("not recognized" in item for item in problems)


def test_demo_writes_a_ledger(tmp_path: Path):
    out = tmp_path / "ledger.json"
    evidence = tmp_path / "evidence"
    plan = tmp_path / "plan.yml"
    gate_path = tmp_path / "apply-gate.json"
    code = main(
        [
            "demo",
            "--out",
            str(out),
            "--evidence",
            str(evidence),
            "--plan",
            str(plan),
            "--gate",
            str(gate_path),
            "--scans",
            str(tmp_path / "scans"),
        ]
    )
    assert code == 0
    assert out.is_file()
    text = json.loads(out.read_text(encoding="utf-8"))
    assert text["tool"] == "findings-register"
    assert text["site"]["name"] == "Integration Lab"
    plan_text = plan.read_text(encoding="utf-8")
    assert "Generated by the findings register" in plan_text
    attestation = (evidence / "attestation.json").read_text(encoding="utf-8")
    assert "did not scan a host" in attestation
    assert gate_path.is_file()
    assert "refuse" in gate_path.read_text(encoding="utf-8")


def test_revert_paths_are_documented():
    play = Path("ansible/revert.yml").read_text(encoding="utf-8")
    assert "latest-path.txt" in play
    assert "restart-sshd" in play
    assert "audit package was not removed" in play
    role = Path("ansible/roles/rhel_baseline/tasks/main.yml").read_text(encoding="utf-8")
    assert "baseline_backup_dir" in role
    script = Path("windows/Invoke-BaselineAudit.ps1").read_text(encoding="utf-8")
    assert "not both" in script
    assert "FS-SMB1-before.xml" in script
    assert "will not write local policy" in script
    assert "No apply gate" in script
    assert "Refusing to change the host" in script
    role = Path("ansible/roles/rhel_baseline/tasks/main.yml").read_text(encoding="utf-8")
    assert "findings_gate" in role
    assert "rpm" in role or "item.probe" in role
