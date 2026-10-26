from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from findings.ledger import build_ledger
from findings.parsers import load_scans, parse_scan
from findings.policy import DEFAULT_POLICY
from findings.windows import checks_from_snapshot, observations_from_checks

TODAY = date(2026, 9, 27)
MILESTONES = {"baseline": "2026-07-15", "previous": "2026-08-20", "current": "2026-09-20"}


def _snapshot(**overrides) -> dict:
    base = {
        "kind": "windows-posture",
        "host": "ad01.lab.local",
        "observed_at": "2026-09-27T14:02:11Z",
        "is_domain_controller": True,
        "time_source": "esxi01.lab.local,0x9",
        "time_type": "NTP (Local)",
        "smb1_installed": False,
        "password_policy_source": "Default Domain Policy",
        "pending_reboot": False,
        "wsus_target_group": "Servers",
        "wsus_server": "http://wsus01.lab.local:8530",
        "probe_errors": [],
    }
    base.update(overrides)
    return base


def _by_rule(checks: list[dict]) -> dict[str, dict]:
    return {item["rule_ver"]: item for item in checks}


def _ledger(observations):
    return build_ledger(
        observations,
        policy=DEFAULT_POLICY,
        today=TODAY,
        hosts=[],
        exceptions=[],
        backups=[],
        services=[],
        site={"name": "Test"},
        milestones=MILESTONES,
    )


def test_dc_following_esxi_is_a_loop_and_fails():
    checks = _by_rule(checks_from_snapshot(_snapshot(), allowed_time_sources=["ntp.lab.local"]))
    time = checks["WN22-DC-000060"]
    assert time["result"] == "fail"
    assert "esxi01.lab.local" in time["detail"]
    assert ",0x9" not in time["detail"]
    assert "not an allowed source" in time["detail"]
    assert checks["WN22-00-000380"]["result"] == "pass"
    assert checks["WN22-AC-000070"]["detail"] == "set by GPO Default Domain Policy"


def test_dc_time_source_allowed_passes_and_cmos_fails():
    allowed = _snapshot(time_source="ntp.lab.local", allowed_time_sources=["ntp.lab.local"])
    assert _by_rule(checks_from_snapshot(allowed))["WN22-DC-000060"]["result"] == "pass"
    for bad in ("Local CMOS Clock", "Free-running System Clock", "", "   "):
        checks = _by_rule(checks_from_snapshot(_snapshot(time_source=bad), allowed_time_sources=["ntp.lab.local"]))
        assert checks["WN22-DC-000060"]["result"] == "fail", bad


def test_dc_peer_with_no_allowed_list_is_not_reviewed():
    checks = _by_rule(checks_from_snapshot(_snapshot()))
    assert checks["WN22-DC-000060"]["result"] == "notchecked"
    assert "No allowed time source list" in checks["WN22-DC-000060"]["detail"]


def test_member_server_has_no_dc_time_check():
    snapshot = _snapshot(
        host="wsus01.lab.local",
        is_domain_controller=False,
        time_source="ad01.lab.local",
        smb1_installed=True,
        password_policy_source="local",
    )
    checks = _by_rule(checks_from_snapshot(snapshot))
    assert "WN22-DC-000060" not in checks
    assert checks["WN22-00-000380"]["result"] == "fail"
    assert checks["WN22-00-000380"]["detail"] == "FS-SMB1 is installed."
    assert checks["WN22-AC-000070"]["detail"] == "local"


def test_password_policy_note_is_not_an_observation():
    checks = checks_from_snapshot(_snapshot(is_domain_controller=False))
    observations = observations_from_checks(checks, source_file="snap.json")
    assert [item.rule_ver for item in observations] == ["WN22-00-000380"]
    assert observations[0].source == "windows"
    assert observations[0].vuln_num == "V-254275"


def test_nulls_are_not_reviewed_not_passed():
    snapshot = _snapshot(
        is_domain_controller=None,
        time_source=None,
        smb1_installed=None,
        password_policy_source=None,
        probe_errors=["smb1_installed: Get-WindowsFeature is not recognized"],
    )
    checks = _by_rule(checks_from_snapshot(snapshot))
    assert checks["WN22-00-000380"]["result"] == "notchecked"
    assert "Get-WindowsFeature is not recognized" in checks["WN22-00-000380"]["detail"]
    assert checks["WN22-DC-000060"]["result"] == "notchecked"
    assert checks["WN22-AC-000070"]["detail"].startswith("Password policy source was not recorded")

    dc_without_source = _by_rule(checks_from_snapshot(_snapshot(time_source=None)))
    assert dc_without_source["WN22-DC-000060"]["result"] == "notchecked"

    observations = observations_from_checks(list(checks.values()))
    assert {item.result for item in observations} == {"notchecked"}


def test_smb1_raw_state_strings():
    assert _by_rule(checks_from_snapshot(_snapshot(smb1_installed="Installed")))["WN22-00-000380"]["result"] == "fail"
    assert _by_rule(checks_from_snapshot(_snapshot(smb1_installed="Available")))["WN22-00-000380"]["result"] == "pass"
    assert _by_rule(checks_from_snapshot(_snapshot(smb1_installed="maybe")))["WN22-00-000380"]["result"] == "notchecked"


def test_reboot_pending_adds_detail():
    removed = _by_rule(checks_from_snapshot(_snapshot(smb1_installed=False, pending_reboot=True)))
    assert removed["WN22-00-000380"]["result"] == "pass"
    assert removed["WN22-00-000380"]["detail"] == "FS-SMB1 is not installed. Feature removed, reboot pending."
    still = _by_rule(checks_from_snapshot(_snapshot(smb1_installed=True, pending_reboot=True)))
    assert still["WN22-00-000380"]["detail"] == "FS-SMB1 is installed. Reboot pending."
    quiet = _by_rule(checks_from_snapshot(_snapshot(pending_reboot=None)))
    assert "reboot" not in quiet["WN22-00-000380"]["detail"].lower()


def test_kind_routes_json(tmp_path: Path):
    windows = tmp_path / "ad01_2026-09-27.json"
    windows.write_text("﻿" + json.dumps(_snapshot(is_domain_controller=False)), encoding="utf-8")
    found = parse_scan(windows)
    assert {item.source for item in found} == {"windows"}
    assert found[0].observed_at == date(2026, 9, 27)

    esxi = tmp_path / "esxi01_2026-09-20.json"
    esxi.write_text(
        json.dumps(
            {
                "host": "esxi01.lab.local",
                "observed_at": "2026-09-20",
                "lockdown_mode": "lockdownNormal",
                "ssh_running": False,
                "ntp_running": True,
                "ntp_servers": ["ntp.lab.local"],
                "syslog_log_host": "udp://log.lab.local:514",
            }
        ),
        encoding="utf-8",
    )
    assert {item.source for item in parse_scan(esxi)} == {"vsphere"}


def test_windows_snapshot_and_ckl_merge(tmp_path: Path):
    (tmp_path / "wsus01_2026-09-20.ckl").write_text(
        """<?xml version="1.0"?>
        <CHECKLIST>
          <ASSET><HOST_FQDN>wsus01.lab.local</HOST_FQDN></ASSET>
          <STIGS><iSTIG>
            <STIG_INFO><SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Windows</SID_DATA></SI_DATA></STIG_INFO>
            <VULN>
              <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-254275</ATTRIBUTE_DATA></STIG_DATA>
              <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>WN22-00-000380</ATTRIBUTE_DATA></STIG_DATA>
              <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
              <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>No SMBv1</ATTRIBUTE_DATA></STIG_DATA>
              <STATUS>Open</STATUS>
            </VULN>
          </iSTIG></STIGS>
        </CHECKLIST>
        """,
        encoding="utf-8",
    )
    snapshot = _snapshot(
        host="WSUS01.lab.local",
        is_domain_controller=False,
        smb1_installed=True,
        password_policy_source="local",
    )
    (tmp_path / "wsus01_2026-09-27.json").write_text(json.dumps(snapshot), encoding="utf-8")

    observations, problems = load_scans(tmp_path)
    assert problems == []
    ledger = _ledger(observations)
    smb1 = [item for item in ledger["findings"] if item["control"] == "WN22-00-000380"]
    assert len(smb1) == 1
    history = smb1[0]["history"]
    assert [point["date"] for point in history] == ["2026-09-20", "2026-09-27"]
    assert history[-1]["sources"] == ["windows"]
    assert {source for point in history for source in point["sources"]} == {"ckl", "windows"}
    assert not any(item["control"] == "WN22-AC-000070" for item in ledger["findings"])
