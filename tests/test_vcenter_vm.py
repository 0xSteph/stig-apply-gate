from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from findings.lab import VCENTER_SNAPSHOT, VM_SNAPSHOT, write_lab_scans
from findings.ledger import build_ledger
from findings.parsers import load_scans, parse_scan
from findings.policy import DEFAULT_POLICY
from findings.vsphere import (
    VCENTER_CHECKS,
    VM_CHECKS,
    VM_SETTINGS,
    checks_for_snapshot,
    vcenter_checks_from_snapshot,
    vcenter_snapshot_from_govc_outputs,
    vm_checks_from_snapshot,
    vm_snapshot_from_govc_outputs,
)

LAB = Path("fixtures/lab")
TODAY = date(2026, 9, 27)


def _by_rule(checks: list[dict]) -> dict[str, dict]:
    return {check["rule_ver"]: check for check in checks}


def _load(name: str):
    return json.loads((LAB / name).read_text(encoding="utf-8"))


def _write(path: Path, snapshot: dict) -> Path:
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    return path


def test_vcenter_snapshot_to_checks():
    checks = _by_rule(vcenter_checks_from_snapshot(VCENTER_SNAPSHOT))
    assert set(checks) == set(VCENTER_CHECKS)
    assert checks["VCSA-80-000089"]["result"] == "fail"
    assert "120 minutes" in checks["VCSA-80-000089"]["detail"]
    for rule in ("VCSA-80-000158", "VCSA-80-000148", "VCSA-80-000023", "VCSA-80-000266", "VCSA-80-000079"):
        assert checks[rule]["result"] == "pass", rule
    assert checks["VCSA-80-000089"]["vuln_num"] == "V-258920"
    assert checks["VCSA-80-000089"]["severity"] == "medium"
    assert checks["VCSA-80-000089"]["benchmark"] == "VMware vSphere 8.0 vCenter STIG"

    worse = {
        **VCENTER_SNAPSHOT,
        "ntp_servers": [],
        "syslog_targets": [],
        "sso_lockout_failures": 0,
        "sso_lockout_unlock_seconds": 300,
        "sso_password_max_days": 180,
        "session_timeout_minutes": 15,
    }
    results = {rule: check["result"] for rule, check in _by_rule(vcenter_checks_from_snapshot(worse)).items()}
    assert results == {
        "VCSA-80-000158": "fail",
        "VCSA-80-000148": "fail",
        "VCSA-80-000023": "fail",
        "VCSA-80-000266": "fail",
        "VCSA-80-000079": "fail",
        "VCSA-80-000089": "pass",
    }


def test_vm_snapshot_to_checks():
    checks = _by_rule(vm_checks_from_snapshot(VM_SNAPSHOT))
    assert set(checks) == set(VM_CHECKS)
    assert checks["VMCH-80-000197"]["result"] == "fail"
    # Unset drag and drop is not a finding in the benchmark; the vSphere 8 default is disabled.
    assert checks["VMCH-80-000191"]["result"] == "pass"
    assert "not set" in checks["VMCH-80-000191"]["detail"]
    for rule in ("VMCH-80-000189", "VMCH-80-000192", "VMCH-80-000193", "VMCH-80-000194", "VMCH-80-000195", "VMCH-80-000198"):
        assert checks[rule]["result"] == "pass", rule
    assert all(check["host"] == "rhel-mission01.lab.local" for check in checks.values())
    assert checks["VMCH-80-000189"]["severity"] == "low"
    assert checks["VMCH-80-000197"]["cci"] == ["CCI-000366"]

    # RemoteDisplay.maxConnections is the one setting where unset is a finding.
    unset = {**VM_SNAPSHOT, "RemoteDisplay.maxConnections": None, "tools.guestlib.enableHostInfo": "TRUE"}
    checks = _by_rule(vm_checks_from_snapshot(unset))
    assert checks["VMCH-80-000195"]["result"] == "fail"
    assert checks["VMCH-80-000198"]["result"] == "fail"


def test_missing_fields_are_not_reviewed():
    vcenter = {
        "kind": "vcenter-posture",
        "host": "vcenter01.lab.local",
        "observed_at": "2026-09-20",
        "ntp_servers": ["time1.lab.local"],
        "sso_lockout_failures": None,
        "probe_errors": ["SSO policy was not readable"],
    }
    checks = _by_rule(vcenter_checks_from_snapshot(vcenter))
    assert checks["VCSA-80-000158"]["result"] == "pass"
    for rule in ("VCSA-80-000148", "VCSA-80-000023", "VCSA-80-000266", "VCSA-80-000079", "VCSA-80-000089"):
        assert checks[rule]["result"] == "notchecked", rule
    assert "SSO policy was not readable" in checks["VCSA-80-000023"]["detail"]

    vm = {key: value for key, value in VM_SNAPSHOT.items() if key != "isolation.device.connectable.disable"}
    checks = _by_rule(vm_checks_from_snapshot(vm))
    assert checks["VMCH-80-000197"]["result"] == "notchecked"
    assert "was not read" in checks["VMCH-80-000197"]["detail"]

    ledger = build_ledger(
        [*_observations(tmp_snapshot=vcenter)],
        policy=DEFAULT_POLICY,
        today=TODAY,
        hosts=[],
        exceptions=[],
        backups=[],
        services=[],
        site={"name": "Test"},
        milestones={"current": "2026-09-20"},
    )
    clocks = {item["control"]: item["clock"] for item in ledger["findings"]}
    assert clocks["VCSA-80-000089"] == "not_reviewed"
    assert clocks["VCSA-80-000158"] == "closed"


def _observations(tmp_snapshot: dict):
    from findings.vsphere import observations_from_checks

    return observations_from_checks(checks_for_snapshot(tmp_snapshot), source_file="vcenter01_2026-09-20.json")


def test_wrong_types_are_refused():
    with pytest.raises(ValueError):
        vcenter_checks_from_snapshot({**VCENTER_SNAPSHOT, "session_timeout_minutes": "15"})
    with pytest.raises(ValueError):
        vcenter_checks_from_snapshot({**VCENTER_SNAPSHOT, "ntp_servers": "esxi01.lab.local"})
    with pytest.raises(ValueError):
        vm_checks_from_snapshot({**VM_SNAPSHOT, "isolation.tools.copy.disable": ["true"]})
    with pytest.raises(ValueError):
        checks_for_snapshot({**VCENTER_SNAPSHOT, "kind": "nsx-posture"})


def test_parse_scan_routes_by_kind(tmp_path: Path):
    vcenter = parse_scan(_write(tmp_path / "vcenter01_2026-09-20.json", VCENTER_SNAPSHOT))
    assert {item.rule_ver for item in vcenter} == set(VCENTER_CHECKS)
    assert {item.platform for item in vcenter} == {"vcenter"}
    assert {item.benchmark for item in vcenter} == {"VMware vSphere 8.0 vCenter STIG"}

    vm = parse_scan(_write(tmp_path / "rhel-mission01-vm_2026-09-20.json", VM_SNAPSHOT))
    assert {item.rule_ver for item in vm} == set(VM_CHECKS)
    assert {item.host for item in vm} == {"rhel-mission01.lab.local"}
    assert {item.benchmark for item in vm} == {"VMware vSphere 8.0 Virtual Machine STIG"}

    esxi = _load("scans/esxi01_2026-09-20.json")
    assert "kind" not in esxi
    plain = parse_scan(_write(tmp_path / "esxi01_2026-09-20.json", esxi))
    tagged = parse_scan(_write(tmp_path / "esxi01-tagged_2026-09-20.json", {**esxi, "kind": "esxi-posture"}))
    assert [item.rule_ver for item in plain] == [item.rule_ver for item in tagged]
    assert [item.result for item in plain] == [item.result for item in tagged]
    assert {item.benchmark for item in plain} == {"VMware vSphere 8.0 ESXi STIG"}
    assert {item.platform for item in plain} == {"esxi"}

    other = tmp_path / "other"
    other.mkdir()
    _write(other / "x_2026-09-20.json", {**esxi, "kind": "nsx-posture"})
    _found, problems = load_scans(other)
    assert problems and "nsx-posture" in problems[0]


def test_govc_incomplete_output_refuses():
    with pytest.raises(ValueError, match="VirtualCenter"):
        vcenter_snapshot_from_govc_outputs("esxi01.lab.local", "2026-09-20", json.dumps({"About": {"ApiType": "HostAgent"}}))
    with pytest.raises(ValueError, match="exactly one"):
        vm_snapshot_from_govc_outputs("rhel-mission01", "vcenter01", "2026-09-20", json.dumps({"VirtualMachines": []}))
    with pytest.raises(ValueError, match="extraConfig"):
        vm_snapshot_from_govc_outputs(
            "rhel-mission01",
            "vcenter01",
            "2026-09-20",
            json.dumps({"VirtualMachines": [{"Name": "rhel-mission01", "Config": {"Name": "rhel-mission01"}}]}),
        )
    with pytest.raises(ValueError, match="config"):
        vm_snapshot_from_govc_outputs("rhel-mission01", "vcenter01", "2026-09-20", json.dumps({"virtualMachines": [{"name": "x"}]}))


def test_govc_complete_output_normalizes():
    about = json.dumps({"About": {"ApiType": "VirtualCenter", "Version": "8.0.3"}})
    snapshot = vcenter_snapshot_from_govc_outputs("vcenter01.lab.local", "2026-09-20", about)
    assert snapshot["kind"] == "vcenter-posture"
    assert snapshot["session_timeout_minutes"] is None and snapshot["probe_errors"]
    assert {check["result"] for check in vcenter_checks_from_snapshot(snapshot)} == {"notchecked"}

    info = {
        "virtualMachines": [
            {
                "name": "rhel-mission01",
                "config": {
                    "extraConfig": [
                        {"key": "isolation.tools.copy.disable", "value": "TRUE"},
                        {"key": "isolation.device.connectable.disable", "value": "FALSE"},
                        {"key": "tools.guestlib.enableHostInfo", "value": False},
                    ]
                },
            }
        ]
    }
    snapshot = vm_snapshot_from_govc_outputs(
        "rhel-mission01", "vcenter01.lab.local", "2026-09-20", json.dumps(info), ledger_host="rhel-mission01.lab.local"
    )
    assert snapshot["host"] == "rhel-mission01.lab.local"
    assert set(VM_SETTINGS) <= set(snapshot)
    assert snapshot["isolation.tools.paste.disable"] is None
    assert snapshot["tools.guestlib.enableHostInfo"] == "false"
    checks = _by_rule(vm_checks_from_snapshot(snapshot))
    assert checks["VMCH-80-000197"]["result"] == "fail"
    assert checks["VMCH-80-000195"]["result"] == "fail"
    assert checks["VMCH-80-000189"]["result"] == "pass"


def test_lab_scans_match_the_generator(tmp_path: Path):
    scans = tmp_path / "scans"
    write_lab_scans(scans)
    for name in ("vcenter01_2026-09-20.json", "rhel-mission01-vm_2026-09-20.json"):
        written = (scans / name).read_bytes()
        assert b"\r\n" not in written
        assert written == (LAB / "scans" / name).read_bytes(), name


def _lab_ledger(tmp_path: Path, services: list[dict] | None = None, drop: tuple[str, ...] = ()) -> dict:
    scans = tmp_path / "scans"
    write_lab_scans(scans)
    for name in drop:
        (scans / name).unlink()
    observations, problems = load_scans(scans)
    assert problems == []
    return build_ledger(
        observations,
        policy=DEFAULT_POLICY,
        today=TODAY,
        hosts=_load("hosts.json"),
        exceptions=_load("exceptions.json"),
        backups=_load("backups.json"),
        services=services if services is not None else _load("services.json"),
        site=_load("site.json"),
        milestones=_load("milestones.json"),
        duties=_load("duties.json"),
    )


def test_lab_demo_includes_vcenter_and_vm_rows(tmp_path: Path):
    ledger = _lab_ledger(tmp_path)
    rows = {(item["host_short"], item["control"]): item for item in ledger["findings"]}
    vcenter = {control for host, control in rows if host == "vcenter01"}
    assert vcenter == set(VCENTER_CHECKS)
    vm = {control for host, control in rows if host == "rhel-mission01" and control.startswith("VMCH-80-")}
    assert vm == set(VM_CHECKS)

    timeout = rows[("vcenter01", "VCSA-80-000089")]
    assert timeout["clock"] == "on_track" and timeout["cat"] == "II"
    assert timeout["remediation"]["class"] == "manual"
    device = rows[("rhel-mission01", "VMCH-80-000197")]
    assert device["clock"] == "on_track" and device["remediation"]["class"] == "manual"
    assert rows[("vcenter01", "VCSA-80-000148")]["remediation"]["class"] == "blocked"

    decisions = {(item["host_short"], item["control"]): item for item in ledger["apply_gate"]["decisions"]}
    assert decisions[("vcenter01", "VCSA-80-000089")]["action"] == "refuse"
    assert decisions[("vcenter01", "VCSA-80-000089")]["tag"] is None
    assert decisions[("rhel-mission01", "VMCH-80-000197")]["action"] == "refuse"
    # vCenter's NTP passes on its own, but it takes time from esxi01, which is in the loop with ad01.
    assert decisions[("vcenter01", "VCSA-80-000158")]["action"] == "hollow"
    assert "vcenter01.lab.local" not in ledger["apply_gate"]["unscanned"]


def test_host_without_a_scan_this_period_is_unscanned(tmp_path: Path):
    ledger = _lab_ledger(tmp_path, drop=("vcenter01_2026-09-20.json",))
    assert ledger["apply_gate"]["unscanned"] == ["vcenter01.lab.local"]
    gates = {gate["id"]: gate for gate in ledger["handoff"]["gates"]}
    assert gates["unscanned"]["status"] == "fail"


def test_vcenter_runbook_leaves_only_dhcp(tmp_path: Path):
    services = _load("services.json")
    vcenter = next(item for item in services if item["name"] == "vCenter")
    assert vcenter["runbook"] == "docs/runbooks/vcenter.md"
    assert Path(vcenter["runbook"]).is_file()
    text = Path(vcenter["runbook"]).read_text(encoding="utf-8")
    assert "## Check" in text and "## What not to do" in text

    gates = {gate["id"]: gate for gate in _lab_ledger(tmp_path)["handoff"]["gates"]}
    assert gates["runbooks"]["status"] == "fail"
    assert gates["runbooks"]["detail"] == "DHCP"
