"""Read-only ESXi posture checks.

The supported input is a snapshot dict. Live collection, when used, only
issues govc reads and refuses to run if the command would change a host.
"""

from __future__ import annotations

import json
from datetime import date

from findings.models import Observation

# Public STIG version identifiers. Severities below are the benchmark
# severities (medium == CAT II), not a local upgrade.
ESXI_CHECKS = {
    "ESXI-80-000008": {
        "vuln_num": "V-258730",
        "rule_id": "SV-258730r958398_rule",
        "severity": "medium",
        "cci": ["CCI-000054"],
        "nist": ["AC-10"],
        "title": "ESXi lockdown mode must be enabled.",
    },
    "ESXI-80-000193": {
        "vuln_num": "V-258754",
        "rule_id": "SV-258754r958478_rule",
        "severity": "medium",
        "cci": ["CCI-000381"],
        "nist": ["CM-7"],
        "title": "The ESXi SSH service must be stopped.",
    },
    "ESXI-80-000124": {
        "vuln_num": "V-258745",
        "rule_id": "SV-258745r1038976_rule",
        "severity": "medium",
        "cci": ["CCI-004923"],
        "nist": [],
        "title": "ESXi must synchronize time from an authoritative source.",
    },
    "ESXI-80-000114": {
        "vuln_num": "V-258744",
        "rule_id": "SV-258744r1015921_rule",
        "severity": "medium",
        "cci": ["CCI-000015"],
        "nist": ["AC-2"],
        "title": "ESXi must forward logs to a site syslog collector.",
    },
}


def checks_from_snapshot(snapshot: dict) -> list[dict]:
    host = snapshot["host"]
    observed = snapshot.get("observed_at")
    if not observed:
        raise ValueError("snapshot is missing observed_at")
    lockdown = str(snapshot.get("lockdown_mode", "")).lower()
    ssh_running = bool(snapshot.get("ssh_running"))
    ntp_servers = [item for item in snapshot.get("ntp_servers") or [] if item]
    ntp_running = bool(snapshot.get("ntp_running"))
    syslog = str(snapshot.get("syslog_log_host") or "").strip()
    circular = snapshot.get("ntp_circular_with") or []

    lockdown_ok = lockdown in {"lockdownnormal", "lockdownstrict", "normal", "strict"}
    ntp_ok = ntp_running and len(ntp_servers) >= 1 and not circular
    if circular:
        ntp_detail = (
            "NTP servers are "
            + ", ".join(ntp_servers)
            + ". Those hosts take time from this ESXi host, so the chain is circular."
        )
    elif not ntp_servers:
        ntp_detail = "No NTP servers are configured."
    elif not ntp_running:
        ntp_detail = "NTP servers are configured but the NTP service is stopped."
    else:
        ntp_detail = "NTP servers: " + ", ".join(ntp_servers)

    rows = [
        ("ESXI-80-000008", "pass" if lockdown_ok else "fail", f"Lockdown mode is {lockdown or 'disabled'}."),
        (
            "ESXI-80-000193",
            "fail" if ssh_running else "pass",
            "SSH is running." if ssh_running else "SSH is stopped.",
        ),
        ("ESXI-80-000124", "pass" if ntp_ok else "fail", ntp_detail),
        (
            "ESXI-80-000114",
            "pass" if syslog else "fail",
            f"Syslog.global.logHost is {syslog or 'empty'}.",
        ),
    ]
    checks = []
    for rule_ver, result, detail in rows:
        meta = ESXI_CHECKS[rule_ver]
        checks.append(
            {
                "host": host,
                "observed_at": observed,
                "rule_ver": rule_ver,
                "result": result,
                "detail": detail,
                **meta,
            }
        )
    return checks


def observations_from_checks(checks: list[dict], source_file: str = "") -> list[Observation]:
    observations: list[Observation] = []
    for check in checks:
        observations.append(
            Observation(
                host=check["host"],
                observed_at=date.fromisoformat(str(check["observed_at"])[:10]),
                source="vsphere",
                source_file=source_file,
                benchmark="VMware vSphere 8.0 ESXi STIG",
                rule_ver=check["rule_ver"],
                vuln_num=check.get("vuln_num"),
                rule_id=check.get("rule_id"),
                title=check.get("title") or check["rule_ver"],
                severity=check.get("severity"),
                cci=list(check.get("cci") or []),
                nist=list(check.get("nist") or []),
                result=check["result"],
                detail=check.get("detail") or "",
                platform="esxi",
            )
        )
    return observations


def snapshot_from_govc_outputs(host: str, observed_at: str, service_json: str, host_info_json: str, syslog_text: str) -> dict:
    """Normalize canned govc output. Unknown shapes raise instead of guessing a pass."""
    services = json.loads(service_json)
    if isinstance(services, dict):
        services = services.get("services") or services.get("value") or []
    if not isinstance(services, list):
        raise ValueError("govc host.service.ls JSON was not a list of services")
    ssh = None
    ntp = None
    for service in services:
        label = str(service.get("Label") or service.get("label") or service.get("Key") or service.get("key") or "")
        key = str(service.get("Key") or service.get("key") or "")
        if label.lower() == "ssh" or key.upper() == "TSM-SSH":
            ssh = service
        if "ntp" in label.lower() or key.lower() == "ntpd":
            ntp = service
    if ssh is None or ntp is None:
        raise ValueError("govc service list did not include SSH and NTP; refusing to infer they are stopped")

    info = json.loads(host_info_json)
    lockdown = (
        info.get("LockdownMode")
        or info.get("lockdownMode")
        or (info.get("Config") or {}).get("LockdownMode")
        or ""
    )
    ntp_servers = info.get("NtpServers") or info.get("ntpServers") or []
    if isinstance(ntp_servers, str):
        ntp_servers = [item.strip() for item in ntp_servers.split(",") if item.strip()]

    syslog_host = ""
    for line in syslog_text.splitlines():
        if "loghost" in line.lower() or "log host" in line.lower():
            syslog_host = line.split(":", 1)[-1].strip()
    return {
        "host": host,
        "observed_at": observed_at,
        "lockdown_mode": lockdown,
        "ssh_running": bool(ssh.get("Running") if "Running" in ssh else ssh.get("running")),
        "ntp_running": bool(ntp.get("Running") if "Running" in ntp else ntp.get("running")),
        "ntp_servers": ntp_servers,
        "syslog_log_host": syslog_host,
    }
