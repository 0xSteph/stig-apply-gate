"""Read-only vSphere posture checks: ESXi hosts, vCenter, and virtual machines.

The supported input is a snapshot dict. Live collection, when used, only
issues govc reads and refuses to run if the command would change a host.

A snapshot names its kind in a top-level `kind` field. No `kind`, or
`esxi-posture`, is an ESXi host. `vcenter-posture` is the vCenter appliance.
`vm-posture` is one virtual machine, reported under the host name the ledger
already uses for its guest, so the VM rows join that host's findings.
"""

from __future__ import annotations

import json
from datetime import date

from findings.models import Observation

ESXI_KIND = "esxi-posture"
VCENTER_KIND = "vcenter-posture"
VM_KIND = "vm-posture"
SNAPSHOT_KINDS = (ESXI_KIND, VCENTER_KIND, VM_KIND)

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

# VMware vSphere 8.0 vCenter STIG. The STIG ids, vuln numbers, rule ids, CCIs,
# and severities were checked against two public copies that agree: the
# per-rule tags in VMware's dod-compliance-and-automation InSpec profile
# (vsphere/8.0/v2r4-stig) and the V2R1 rule list on cyber.trackr.live. The rule
# revision suffix (the part after `r`) is the one in that profile; DISA can
# move it in a later release without changing the rule. Titles are written for
# this lab.
VCENTER_CHECKS = {
    "VCSA-80-000158": {
        "vuln_num": "V-258927",
        "rule_id": "SV-258927r1003604_rule",
        "severity": "medium",
        "cci": ["CCI-004923", "CCI-001891"],
        "nist": ["SC-45 (1) (a)", "AU-8 (1) (a)"],
        "title": "vCenter must take time from an authoritative NTP source.",
    },
    "VCSA-80-000148": {
        "vuln_num": "V-258925",
        "rule_id": "SV-258925r961395_rule",
        "severity": "medium",
        "cci": ["CCI-001851"],
        "nist": ["AU-4 (1)"],
        "title": "vCenter must forward its logs to a site syslog collector.",
    },
    "VCSA-80-000023": {
        "vuln_num": "V-258905",
        "rule_id": "SV-258905r960840_rule",
        "severity": "medium",
        "cci": ["CCI-000044"],
        "nist": ["AC-7 a"],
        "title": "vCenter SSO must lock an account after three failed logins.",
    },
    "VCSA-80-000266": {
        "vuln_num": "V-258933",
        "rule_id": "SV-258933r961368_rule",
        "severity": "medium",
        "cci": ["CCI-002238"],
        "nist": ["AC-7 b"],
        "title": "A locked vCenter SSO account must stay locked until an administrator unlocks it.",
    },
    "VCSA-80-000079": {
        "vuln_num": "V-258918",
        "rule_id": "SV-258918r1003597_rule",
        "severity": "medium",
        "cci": ["CCI-004066", "CCI-000199"],
        "nist": ["IA-5 (1) (h)", "IA-5 (1) (d)"],
        "title": "vCenter SSO passwords must expire within 90 days.",
    },
    "VCSA-80-000089": {
        "vuln_num": "V-258920",
        "rule_id": "SV-258920r1003601_rule",
        "severity": "medium",
        "cci": ["CCI-001133", "CCI-004895", "CCI-002361", "CCI-002038"],
        "nist": ["SC-10", "SC-11 b", "AC-12", "IA-11"],
        "title": "vSphere Client sessions must end after 15 idle minutes.",
    },
}

# VMware vSphere 8.0 Virtual Machine STIG, checked the same way as the vCenter
# rows above. Every rule here maps to CCI-000366 / CM-6 b.
VM_CHECKS = {
    "VMCH-80-000189": {
        "vuln_num": "V-258703",
        "rule_id": "SV-258703r959010_rule",
        "severity": "low",
        "setting": "isolation.tools.copy.disable",
        "want": "true",
        "unset_ok": True,
        "title": "Console copy from the guest must be disabled.",
    },
    "VMCH-80-000191": {
        "vuln_num": "V-258704",
        "rule_id": "SV-258704r959010_rule",
        "severity": "low",
        "setting": "isolation.tools.dnd.disable",
        "want": "true",
        "unset_ok": True,
        "title": "Console drag and drop must be disabled.",
    },
    "VMCH-80-000192": {
        "vuln_num": "V-258705",
        "rule_id": "SV-258705r959010_rule",
        "severity": "low",
        "setting": "isolation.tools.paste.disable",
        "want": "true",
        "unset_ok": True,
        "title": "Console paste into the guest must be disabled.",
    },
    "VMCH-80-000193": {
        "vuln_num": "V-258706",
        "rule_id": "SV-258706r959010_rule",
        "severity": "medium",
        "setting": "isolation.tools.diskShrink.disable",
        "want": "true",
        "unset_ok": True,
        "title": "Guest-initiated virtual disk shrinking must be disabled.",
    },
    "VMCH-80-000194": {
        "vuln_num": "V-258707",
        "rule_id": "SV-258707r959010_rule",
        "severity": "medium",
        "setting": "isolation.tools.diskWiper.disable",
        "want": "true",
        "unset_ok": True,
        "title": "Guest-initiated virtual disk wiping must be disabled.",
    },
    "VMCH-80-000195": {
        "vuln_num": "V-258708",
        "rule_id": "SV-258708r959010_rule",
        "severity": "medium",
        "setting": "RemoteDisplay.maxConnections",
        "want": "1",
        # The benchmark counts a missing value as a finding for this one only.
        "unset_ok": False,
        "title": "Only one remote console session may attach to the VM.",
    },
    "VMCH-80-000197": {
        "vuln_num": "V-258710",
        "rule_id": "SV-258710r959010_rule",
        "severity": "medium",
        "setting": "isolation.device.connectable.disable",
        "want": "true",
        "unset_ok": True,
        "title": "The guest must not connect, disconnect, or change virtual devices.",
    },
    "VMCH-80-000198": {
        "vuln_num": "V-258711",
        "rule_id": "SV-258711r959010_rule",
        "severity": "medium",
        "setting": "tools.guestlib.enableHostInfo",
        "want": "false",
        "unset_ok": True,
        "title": "The guest must not read host details from the hypervisor.",
    },
}

VM_SETTINGS = tuple(meta["setting"] for meta in VM_CHECKS.values())

_BENCHMARK = {
    ESXI_KIND: ("VMware vSphere 8.0 ESXi STIG", "esxi"),
    VCENTER_KIND: ("VMware vSphere 8.0 vCenter STIG", "vcenter"),
    VM_KIND: ("VMware vSphere 8.0 Virtual Machine STIG", "vm"),
}

NOT_READ = "notchecked"


def snapshot_kind(snapshot: dict) -> str:
    """The snapshot's kind. A snapshot with no `kind` is an ESXi host, as before."""
    kind = snapshot.get("kind") or ESXI_KIND
    if kind not in SNAPSHOT_KINDS:
        raise ValueError(f"snapshot kind {kind!r} is not one of {', '.join(SNAPSHOT_KINDS)}")
    return kind


def checks_for_snapshot(snapshot: dict) -> list[dict]:
    """Route a snapshot to the checks for its kind."""
    kind = snapshot_kind(snapshot)
    if kind == VCENTER_KIND:
        return vcenter_checks_from_snapshot(snapshot)
    if kind == VM_KIND:
        return vm_checks_from_snapshot(snapshot)
    return checks_from_snapshot(snapshot)


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


def vcenter_checks_from_snapshot(snapshot: dict) -> list[dict]:
    """Checks for a `vcenter-posture` snapshot.

    A field that is missing or null was not read, and its row is not reviewed.
    That is different from a value that was read and is wrong. `probe_errors`
    says why a field was not read and is copied into those rows.
    """
    host, observed = _identity(snapshot, VCENTER_KIND)
    errors = [str(item) for item in snapshot.get("probe_errors") or [] if str(item).strip()]

    def unread(field: str) -> tuple[str, str]:
        why = f" Probe errors: {'; '.join(errors)}" if errors else ""
        return NOT_READ, f"{field} was not read.{why}"

    rows: list[tuple[str, str, str]] = []

    ntp = _list_field(snapshot, "ntp_servers")
    if ntp is None:
        rows.append(("VCSA-80-000158", *unread("ntp_servers")))
    elif not ntp:
        rows.append(("VCSA-80-000158", "fail", "No NTP servers are configured."))
    else:
        rows.append(
            (
                "VCSA-80-000158",
                "pass",
                "NTP servers: " + ", ".join(ntp) + ". The snapshot does not say whether those sources are themselves authoritative.",
            )
        )

    targets = _list_field(snapshot, "syslog_targets")
    if targets is None:
        rows.append(("VCSA-80-000148", *unread("syslog_targets")))
    elif not targets:
        rows.append(("VCSA-80-000148", "fail", "No syslog forwarding target is configured."))
    else:
        rows.append(
            (
                "VCSA-80-000148",
                "pass",
                "Syslog forwards to " + ", ".join(targets) + ". Reachability is not in the snapshot.",
            )
        )

    numeric = (
        ("VCSA-80-000023", "sso_lockout_failures", lambda n: 1 <= n <= 3, "SSO locks an account after {n} failed logins.", "The benchmark wants 3."),
        ("VCSA-80-000266", "sso_lockout_unlock_seconds", lambda n: n == 0, "SSO unlock time is {n} seconds.", "The benchmark wants 0, so only an administrator unlocks."),
        ("VCSA-80-000079", "sso_password_max_days", lambda n: 1 <= n <= 90, "SSO password lifetime is {n} days.", "The benchmark wants 90 or less."),
        ("VCSA-80-000089", "session_timeout_minutes", lambda n: 1 <= n <= 15, "vSphere Client session timeout is {n} minutes.", "The benchmark wants 15 or less."),
    )
    for rule_ver, field, ok, said, wanted in numeric:
        value = _int_field(snapshot, field)
        if value is None:
            rows.append((rule_ver, *unread(field)))
            continue
        passed = ok(value)
        detail = said.format(n=value) + ("" if passed else " " + wanted)
        rows.append((rule_ver, "pass" if passed else "fail", detail))

    return [_check(host, observed, VCENTER_KIND, rule_ver, result, detail, VCENTER_CHECKS[rule_ver]) for rule_ver, result, detail in rows]


def vm_checks_from_snapshot(snapshot: dict) -> list[dict]:
    """Checks for a `vm-posture` snapshot.

    A setting that is null was read and is not set on the VM. The benchmark
    treats most of these as not a finding when unset, because the vSphere 8
    default is already the safe value; RemoteDisplay.maxConnections is the
    exception. A setting that is missing from the snapshot was not read, and
    its row is not reviewed.
    """
    host, observed = _identity(snapshot, VM_KIND)
    vm_name = str(snapshot.get("vm_name") or "").strip()
    rows = []
    for rule_ver, meta in VM_CHECKS.items():
        setting = meta["setting"]
        if setting not in snapshot:
            rows.append((rule_ver, NOT_READ, f"{setting} was not read."))
            continue
        value = _setting_value(snapshot[setting], setting)
        if value is None:
            if meta["unset_ok"]:
                rows.append((rule_ver, "pass", f"{setting} is not set. The vSphere 8 default is the safe value, and the benchmark does not count unset as a finding."))
            else:
                rows.append((rule_ver, "fail", f"{setting} is not set. The benchmark wants {meta['want']}."))
            continue
        passed = value.strip().lower() == meta["want"]
        detail = f"{setting} is {value}." + ("" if passed else f" The benchmark wants {meta['want']}.")
        rows.append((rule_ver, "pass" if passed else "fail", detail))
    checks = []
    for rule_ver, result, detail in rows:
        meta = {key: value for key, value in VM_CHECKS[rule_ver].items() if key in {"vuln_num", "rule_id", "severity", "title"}}
        meta["cci"] = ["CCI-000366"]
        meta["nist"] = ["CM-6 b"]
        if vm_name and vm_name.lower() != host.lower():
            detail = f"VM {vm_name}: {detail}"
        checks.append(_check(host, observed, VM_KIND, rule_ver, result, detail, meta))
    return checks


def _identity(snapshot: dict, kind: str) -> tuple[str, str]:
    host = str(snapshot.get("host") or "").strip()
    if not host:
        raise ValueError(f"{kind} snapshot is missing host")
    observed = snapshot.get("observed_at")
    if not observed:
        raise ValueError(f"{kind} snapshot is missing observed_at")
    return host, str(observed)


def _check(host: str, observed: str, kind: str, rule_ver: str, result: str, detail: str, meta: dict) -> dict:
    benchmark, platform = _BENCHMARK[kind]
    return {
        "host": host,
        "observed_at": observed,
        "rule_ver": rule_ver,
        "result": result,
        "detail": detail,
        "benchmark": benchmark,
        "platform": platform,
        **meta,
    }


def _list_field(snapshot: dict, field: str) -> list[str] | None:
    value = snapshot.get(field)
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list, got {type(value).__name__}")
    return [str(item).strip() for item in value if str(item).strip()]


def _int_field(snapshot: dict, field: str) -> int | None:
    value = snapshot.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer or null, got {value!r}")
    return value


def _setting_value(value, setting: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int)):
        return str(value)
    raise ValueError(f"{setting} must be a string or null, got {value!r}")


def observations_from_checks(checks: list[dict], source_file: str = "") -> list[Observation]:
    observations: list[Observation] = []
    for check in checks:
        observations.append(
            Observation(
                host=check["host"],
                observed_at=date.fromisoformat(str(check["observed_at"])[:10]),
                source="vsphere",
                source_file=source_file,
                benchmark=check.get("benchmark") or "VMware vSphere 8.0 ESXi STIG",
                rule_ver=check["rule_ver"],
                vuln_num=check.get("vuln_num"),
                rule_id=check.get("rule_id"),
                title=check.get("title") or check["rule_ver"],
                severity=check.get("severity"),
                cci=list(check.get("cci") or []),
                nist=list(check.get("nist") or []),
                result=check["result"],
                detail=check.get("detail") or "",
                platform=check.get("platform") or "esxi",
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


# What --govc cannot read on the vCenter appliance. These settings live in the
# appliance management API and the SSO admin interface, not in the vSphere API
# that govc reads, so the collector records them as null with this reason
# instead of guessing a value.
VCENTER_UNREADABLE = {
    "ntp_servers": "appliance NTP is in the appliance management API (VAMI), which govc does not read",
    "syslog_targets": "syslog forwarding is in the appliance management API (VAMI), which govc does not read",
    "sso_lockout_failures": "the SSO lockout policy is in the SSO administration interface, which govc about and object.collect do not read",
    "sso_lockout_unlock_seconds": "the SSO lockout policy is in the SSO administration interface, which govc about and object.collect do not read",
    "sso_password_max_days": "the SSO password policy is in the SSO administration interface, which govc about and object.collect do not read",
    "session_timeout_minutes": "the vSphere Client session timeout is client configuration, not a vSphere API property",
}


def vcenter_snapshot_from_govc_outputs(host: str, observed_at: str, about_json: str) -> dict:
    """Normalize `govc about -json`. Anything govc did not read stays null."""
    about = _about(about_json)
    api_type = str(about.get("ApiType") or about.get("apiType") or "")
    if api_type != "VirtualCenter":
        raise ValueError(f"govc about reports ApiType {api_type or 'missing'!r}, not VirtualCenter; refusing to call this a vCenter")
    snapshot: dict = {"kind": VCENTER_KIND, "host": host, "observed_at": observed_at}
    errors = []
    for field, why in VCENTER_UNREADABLE.items():
        snapshot[field] = None
        errors.append(f"{field}: {why}")
    snapshot["probe_errors"] = errors
    return snapshot


def vm_snapshot_from_govc_outputs(
    vm_name: str,
    vcenter: str,
    observed_at: str,
    vm_info_json: str,
    ledger_host: str | None = None,
) -> dict:
    """Normalize `govc vm.info -json <vm>`.

    The output must hold exactly one VM, with its config.extraConfig list. A
    key that is not in that list is unset on the VM and recorded as null. If
    the list itself is missing, the read was incomplete and this refuses.
    """
    info = json.loads(vm_info_json)
    if not isinstance(info, dict):
        raise ValueError("govc vm.info JSON was not an object")
    machines = info.get("VirtualMachines")
    if machines is None:
        machines = info.get("virtualMachines")
    if not isinstance(machines, list) or len(machines) != 1:
        count = len(machines) if isinstance(machines, list) else 0
        raise ValueError(f"govc vm.info returned {count} virtual machines for {vm_name!r}; expected exactly one")
    machine = machines[0]
    config = machine.get("Config") if "Config" in machine else machine.get("config")
    if not isinstance(config, dict):
        raise ValueError("govc vm.info did not include the VM config; refusing to infer that advanced settings are unset")
    extra = config.get("ExtraConfig") if "ExtraConfig" in config else config.get("extraConfig")
    if not isinstance(extra, list):
        raise ValueError("govc vm.info did not include config.extraConfig; refusing to infer that advanced settings are unset")
    values: dict[str, object] = {}
    for option in extra:
        if not isinstance(option, dict):
            raise ValueError("govc vm.info extraConfig entry was not an object")
        key = option.get("Key") if "Key" in option else option.get("key")
        if key is None:
            raise ValueError("govc vm.info extraConfig entry had no key")
        values[str(key)] = option.get("Value") if "Value" in option else option.get("value")
    snapshot: dict = {
        "kind": VM_KIND,
        "host": ledger_host or vm_name,
        "vm_name": vm_name,
        "vcenter": vcenter,
        "observed_at": observed_at,
    }
    for setting in VM_SETTINGS:
        snapshot[setting] = _setting_value(values.get(setting), setting)
    return snapshot


def _about(about_json: str) -> dict:
    data = json.loads(about_json)
    if not isinstance(data, dict):
        raise ValueError("govc about JSON was not an object")
    about = data.get("About") or data.get("about") or data
    if not isinstance(about, dict):
        raise ValueError("govc about JSON had no About object")
    return about
