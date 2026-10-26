"""Read-only Windows posture checks.

The input is the snapshot `windows/Invoke-BaselineAudit.ps1 -Snapshot <path>`
writes: one JSON object with `kind: "windows-posture"`. The script makes no
change in that mode, and this module only reads the dict it produced.

A field the script could not read is null, with the reason in `probe_errors`.
A null never becomes a pass. The check it feeds is recorded as not reviewed.

The snapshot records what the domain controller's clock is set to follow. It
does not replace `fixtures/lab/duties.json`. duties.json says which hosts take
time from each other across the site, and that is what the apply gate reads to
stop a one-sided fix. A Windows snapshot sees one host. It can show that the DC
follows esxi01. It cannot show that esxi01 follows the DC; that comes from the
ESXi snapshot or from duties.json.
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

from findings.models import Observation

KIND = "windows-posture"
BENCHMARK = "Microsoft Windows Server 2022 Security Technical Implementation Guide"

# Public STIG version identifiers, as the lab already uses them. Only SMBv1 has
# a vuln and rule id in the lab. The other two are matched on rule_ver alone.
WINDOWS_CHECKS = {
    "WN22-00-000380": {
        "vuln_num": "V-254275",
        "rule_id": "SV-254275r958478_rule",
        "severity": "medium",
        "cci": ["CCI-000381"],
        "nist": [],
        "title": "The SMBv1 feature must not be installed.",
    },
    "WN22-AC-000070": {
        "vuln_num": "",
        "rule_id": "",
        "severity": "medium",
        "cci": [],
        "nist": ["IA-5"],
        "title": "Minimum password length must be 14 characters.",
    },
    "WN22-DC-000060": {
        "vuln_num": "",
        "rule_id": "",
        "severity": "medium",
        "cci": [],
        "nist": [],
        "title": "Domain controller clock skew must stay within five minutes.",
    },
}

# w32tm /query /source prints these when the DC is not following any peer.
_NO_PEER = {"local cmos clock", "free-running system clock"}

# Get-WindowsFeature InstallState and Get-WindowsOptionalFeature State, when the
# script wrote the raw state instead of a bool.
_SMB1_INSTALLED = {"installed", "installpending", "enabled", "enablepending"}
_SMB1_ABSENT = {"available", "removed", "uninstallpending", "disabled", "disablepending", "disabledwithpayloadremoved"}

# Not a scanner result. A note rides along in the check list and is not turned
# into an Observation, so it cannot open, close, or mask a finding.
NOTE = "note"


def is_windows_snapshot(path: Path) -> bool:
    """True when path is JSON whose top-level kind is windows-posture."""
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, OSError):
        return False
    return isinstance(document, dict) and document.get("kind") == KIND


def parse_windows_export(path: Path, observed_on: date | None = None) -> list[Observation]:
    snapshot = json.loads(path.read_text(encoding="utf-8-sig"))
    if observed_on and not snapshot.get("observed_at"):
        snapshot = {**snapshot, "observed_at": observed_on.isoformat()}
    return observations_from_checks(checks_from_snapshot(snapshot), source_file=str(path))


def checks_from_snapshot(snapshot: dict, allowed_time_sources: list[str] | None = None) -> list[dict]:
    """Turn a windows-posture snapshot into check rows.

    allowed_time_sources overrides the snapshot's own `allowed_time_sources`
    list. With neither, a DC that names a peer is not reviewed: there is nothing
    to judge that peer against.
    """
    if snapshot.get("kind") not in (None, KIND):
        raise ValueError(f"snapshot kind is {snapshot.get('kind')!r}, expected {KIND!r}")
    host = str(snapshot.get("host") or "").strip()
    if not host:
        raise ValueError("snapshot is missing host")
    observed = snapshot.get("observed_at")
    if not observed:
        raise ValueError("snapshot is missing observed_at")
    if allowed_time_sources is None:
        allowed_time_sources = snapshot.get("allowed_time_sources")

    rows = [_smb1_row(snapshot)]
    dc_row = _dc_time_row(snapshot, allowed_time_sources)
    if dc_row is not None:
        rows.append(dc_row)
    rows.append(_password_note(snapshot))

    checks = []
    for rule_ver, result, detail in rows:
        checks.append(
            {
                "host": host,
                "observed_at": observed,
                "rule_ver": rule_ver,
                "result": result,
                "detail": detail,
                **WINDOWS_CHECKS[rule_ver],
            }
        )
    return checks


def observations_from_checks(checks: list[dict], source_file: str = "") -> list[Observation]:
    observations: list[Observation] = []
    for check in checks:
        if check["result"] == NOTE:
            continue
        observations.append(
            Observation(
                host=check["host"],
                observed_at=date.fromisoformat(str(check["observed_at"])[:10]),
                source="windows",
                source_file=source_file,
                benchmark=BENCHMARK,
                rule_ver=check["rule_ver"],
                vuln_num=check.get("vuln_num") or None,
                rule_id=check.get("rule_id") or None,
                title=check.get("title") or check["rule_ver"],
                severity=check.get("severity"),
                cci=list(check.get("cci") or []),
                nist=list(check.get("nist") or []),
                result=check["result"],
                detail=check.get("detail") or "",
                platform="windows",
            )
        )
    return observations


def _smb1_row(snapshot: dict) -> tuple[str, str, str]:
    installed = _smb1_installed(snapshot.get("smb1_installed"))
    pending = snapshot.get("pending_reboot") is True
    if installed is None:
        result, lines = "notchecked", ["SMBv1 install state was not recorded" + _probe_reason(snapshot, "smb1_installed")]
    elif installed:
        result, lines = "fail", ["FS-SMB1 is installed."]
    else:
        result, lines = "pass", ["FS-SMB1 is not installed."]
    if pending:
        lines.append("Reboot pending." if installed else "Feature removed, reboot pending.")
    return "WN22-00-000380", result, " ".join(lines)


def _dc_time_row(snapshot: dict, allowed: list[str] | None) -> tuple[str, str, str] | None:
    role = snapshot.get("is_domain_controller")
    if role is False:
        return None
    if role is None:
        return (
            "WN22-DC-000060",
            "notchecked",
            "Domain controller role was not recorded" + _probe_reason(snapshot, "is_domain_controller"),
        )
    raw = snapshot.get("time_source")
    if raw is None:
        return (
            "WN22-DC-000060",
            "notchecked",
            "Time source was not recorded" + _probe_reason(snapshot, "time_source"),
        )
    source = _peer_name(str(raw))
    time_type = snapshot.get("time_type")
    suffix = f" w32tm Type is {time_type}." if time_type else ""
    if not source:
        return "WN22-DC-000060", "fail", "w32tm /query /source was empty." + suffix
    if source.lower() in _NO_PEER:
        return "WN22-DC-000060", "fail", f"The DC follows {source}, not an authoritative peer." + suffix
    if not allowed:
        return (
            "WN22-DC-000060",
            "notchecked",
            f"The DC takes time from {source}. No allowed time source list was given to judge it against." + suffix,
        )
    if _is_allowed(source, allowed):
        return "WN22-DC-000060", "pass", f"The DC takes time from {source}, an allowed source." + suffix
    return (
        "WN22-DC-000060",
        "fail",
        f"The DC takes time from {source}, which is not an allowed source ({', '.join(allowed)})." + suffix,
    )


def _password_note(snapshot: dict) -> tuple[str, str, str]:
    source = snapshot.get("password_policy_source")
    if source is None:
        detail = "Password policy source was not recorded" + _probe_reason(snapshot, "password_policy_source")
    elif str(source).strip().lower() == "local":
        detail = "local"
    else:
        detail = f"set by GPO {str(source).strip()}"
    return "WN22-AC-000070", NOTE, detail


def _smb1_installed(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        key = value.strip().lower()
        if key in _SMB1_INSTALLED:
            return True
        if key in _SMB1_ABSENT:
            return False
    return None


def _peer_name(value: str) -> str:
    """w32tm prints 'host,0x9' when the peer was configured with flags."""
    text = value.strip()
    return re.sub(r",0x[0-9a-fA-F]+$", "", text).strip()


def _is_allowed(source: str, allowed: list[str]) -> bool:
    name = source.lower()
    short = name.split(".")[0]
    for item in allowed:
        candidate = _peer_name(str(item)).lower()
        if not candidate:
            continue
        if candidate == name or (candidate.split(".")[0] == short and ("." not in name or "." not in candidate)):
            return True
    return False


def _probe_reason(snapshot: dict, field: str) -> str:
    for error in snapshot.get("probe_errors") or []:
        text = str(error)
        if text.startswith(f"{field}:"):
            return ". " + text.split(":", 1)[1].strip().rstrip(".") + "."
    return "."
