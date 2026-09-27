"""Decide whether a playbook is allowed to touch a finding.

The scanner and the POA&M record the row. They do not stand in front of the
change. This gate does. A stock STIG role ships controls on, and a person is
expected to turn the dangerous ones off. Here the run stops instead.
"""

from __future__ import annotations

from datetime import date

from findings.models import PASS_RESULTS

# Tags the sample play and the Windows script actually implement.
TAGS = {
    "RHEL-08-010370": "gpgcheck",
    "RHEL-08-010371": "localpkg",
    "RHEL-08-020230": "pwquality",
    "RHEL-08-010550": "ssh-root",
    "RHEL-08-030180": "audit",
    "CVE-2024-6387": "openssh",
    "CVE-2023-48795": "openssh",
    "WN22-00-000380": "smb1",
}

LABELS = {
    "refuse": "Stopped",
    "probe": "Check first",
    "bundle": "One restart",
    "window": "Someone there",
    "hollow": "Pass is local",
    "allow": "Apply",
}


def build_apply_gate(
    *,
    findings: list[dict],
    hosts: list[dict],
    backups: list[dict],
    duties: dict | None,
    today: date,
    current: date | None,
) -> dict:
    duties = duties or {}
    index = {(item["host"].lower(), item["control"]): item for item in findings}
    loops = _loops(duties)
    backup_by_host = {item["host"].lower(): item for item in backups}
    decisions = []
    for finding in findings:
        decision = _decision(
            finding=finding,
            index=index,
            loops=loops,
            backup_by_host=backup_by_host,
            duties=duties,
            today=today,
        )
        if decision:
            decisions.append(decision)
    rank = {"refuse": 0, "hollow": 1, "probe": 2, "bundle": 3, "window": 4, "allow": 5}
    decisions.sort(key=lambda item: (rank.get(item["action"], 9), item["host"], item["control"]))
    unscanned = _unscanned(hosts, findings, current)
    counts: dict[str, int] = {}
    for item in decisions:
        counts[item["action"]] = counts.get(item["action"], 0) + 1
    return {"decisions": decisions, "unscanned": unscanned, "counts": counts}


def _decision(*, finding, index, loops, backup_by_host, duties, today: date) -> dict | None:
    hollow = _hollow(finding, index, duties)
    if finding["clock"] == "closed" and not hollow:
        return None

    candidates: list[tuple[int, str, str]] = []
    if hollow:
        candidates.append((1, "hollow", hollow))

    if finding["clock"] == "excepted":
        expires = _exception_expires(finding)
        ticket = finding.get("exception_id") or "the exception"
        when = f" through {expires}" if expires else ""
        candidates.append(
            (
                2,
                "refuse",
                f"{ticket} is signed{when}. Closing this from a playbook would pass the scan and break that signature.",
            )
        )

    loop = loops.get((finding["host"].lower(), finding["control"]))
    if loop:
        candidates.append((3, "refuse", loop))

    kind = finding.get("remediation", {}).get("class")
    if kind == "do-not-automate":
        candidates.append((4, "refuse", finding["remediation"]["why"]))
    elif kind == "blocked":
        candidates.append(
            (
                4,
                "refuse",
                "A value written here would pass the check while the control is still false. " + finding["remediation"]["why"],
            )
        )
    elif kind == "gpo":
        candidates.append((4, "refuse", "This host takes the setting from Group Policy. A local edit loses to the next gpupdate."))
    elif kind == "manual":
        candidates.append((4, "refuse", finding["remediation"]["why"]))

    backup = backup_by_host.get(finding["host"].lower())
    if kind == "change-window" and backup and backup.get("status") == "breach":
        detail = " ".join(backup.get("reasons") or [])
        candidates.append(
            (
                5,
                "refuse",
                f"This change restarts a service or removes a feature, and the backup for this host is outside policy. {detail}".strip(),
            )
        )

    predecessor = _predecessor(finding, duties)
    if predecessor:
        candidates.append((6, "probe", predecessor.get("detail") or f"Run {predecessor.get('probe')} before changing this."))

    bundle = _bundle(finding, index, duties)
    if bundle:
        service, members = bundle
        names = ", ".join(members)
        candidates.append(
            (
                7,
                "bundle",
                f"These open rows restart {service} together: {names}. Doing one of them restarts the service before the others land.",
            )
        )

    if kind == "change-window":
        candidates.append(
            (
                8,
                "window",
                "This restarts a service or wants a reboot. An unattended run will not touch it. Someone has to be at the console.",
            )
        )
    elif kind == "automate" and not predecessor:
        candidates.append((9, "allow", "No signature, dependency, or predecessor blocks this edit."))

    if not candidates:
        return None
    _, action, reason = min(candidates, key=lambda item: item[0])
    # A closed hollow pass stays hollow even if some other rule would allow it.
    if hollow and finding["clock"] == "closed":
        action, reason = "hollow", hollow
    tag = TAGS.get(finding["control"])
    members = _bundle_members(finding, duties)
    return {
        "host": finding["host"],
        "host_short": finding["host_short"],
        "control": finding["control"],
        "slug": finding["slug"],
        "tag": tag,
        "action": action,
        "label": LABELS[action],
        "reason": reason,
        "probe": predecessor.get("probe") if predecessor and action == "probe" else None,
        "bundle": members if action == "bundle" else [],
        "as_of": today.isoformat(),
    }


def _exception_expires(finding: dict) -> str:
    # The clock stores the exception end as the due date while the row is excepted.
    if finding.get("clock") == "excepted" and finding.get("due"):
        return finding["due"]
    return ""


def _loops(duties: dict) -> dict[tuple[str, str], str]:
    rows = duties.get("time_sources") or []
    by_host = {row["host"].lower(): row for row in rows}
    found: dict[tuple[str, str], str] = {}
    for row in rows:
        host = row["host"].lower()
        for peer in row.get("peers") or []:
            other = by_host.get(peer.lower())
            if other is None:
                continue
            back = {item.lower() for item in other.get("peers") or []}
            if host not in back:
                continue
            text = (
                f"{row['host'].split('.')[0]} and {peer.split('.')[0]} take time from each other. "
                "Fixing either side leaves the loop in place."
            )
            for control in row.get("controls") or []:
                found[(host, control)] = text
    return found


def _hollow(finding: dict, index: dict, duties: dict) -> str | None:
    if finding["result"] not in PASS_RESULTS and finding["clock"] != "closed":
        return None
    for dep in duties.get("depends_on") or []:
        if dep["host"].lower() != finding["host"].lower() or dep["control"] != finding["control"]:
            continue
        upstream = index.get((dep["upstream_host"].lower(), dep["upstream_control"]))
        if upstream and upstream["clock"] != "closed":
            return dep["because"]
    return None


def _predecessor(finding: dict, duties: dict) -> dict | None:
    for row in duties.get("predecessors") or []:
        if row["host"].lower() == finding["host"].lower() and row["control"] == finding["control"]:
            if not row.get("met", False):
                return row
    return None


def _bundle(finding: dict, index: dict, duties: dict) -> tuple[str, list[str]] | None:
    for row in duties.get("restart_bundles") or []:
        if row["host"].lower() != finding["host"].lower():
            continue
        if finding["control"] not in (row.get("controls") or []):
            continue
        open_members = []
        for control in row["controls"]:
            other = index.get((row["host"].lower(), control))
            if other and other["clock"] != "closed":
                open_members.append(control)
        if len(open_members) >= 2 and finding["control"] in open_members:
            return row.get("service") or "the service", open_members
    return None


def _bundle_members(finding: dict, duties: dict) -> list[str]:
    for row in duties.get("restart_bundles") or []:
        if row["host"].lower() == finding["host"].lower() and finding["control"] in (row.get("controls") or []):
            return list(row["controls"])
    return []


def _unscanned(hosts: list[dict], findings: list[dict], current: date | None) -> list[str]:
    if current is None:
        return []
    seen = {item["host"].lower() for item in findings if item.get("last_seen", "") >= current.isoformat()}
    return [item["hostname"] for item in hosts if item["hostname"].lower() not in seen]
