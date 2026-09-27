"""Rehearse gate changes on a copy of the lab.

The copy is the test window. fixtures/lab, the ledger the UI reads, and the
apply-gate file the playbook reads stay as they are. A host marked production
is refused even when the same change is allowed on the lab copy.
"""

from __future__ import annotations

import copy
from datetime import date
from pathlib import Path

from findings.cli import _ledger_from_dir
from findings.policy import parse_day

# Rows the interview walks on the unchanged lab record.
STORIES = [
    ("rhel-repo01.lab.local", "RHEL-08-010370", "Oldest CAT I. The signing key has to be on the box before gpgcheck."),
    ("wsus01.lab.local", "WN22-00-000380", "SMBv1 wants a reboot. The backup is outside policy, so the play stops."),
    ("ad01.lab.local", "WN22-DC-000060", "The domain controller and ESXi take time from each other."),
    ("esxi01.lab.local", "ESXI-80-000124", "Pointing ESXi at the domain controller keeps that loop."),
    ("rhel-mission01.lab.local", "RHEL-08-010550", "OpenSSH, PermitRootLogin, and the audit package share one sshd restart."),
]


def rehearse(lab: Path, *, today: date, scenario: str = "all") -> dict:
    baseline_inputs = _load_inputs(lab)
    baseline = _ledger(lab, baseline_inputs, today)
    cases = []
    for spec in _specs():
        if scenario not in {"all", spec["id"]}:
            continue
        mutated = copy.deepcopy(baseline_inputs)
        spec["apply"](mutated)
        led = _ledger(lab, mutated, today)
        cases.append(
            {
                "id": spec["id"],
                "title": spec["title"],
                "change": spec["change"],
                "meaning": spec["meaning"],
                "rows": _rows(baseline, led, spec["watch"]),
            }
        )
    return {
        "as_of": today.isoformat(),
        "isolated": True,
        "lab": str(lab),
        "handoff_ready": baseline["handoff"]["ready"],
        "stories": _stories(baseline),
        "cases": cases,
    }


def render_report(report: dict) -> str:
    lines = [
        "# Test window",
        "",
        f"Sample clock {report['as_of']}. This report was built from a copy of the lab records.",
        "The lab files, the ledger the UI reads, and the apply-gate file the playbook reads were not written.",
        "",
        "Integration Lab is the only place a change is tried. A maintenance window on an operations host",
        "is the scheduled time to apply a change the lab already proved, with someone at the console and a rollback.",
        "It is not the time you find out whether the change is safe.",
        "",
        f"Handoff on the unchanged lab: {'ready' if report['handoff_ready'] else 'not ready'}.",
        "",
        "## Walk these on the unchanged lab",
        "",
    ]
    for story in report["stories"]:
        lines.append(f"- {story['host_short']} {story['control']} - {story['action']}. {story['point']}")
        lines.append(f"  {story['reason']}")
    lines.append("")
    for case in report["cases"]:
        lines.append(f"## {case['title']}")
        lines.append("")
        lines.append(case["change"])
        lines.append("")
        lines.append(case["meaning"])
        lines.append("")
        for row in case["rows"]:
            lines.append(
                f"- {row['host_short']} {row['control']}: {row['before_action']} -> {row['after_action']}"
            )
            lines.append(f"  Before: {row['before_reason']}")
            lines.append(f"  After: {row['after_reason']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def publishable(report: dict) -> dict:
    """Drop ledger-sized fields. The UI only needs the comparison."""
    return {
        "as_of": report["as_of"],
        "isolated": True,
        "handoff_ready": report["handoff_ready"],
        "stories": report["stories"],
        "cases": report["cases"],
    }


def _specs() -> list[dict]:
    return [
        {
            "id": "wsus-backup",
            "title": "WSUS backup back inside policy",
            "change": (
                "On the copy only, the WSUS last good backup is 27 Sep 2026 02:00 UTC and the restore test is 1 Sep 2026. "
                "Both the RPO and the restore-test window have to be inside policy. Moving only the backup age leaves the stop in place."
            ),
            "meaning": (
                "The backup stop lifts. The row does not become an unattended apply. "
                "SMBv1 still wants a reboot, so someone has to be at the console. That is the maintenance window."
            ),
            "watch": [("wsus01.lab.local", "WN22-00-000380")],
            "apply": _wsus_backup,
        },
        {
            "id": "exception-lapsed",
            "title": "ESXi SSH exception dated yesterday",
            "change": "On the copy only, EX-014 expires on 26 Sep 2026, the day before the sample clock.",
            "meaning": (
                "The signature stop lifts. The row stays stopped, because closing SSH from a playbook still removes the break-glass path. "
                "An expired signature is not permission to automate the STIG."
            ),
            "watch": [("esxi01.lab.local", "ESXI-80-000193")],
            "apply": _exception_lapsed,
        },
        {
            "id": "signing-key",
            "title": "Lab signing key imported",
            "change": "On the copy only, the predecessor check rpm -q gpg-pubkey is marked met on the repository host.",
            "meaning": "The GPG rows become safe to apply on the lab host. Run them with --check --diff before a real run. The mission host is a different row.",
            "watch": [
                ("rhel-repo01.lab.local", "RHEL-08-010370"),
                ("rhel-repo01.lab.local", "RHEL-08-010371"),
            ],
            "apply": _signing_key,
        },
        {
            "id": "operations-hold",
            "title": "Same key, host marked operations",
            "change": (
                "On the copy only, the signing key is met and the repository host is marked production. "
                "The lab twin of this change is the signing-key case, which allows the edit."
            ),
            "meaning": "The same change the lab would allow is refused on an operations host. Prove it in the lab, then schedule the window.",
            "watch": [
                ("rhel-repo01.lab.local", "RHEL-08-010370"),
                ("rhel-repo01.lab.local", "RHEL-08-010371"),
            ],
            "apply": _operations_hold,
        },
    ]


def _load_inputs(lab: Path) -> dict:
    import json

    def load(name: str):
        return json.loads((lab / name).read_text(encoding="utf-8"))

    return {
        "hosts": load("hosts.json"),
        "exceptions": load("exceptions.json"),
        "backups": load("backups.json"),
        "services": load("services.json"),
        "site": load("site.json"),
        "milestones": load("milestones.json"),
        "duties": load("duties.json"),
    }


def _ledger(lab: Path, inputs: dict, today: date) -> dict:
    return _ledger_from_dir(
        scan_dir=lab / "scans",
        hosts=inputs["hosts"],
        exceptions=inputs["exceptions"],
        backups=inputs["backups"],
        services=inputs["services"],
        site=inputs["site"],
        milestones=inputs["milestones"],
        duties=inputs["duties"],
        policy_path=Path("policy/default.json"),
        today=today,
    )


def _stories(ledger: dict) -> list[dict]:
    decisions = {(item["host"].lower(), item["control"]): item for item in ledger["apply_gate"]["decisions"]}
    rows = []
    for host, control, point in STORIES:
        decision = decisions[(host.lower(), control)]
        rows.append(
            {
                "host": host,
                "host_short": decision["host_short"],
                "control": control,
                "action": decision["action"],
                "label": decision["label"],
                "reason": decision["reason"],
                "point": point,
            }
        )
    return rows


def _rows(before: dict, after: dict, watch: list[tuple[str, str]]) -> list[dict]:
    left = {(item["host"].lower(), item["control"]): item for item in before["apply_gate"]["decisions"]}
    right = {(item["host"].lower(), item["control"]): item for item in after["apply_gate"]["decisions"]}
    rows = []
    for host, control in watch:
        key = (host.lower(), control)
        prior = left[key]
        later = right[key]
        rows.append(
            {
                "host": host,
                "host_short": later["host_short"],
                "control": control,
                "before_action": prior["action"],
                "before_label": prior["label"],
                "before_reason": prior["reason"],
                "after_action": later["action"],
                "after_label": later["label"],
                "after_reason": later["reason"],
            }
        )
    return rows


def _wsus_backup(inputs: dict) -> None:
    for item in inputs["backups"]:
        if item["host"].lower().startswith("wsus"):
            item["last_success"] = "2026-09-27T02:00:00Z"
            item["last_restore_test"] = "2026-09-01"


def _exception_lapsed(inputs: dict) -> None:
    for item in inputs["exceptions"]:
        if item.get("id") == "EX-014":
            item["expires"] = "2026-09-26"


def _signing_key(inputs: dict) -> None:
    for row in inputs["duties"].get("predecessors") or []:
        if row.get("probe") == "rpm -q gpg-pubkey":
            row["met"] = True


def _operations_hold(inputs: dict) -> None:
    _signing_key(inputs)
    for item in inputs["hosts"]:
        if item["hostname"].lower() == "rhel-repo01.lab.local":
            item["tier"] = "production"


def default_today() -> date:
    return parse_day("2026-09-27")
