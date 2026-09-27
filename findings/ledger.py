from __future__ import annotations

from collections import defaultdict
from datetime import date, timedelta

from findings import __version__
from findings.catalog import lookup
from findings.gate import build_apply_gate
from findings.models import FAIL_RESULTS, PASS_RESULTS, Observation, slug_for
from findings.policy import Policy, parse_day


def build_ledger(
    observations: list[Observation],
    *,
    policy: Policy,
    today: date,
    hosts: list[dict],
    exceptions: list[dict],
    backups: list[dict],
    services: list[dict],
    site: dict,
    milestones: dict[str, str],
    duties: dict | None = None,
) -> dict:
    observations = _synthesize_acas_passes(observations)
    host_meta = {item["hostname"].lower(): item for item in hosts}
    clusters = _cluster(observations)
    findings = []
    for group in clusters:
        finding = _finding_from_group(group, policy=policy, today=today, host_meta=host_meta, exceptions=exceptions)
        findings.append(finding)
    findings.sort(key=lambda item: (item["clock"] != "overdue", item["cat"], item["due"] or "9999", item["host"], item["control"]))

    milestone_dates = {name: parse_day(value) for name, value in milestones.items()}
    drift = _drift(findings, milestone_dates)
    backup_rows = evaluate_backups(backups, today)
    for finding in findings:
        finding["drift"] = _drift_label(finding, drift)
        if any(item["slug"] == finding["slug"] for item in drift["opened_since_baseline"]):
            finding["flags"].append("opened_since_baseline")

    attention = _attention(findings, backup_rows)
    windows = _windows(findings, host_meta)
    stats = _stats(findings, drift)
    brief = _brief(findings, backup_rows, drift, windows, today, site)
    apply_gate = build_apply_gate(
        findings=findings,
        hosts=hosts,
        backups=backup_rows,
        duties=duties,
        today=today,
        current=milestone_dates.get("current"),
    )
    by_slug = {item["slug"]: item for item in apply_gate["decisions"]}
    for finding in findings:
        decision = by_slug.get(finding["slug"])
        finding["apply_action"] = decision["action"] if decision else None
        finding["apply_reason"] = decision["reason"] if decision else None
        if decision and decision["action"] == "hollow" and "hollow_pass" not in finding["flags"]:
            finding["flags"].append("hollow_pass")
    for decision in apply_gate["decisions"]:
        if decision["action"] != "hollow":
            continue
        attention.append(
            {
                "kind": "finding",
                "slug": decision["slug"],
                "href": f"/findings/{decision['slug']}",
                "title": next(item["title"] for item in findings if item["slug"] == decision["slug"]),
                "host": decision["host_short"],
                "control": decision["control"],
                "cat": next(item["cat"] for item in findings if item["slug"] == decision["slug"]),
                "clock": "closed",
                "reason": decision["reason"],
                "due": None,
            }
        )
    gates = handoff_gates(findings, backup_rows, services)
    hollow = [item for item in apply_gate["decisions"] if item["action"] == "hollow"]
    gates["gates"].extend(
        [
            {
                "id": "hollow-pass",
                "title": "No passing row depends on a host that is still failing",
                "status": "fail" if hollow else "pass",
                "detail": "; ".join(f"{item['host_short']} {item['control']}" for item in hollow)
                or "A pass on a client is not counted while the host it installs from is still failing.",
            },
            {
                "id": "unscanned",
                "title": "Every inventoried host was in this period's scan",
                "status": "fail" if apply_gate["unscanned"] else "pass",
                "detail": ", ".join(apply_gate["unscanned"]) or "Every host in the inventory has a result dated this period.",
            },
        ]
    )
    gates["ready"] = all(gate["status"] == "pass" for gate in gates["gates"])

    return {
        "tool": "findings-register",
        "version": __version__,
        "generated_for": today.isoformat(),
        "site": site,
        "policy": {
            "sla_days": policy.sla_days,
            "due_soon_days": policy.due_soon_days,
            "regression_restarts_clock": policy.regression_restarts_clock,
            "exception_grace_days": policy.exception_grace_days,
            "cvss_cat_i_min": policy.cvss_cat_i_min,
            "cvss_cat_ii_min": policy.cvss_cat_ii_min,
        },
        "milestones": {name: value.isoformat() for name, value in milestone_dates.items()},
        "hosts": hosts,
        "services": services,
        "findings": findings,
        "exceptions": _exception_view(exceptions, findings, today),
        "drift": drift,
        "backups": backup_rows,
        "attention": attention,
        "windows": windows,
        "brief": brief,
        "handoff": gates,
        "apply_gate": apply_gate,
        "stats": stats,
        "sources": _sources(observations),
    }


def evaluate_backups(backups: list[dict], today: date) -> list[dict]:
    from datetime import datetime, timezone

    as_of = datetime(today.year, today.month, today.day, 12, 0, tzinfo=timezone.utc)
    rows = []
    for item in backups:
        last_success = datetime.fromisoformat(item["last_success"].replace("Z", "+00:00"))
        age_hours = (as_of - last_success).total_seconds() / 3600
        rpo_hours = float(item["rpo_hours"])
        restore = parse_day(item["last_restore_test"])
        restore_age = (today - restore).days
        restore_max = int(item["restore_test_max_days"])
        rpo_met = age_hours <= rpo_hours
        restore_met = restore_age <= restore_max
        status = "ok" if rpo_met and restore_met else "breach"
        reasons = []
        if not rpo_met:
            reasons.append(f"Last good backup is {int(age_hours)} hours old against an RPO of {int(rpo_hours)} hours.")
        if not restore_met:
            reasons.append(f"Last restore test was {restore_age} days ago. Policy is {restore_max} days.")
        rows.append(
            {
                **item,
                "age_hours": round(age_hours, 1),
                "restore_age_days": restore_age,
                "rpo_met": rpo_met,
                "restore_met": restore_met,
                "status": status,
                "reasons": reasons,
            }
        )
    return rows


def handoff_gates(findings: list[dict], backups: list[dict], services: list[dict]) -> dict:
    open_findings = [item for item in findings if item["clock"] != "closed"]
    cat_i_overdue = [item for item in open_findings if item["cat"] == "I" and item["clock"] == "overdue"]
    expired = [item for item in open_findings if "exception_expired" in item["flags"]]
    regressions = [item for item in open_findings if item["regression"]]
    unreviewed = [item for item in regressions if not item.get("engineer_note")]
    backup_breaches = [item for item in backups if item["status"] != "ok"]
    missing_runbooks = [item for item in services if not item.get("runbook")]
    gates = [
        {
            "id": "cat-i-clock",
            "title": "No CAT I item is past its clock",
            "status": "fail" if cat_i_overdue else "pass",
            "detail": _name_list(cat_i_overdue) or "Every open CAT I is inside the SLA or covered by an approved exception.",
        },
        {
            "id": "expired-exceptions",
            "title": "No expired exception is still open",
            "status": "fail" if expired else "pass",
            "detail": _name_list(expired) or "Approved exceptions are either still in force or the finding is closed.",
        },
        {
            "id": "regressions-reviewed",
            "title": "Every regression has an engineer note",
            "status": "fail" if unreviewed else "pass",
            "detail": _name_list(unreviewed) or "Regressions are explained, not just re-opened.",
        },
        {
            "id": "backups",
            "title": "RPO and restore tests are inside policy",
            "status": "fail" if backup_breaches else "pass",
            "detail": ", ".join(item["host"] for item in backup_breaches) or "Every recorded system met RPO and has a recent restore test.",
        },
        {
            "id": "runbooks",
            "title": "Every enterprise service has a runbook",
            "status": "fail" if missing_runbooks else "pass",
            "detail": ", ".join(item["name"] for item in missing_runbooks) or "AD, DNS, DHCP, WSUS, repo, and vCenter each have a one-page runbook.",
        },
    ]
    ready = all(gate["status"] == "pass" for gate in gates)
    return {"ready": ready, "gates": gates}


def _synthesize_acas_passes(observations: list[Observation]) -> list[Observation]:
    acas = [item for item in observations if item.source == "acas"]
    others = [item for item in observations if item.source != "acas"]
    coverage: dict[str, set[date]] = defaultdict(set)
    failed: dict[str, dict[date, set[str]]] = defaultdict(lambda: defaultdict(set))
    meta: dict[tuple[str, str], Observation] = {}
    explicit_pass: set[tuple[str, str, date]] = set()
    for item in acas:
        coverage[item.host.lower()].add(item.observed_at)
        plugin = item.plugin_id or item.cve or ""
        if not plugin:
            continue
        if item.result in PASS_RESULTS:
            explicit_pass.add((item.host.lower(), plugin, item.observed_at))
        elif item.result in FAIL_RESULTS:
            failed[item.host.lower()][item.observed_at].add(plugin)
            meta[(item.host.lower(), plugin)] = item
    synthesized: list[Observation] = []
    for host, dates in coverage.items():
        ordered = sorted(dates)
        plugins: set[str] = set()
        for day in ordered:
            plugins |= failed[host].get(day, set())
        for plugin in plugins:
            fail_days = {day for day in ordered if plugin in failed[host].get(day, set())}
            template = meta.get((host, plugin))
            if template is None:
                continue
            for day in ordered:
                if day in fail_days or (host, plugin, day) in explicit_pass:
                    continue
                if not any(fail < day for fail in fail_days):
                    continue
                synthesized.append(
                    Observation(
                        host=template.host,
                        observed_at=day,
                        source="acas",
                        source_file=template.source_file,
                        benchmark=template.benchmark,
                        plugin_id=template.plugin_id,
                        cve=template.cve,
                        title=template.title,
                        severity=template.severity,
                        cvss=template.cvss,
                        result="pass",
                        detail="Absent from a later ACAS export that still covered this host.",
                        platform=template.platform,
                    )
                )
    return others + acas + synthesized


def _cluster(observations: list[Observation]) -> list[list[Observation]]:
    parent = list(range(len(observations)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    buckets: dict[tuple[str, str, str], int] = {}
    for index, observation in enumerate(observations):
        for kind, value in observation.identifiers():
            key = (observation.host.lower(), kind, value)
            if key in buckets:
                union(index, buckets[key])
            else:
                buckets[key] = index
    groups: dict[int, list[Observation]] = defaultdict(list)
    for index, observation in enumerate(observations):
        groups[find(index)].append(observation)
    return list(groups.values())


def _finding_from_group(
    group: list[Observation],
    *,
    policy: Policy,
    today: date,
    host_meta: dict[str, dict],
    exceptions: list[dict],
) -> dict:
    ordered = sorted(group, key=lambda item: (item.observed_at, item.source))
    host = ordered[-1].host
    control = _control_key(ordered)
    identifiers = {
        "rule_ver": _latest(ordered, "rule_ver"),
        "vuln_num": _latest(ordered, "vuln_num"),
        "rule_id": _latest(ordered, "rule_id"),
        "plugin_id": _latest(ordered, "plugin_id"),
        "cve": _latest(ordered, "cve"),
    }
    history = _history(ordered)
    latest_result = history[-1]["result"]
    regression = _is_regression(history)
    severity, verified, override = _severity(ordered)
    cat, cat_source = _category(ordered, severity, policy)
    exception = _match_exception(exceptions, host, identifiers, control)
    clock, due, flags = _clock(
        history=history,
        latest_result=latest_result,
        cat=cat,
        exception=exception,
        today=today,
        policy=policy,
    )
    if regression and clock != "closed":
        flags.append("regression")
    if override:
        flags.append("severity_override")
    if not verified:
        flags.append("severity_unverified")
    meta = host_meta.get(host.lower(), {})
    raw_guidance = lookup(control)
    if raw_guidance.get("severity_verified") is False:
        verified = False
        if "severity_unverified" not in flags:
            flags.append("severity_unverified")
    guidance = {key: value for key, value in raw_guidance.items() if key != "severity_verified"}
    open_start = _streak_start(history, policy.regression_restarts_clock)
    if open_start is not None:
        first_seen = open_start.isoformat()
    else:
        fails = [point["date"] for point in history if point["result"] in FAIL_RESULTS]
        first_seen = fails[0] if fails else history[0]["date"]
    days_overdue = 0
    days_to_due: int | None = None
    if due and clock != "closed":
        delta = (due - today).days
        days_to_due = delta
        if delta < 0:
            days_overdue = -delta
    comments = _latest(ordered, "comments") or ""
    detail = _latest(ordered, "detail") or ""
    return {
        "slug": slug_for(host, control),
        "host": host,
        "host_short": host.split(".")[0],
        "platform": meta.get("platform") or ordered[-1].platform,
        "role": meta.get("role", ""),
        "owner": meta.get("owner", ""),
        "control": control,
        **identifiers,
        "title": _best_title(ordered),
        "benchmark": _latest(ordered, "benchmark") or "",
        "severity": severity,
        "severity_verified": verified,
        "severity_override": override,
        "cat": cat,
        "cat_source": cat_source,
        "cci": _union(ordered, "cci"),
        "nist": _union(ordered, "nist"),
        "result": latest_result,
        "clock": clock,
        "flags": flags,
        "regression": regression and clock != "closed",
        "first_seen": first_seen,
        "last_seen": history[-1]["date"],
        "due": due.isoformat() if due else None,
        "days_to_due": days_to_due,
        "days_overdue": days_overdue,
        "history": history,
        "comments": comments,
        "detail": detail,
        "engineer_note": "",
        "cvss": _latest_cvss(ordered),
        "remediation": guidance,
        "exception_id": exception["id"] if exception else None,
    }


def _control_key(group: list[Observation]) -> str:
    for attr in ("rule_ver", "cve", "vuln_num", "plugin_id", "rule_id"):
        for item in reversed(group):
            value = getattr(item, attr)
            if value:
                return str(value)
    return "unknown"


def _latest(group: list[Observation], attr: str):
    for item in reversed(group):
        value = getattr(item, attr)
        if value:
            return value
    return None


def _latest_cvss(group: list[Observation]) -> float | None:
    for item in reversed(group):
        if item.cvss is not None:
            return item.cvss
    return None


def _best_title(group: list[Observation]) -> str:
    titles = [item.title for item in group if item.title]
    if not titles:
        return _control_key(group)
    return max(titles, key=len)


def _union(group: list[Observation], attr: str) -> list[str]:
    values: list[str] = []
    for item in group:
        for value in getattr(item, attr):
            if value not in values:
                values.append(value)
    return values


def _history(group: list[Observation]) -> list[dict]:
    by_day: dict[date, list[Observation]] = defaultdict(list)
    for item in group:
        by_day[item.observed_at].append(item)
    points = []
    for day in sorted(by_day):
        items = by_day[day]
        result = _winning_result(item.result for item in items)
        points.append(
            {
                "date": day.isoformat(),
                "result": result,
                "sources": sorted({item.source for item in items}),
            }
        )
    return points


def _winning_result(results) -> str:
    found = list(results)
    for candidate in ("fail", "error", "notchecked", "pass", "notapplicable"):
        if candidate in found:
            return candidate
    return found[-1]


def _is_regression(history: list[dict]) -> bool:
    if len(history) < 2:
        return False
    return history[-1]["result"] in FAIL_RESULTS and history[-2]["result"] in PASS_RESULTS


def _severity(group: list[Observation]) -> tuple[str | None, bool, str | None]:
    override = None
    verified = True
    severity = None
    for item in group:
        if item.severity:
            severity = item.severity
            verified = item.severity_verified
        if item.severity_override:
            override = item.severity_override
    if override:
        return override, verified, override
    return severity, verified, None


def _category(group: list[Observation], severity: str | None, policy: Policy) -> tuple[str, str]:
    if any(item.cve or item.source == "acas" for item in group) and not any(item.rule_ver for item in group):
        cvss = _latest_cvss(group)
        if cvss is not None:
            return policy.cat_for_cvss(cvss), "cvss"
        if severity == "high":
            return "I", "acas-risk"
        if severity == "low":
            return "III", "acas-risk"
        return "II", "acas-risk"
    mapping = {"high": "I", "medium": "II", "low": "III"}
    if severity in mapping:
        return mapping[severity], "stig"
    return "II", "default"


def _match_exception(exceptions: list[dict], host: str, identifiers: dict, control: str) -> dict | None:
    keys = {control}
    keys.update(str(value) for value in identifiers.values() if value)
    chosen = None
    for item in exceptions:
        item_host = item.get("host", "*").lower()
        if item_host not in {host.lower(), "*"}:
            continue
        if item.get("control") not in keys:
            continue
        chosen = item
    return chosen


def _clock(
    *,
    history: list[dict],
    latest_result: str,
    cat: str,
    exception: dict | None,
    today: date,
    policy: Policy,
) -> tuple[str, date | None, list[str]]:
    if latest_result in PASS_RESULTS:
        return "closed", None, []
    if latest_result == "notchecked":
        return "not_reviewed", None, []
    start = _streak_start(history, policy.regression_restarts_clock)
    if start is None:
        return "not_reviewed", None, []
    sla = policy.sla_days[cat]
    organic_due = start + timedelta(days=sla)
    flags: list[str] = []
    due = organic_due
    if exception and exception.get("status") == "approved":
        expires = parse_day(exception["expires"])
        if expires >= today:
            return "excepted", expires, ["excepted"]
        due = expires + timedelta(days=policy.exception_grace_days)
        flags.append("exception_expired")
    elif exception and exception.get("status") == "pending":
        flags.append("exception_pending")
    if today > due:
        clock = "overdue"
    elif (due - today).days <= policy.due_soon_days:
        clock = "due_soon"
    else:
        clock = "on_track"
    return clock, due, flags


def _streak_start(history: list[dict], restarts: bool) -> date | None:
    if history[-1]["result"] not in FAIL_RESULTS:
        return None
    if restarts:
        start = parse_day(history[-1]["date"])
        for point in reversed(history[:-1]):
            if point["result"] in FAIL_RESULTS:
                start = parse_day(point["date"])
            elif point["result"] in PASS_RESULTS:
                break
        return start
    for point in history:
        if point["result"] in FAIL_RESULTS:
            return parse_day(point["date"])
    return parse_day(history[-1]["date"])


def _drift(findings: list[dict], milestones: dict[str, date]) -> dict:
    previous = milestones.get("previous")
    current = milestones.get("current")
    baseline = milestones.get("baseline")
    buckets = {"regressed": [], "closed": [], "persistent": [], "new": [], "opened_since_baseline": []}
    if previous is None or current is None:
        return {key: [] for key in buckets}
    for finding in findings:
        prev = _result_as_of(finding["history"], previous)
        curr = _result_as_of(finding["history"], current)
        base = _result_as_of(finding["history"], baseline) if baseline else None
        ref = {"slug": finding["slug"], "host": finding["host"], "control": finding["control"], "title": finding["title"], "cat": finding["cat"]}
        if prev in PASS_RESULTS and curr in FAIL_RESULTS:
            buckets["regressed"].append(ref)
        elif prev in FAIL_RESULTS and curr in PASS_RESULTS:
            buckets["closed"].append(ref)
        elif prev in FAIL_RESULTS and curr in FAIL_RESULTS:
            buckets["persistent"].append(ref)
        elif prev is None and curr in FAIL_RESULTS:
            buckets["new"].append(ref)
        if curr in FAIL_RESULTS and (base in PASS_RESULTS or base is None) and ref not in buckets["new"] and ref not in buckets["regressed"]:
            if base in PASS_RESULTS:
                buckets["opened_since_baseline"].append(ref)
    return buckets


def _result_as_of(history: list[dict], milestone: date) -> str | None:
    eligible = [point for point in history if parse_day(point["date"]) <= milestone]
    if not eligible:
        return None
    return eligible[-1]["result"]


def _drift_label(finding: dict, drift: dict) -> str:
    for name in ("regressed", "closed", "new", "persistent", "opened_since_baseline"):
        if any(item["slug"] == finding["slug"] for item in drift[name]):
            return name
    return "unchanged"


def _attention(findings: list[dict], backups: list[dict]) -> list[dict]:
    rows = []
    for finding in findings:
        reason = None
        if finding["clock"] == "overdue":
            reason = "Past the CAT clock"
        elif finding["clock"] == "due_soon":
            reason = "Due inside the warning window"
        elif finding["regression"]:
            reason = "Regressed since the previous scan"
        else:
            reason = None
        if "exception_pending" in finding["flags"]:
            reason = f"{reason}. Exception is still unsigned" if reason else "Exception is waiting on the ISSO"
        if reason is None:
            continue
        rows.append(
            {
                "kind": "finding",
                "slug": finding["slug"],
                "href": f"/findings/{finding['slug']}",
                "title": finding["title"],
                "host": finding["host_short"],
                "control": finding["control"],
                "cat": finding["cat"],
                "clock": finding["clock"],
                "reason": reason,
                "due": finding["due"],
            }
        )
    for backup in backups:
        if backup["status"] == "ok":
            continue
        rows.append(
            {
                "kind": "backup",
                "slug": backup["host"],
                "href": "/backups",
                "title": backup["method"],
                "host": backup["host"].split(".")[0],
                "control": "backup",
                "cat": "",
                "clock": "breach",
                "reason": " ".join(backup["reasons"]),
                "due": None,
            }
        )
    return rows


def _windows(findings: list[dict], host_meta: dict[str, dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        if finding["clock"] in {"closed", "excepted"}:
            continue
        grouped[finding["host"]].append(finding)
    windows = []
    for host, items in grouped.items():
        items = sorted(items, key=lambda item: (item["cat"], item["due"] or "9999"))
        meta = host_meta.get(host.lower(), {})
        windows.append(
            {
                "host": host,
                "host_short": host.split(".")[0],
                "note": meta.get("window_note") or "One visit. Do not schedule a separate change per row.",
                "items": [
                    {
                        "slug": item["slug"],
                        "control": item["control"],
                        "title": item["title"],
                        "cat": item["cat"],
                        "clock": item["clock"],
                        "class": item["remediation"]["class"],
                        "days_overdue": item["days_overdue"],
                    }
                    for item in items
                ],
            }
        )
    rank = {"overdue": 0, "due_soon": 1, "on_track": 2, "not_reviewed": 3}

    def sort_key(window: dict) -> tuple:
        clocks = [rank.get(item["clock"], 9) for item in window["items"]]
        cats = [item["cat"] for item in window["items"]]
        overdue = max((item["days_overdue"] for item in window["items"]), default=0)
        return (-overdue, min(clocks) if clocks else 9, min(cats) if cats else "Z", window["host"])

    windows.sort(key=sort_key)
    return windows


def _stats(findings: list[dict], drift: dict) -> dict:
    open_items = [item for item in findings if item["clock"] != "closed"]
    by_cat = {}
    for cat in ("I", "II", "III"):
        subset = [item for item in open_items if item["cat"] == cat]
        by_cat[cat] = {
            "open": len(subset),
            "overdue": sum(1 for item in subset if item["clock"] == "overdue"),
        }
    return {
        "open": len(open_items),
        "overdue": sum(1 for item in findings if item["clock"] == "overdue"),
        "due_soon": sum(1 for item in findings if item["clock"] == "due_soon"),
        "excepted": sum(1 for item in findings if item["clock"] == "excepted"),
        "regressions": sum(1 for item in findings if item["regression"]),
        "closed_this_period": len(drift["closed"]),
        "by_cat": by_cat,
    }


def _brief(findings, backups, drift, windows, today: date, site: dict) -> dict:
    overdue = [item for item in findings if item["clock"] == "overdue"]
    paragraphs = []
    name = site.get("name", "This site")
    paragraphs.append(
        f"{name}, as of {today.day} {today.strftime('%b %Y')}. This is the note for the ISSO, written from the ledger rather than from memory."
    )
    if overdue:
        oldest = max(overdue, key=lambda item: item["days_overdue"])
        paragraphs.append(
            f"{len(overdue)} items are past their clock. The oldest is {oldest['control']} on {oldest['host_short']}, "
            f"{oldest['days_overdue']} days late. {oldest['remediation']['summary']}"
        )
    else:
        paragraphs.append("Nothing is past its CAT clock.")
    if drift["regressed"]:
        names = ", ".join(f"{item['control']} on {item['host'].split('.')[0]}" for item in drift["regressed"])
        paragraphs.append(f"Regressed since the August scan: {names}. A regression restarts the clock. It does not inherit credit for the months it was clean.")
    if drift["closed"]:
        names = ", ".join(f"{item['control']} on {item['host'].split('.')[0]}" for item in drift["closed"])
        paragraphs.append(f"Closed since the last scan: {names}.")
    expired = [item for item in findings if "exception_expired" in item["flags"]]
    if expired:
        paragraphs.append(
            "An exception that expires is an open finding the next morning. "
            + " ".join(f"{item['control']} on {item['host_short']} expired and is still open." for item in expired)
        )
    breaches = [item for item in backups if item["status"] != "ok"]
    if breaches:
        paragraphs.append(
            "Backups: "
            + " ".join(" ".join(item["reasons"]) + f" ({item['host'].split('.')[0]})" for item in breaches)
        )
    if windows:
        first = windows[0]
        controls = ", ".join(item["control"] for item in first["items"][:4])
        paragraphs.append(f"Next bench visit is {first['host_short']}: {controls}. {first['note']}")
    return {"paragraphs": paragraphs}


def _exception_view(exceptions: list[dict], findings: list[dict], today: date) -> list[dict]:
    by_id = {item.get("exception_id"): item for item in findings if item.get("exception_id")}
    rows = []
    for item in exceptions:
        expires = parse_day(item["expires"]) if item.get("expires") else None
        status = item.get("status", "draft")
        if status == "approved" and expires and expires < today:
            display = "expired"
        else:
            display = status
        linked = by_id.get(item["id"])
        rows.append({**item, "display_status": display, "finding_slug": linked["slug"] if linked else None})
    return rows


def _sources(observations: list[Observation]) -> list[dict]:
    seen = []
    keys = set()
    for item in observations:
        if item.result == "pass" and "Absent from a later ACAS" in item.detail:
            continue
        key = (item.source_file, item.observed_at.isoformat(), item.source)
        if key in keys or not item.source_file:
            continue
        keys.add(key)
        seen.append({"file": item.source_file, "source": item.source, "observed_at": item.observed_at.isoformat()})
    return seen


def _name_list(findings: list[dict]) -> str:
    if not findings:
        return ""
    return ", ".join(f"{item['control']} on {item['host_short']}" for item in findings)
