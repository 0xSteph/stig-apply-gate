"""What moved between two ledgers.

The register is point in time. This compares last period's ledger with this
one and lists what an ISSO asks about first: rows that opened, rows that
closed, rows that closed with no scan to show for it, clocks that moved,
exceptions running out, hosts that dropped out of the period, gate decisions
that changed, and backups that went in or out of policy.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

from findings.policy import parse_day

DEFAULT_DUE_SOON_DAYS = 21
DEFAULT_EXPIRING_DAYS = 30


class LedgerReadError(ValueError):
    """A ledger file could not be read as a ledger."""


def load_ledger(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise LedgerReadError(f"{path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise LedgerReadError(f"{path}: not JSON. {exc}") from exc
    if not isinstance(data, dict):
        raise LedgerReadError(f"{path}: not a ledger. The top level is not an object.")
    if not isinstance(data.get("findings"), list):
        raise LedgerReadError(f"{path}: not a ledger. There is no findings list.")
    try:
        parse_day(data.get("generated_for") or "")
    except (TypeError, ValueError) as exc:
        raise LedgerReadError(f"{path}: generated_for is missing or is not a date.") from exc
    return data


def compute_delta(
    before: dict,
    after: dict,
    *,
    due_within: int | None = None,
    expiring_within: int = DEFAULT_EXPIRING_DAYS,
) -> dict:
    before_day = parse_day(before["generated_for"])
    after_day = parse_day(after["generated_for"])
    if due_within is None:
        due_within = int((after.get("policy") or {}).get("due_soon_days", DEFAULT_DUE_SOON_DAYS))
    left = {item["slug"]: item for item in before["findings"]}
    right = {item["slug"]: item for item in after["findings"]}

    new_open, closed, closed_unscanned, vanished, regressions, clocks = [], [], [], [], [], []
    for slug, row in right.items():
        prior = left.get(slug)
        if _open(row) and (prior is None or not _open(prior)):
            new_open.append({"row": row, "was": "absent" if prior is None else "closed"})
        if prior is not None and _open(prior) and not _open(row):
            if _rescanned(row, before_day):
                closed.append({"row": row, "was": prior["clock"]})
            else:
                closed_unscanned.append({"row": row, "was": prior["clock"]})
        reopened = prior is not None and not _open(prior) and _open(row)
        flagged = bool(row.get("regression")) and not (prior is not None and prior.get("regression"))
        if reopened or (flagged and _open(row)):
            regressions.append({"row": row, "was": prior["clock"] if prior else "absent"})
        if prior is not None and _open(prior) and _open(row) and prior.get("clock") != row.get("clock"):
            clocks.append({"row": row, "was": prior["clock"]})
    for slug, prior in left.items():
        if slug not in right and _open(prior):
            vanished.append({"row": prior, "was": prior["clock"]})

    horizon = after_day + timedelta(days=due_within)
    due = []
    for row in right.values():
        if not _open(row) or row.get("clock") == "excepted" or not row.get("due"):
            continue
        when = parse_day(row["due"])
        if after_day <= when <= horizon:
            due.append({"row": row, "due": when.isoformat(), "days": (when - after_day).days})
    due.sort(key=lambda item: (item["due"], item["row"]["host"], item["row"]["control"]))

    expiring, expired = _exceptions(before, after, before_day, after_day, expiring_within)

    return {
        "before": before_day.isoformat(),
        "after": after_day.isoformat(),
        "due_within": due_within,
        "expiring_within": expiring_within,
        "new_open": _sorted(new_open),
        "closed": _sorted(closed),
        "closed_without_rescan": _sorted(closed_unscanned),
        "vanished": _sorted(vanished),
        "regressions": _sorted(regressions),
        "clock_changes": _sorted(clocks),
        "due": due,
        "exceptions_expiring": expiring,
        "exceptions_expired": expired,
        "hosts_missing": _missing_hosts(before, after, before_day, after_day),
        "gate_changes": _gate_changes(before, after),
        "backup_changes": _backup_changes(before, after),
    }


def summary_line(delta: dict) -> str:
    def count(n: int, one: str, many: str | None = None) -> str:
        return f"{n} {one if n == 1 else (many or one + 's')}"

    parts = [
        count(len(delta["new_open"]), "new open row"),
        count(len(delta["closed"]), "closed"),
        count(len(delta["closed_without_rescan"]), "closed without a rescan", "closed without a rescan"),
        count(len(delta["regressions"]), "regression"),
        count(len(delta["clock_changes"]), "clock change"),
        f"{len(delta['due'])} due within {delta['due_within']} days",
        count(len(delta["exceptions_expiring"]), "exception expiring", "exceptions expiring")
        + f" within {delta['expiring_within']} days",
        count(len(delta["exceptions_expired"]), "exception expired", "exceptions expired"),
        count(len(delta["hosts_missing"]), "host missing", "hosts missing"),
        count(len(delta["gate_changes"]), "gate change"),
        count(len(delta["backup_changes"]), "backup change"),
    ]
    if delta["vanished"]:
        parts.append(count(len(delta["vanished"]), "open row gone from the later ledger", "open rows gone from the later ledger"))
    return f"Findings delta {delta['before']} to {delta['after']}: " + ", ".join(parts) + "."


def render_delta(delta: dict) -> str:
    lines = [
        "# What moved since last period",
        "",
        summary_line(delta),
        "",
        f"Before: ledger for {delta['before']}. After: ledger for {delta['after']}.",
        "",
    ]

    def section(title: str, body: list[str]) -> None:
        lines.append(f"## {title}")
        lines.append("")
        lines.extend(body or ["none"])
        lines.append("")

    section(
        "New open rows",
        [
            f"- {_label(item['row'])}: {_state(item['row'])}. "
            + ("Not in the earlier ledger." if item["was"] == "absent" else "Closed in the earlier ledger.")
            for item in delta["new_open"]
        ],
    )
    section(
        "Closed since",
        [
            f"- {_label(item['row'])}: was {item['was']}, closed on the {item['row'].get('last_seen') or '-'} scan."
            for item in delta["closed"]
        ],
    )
    section(
        "Closed without a rescan",
        [
            f"- {_label(item['row'])}: was {item['was']}, now closed, but the last scan in its history is "
            f"{_last_scan(item['row']) or 'missing'}, not after {delta['before']}. Ask what closed it."
            for item in delta["closed_without_rescan"]
        ],
    )
    if delta["vanished"]:
        section(
            "Open rows gone from the later ledger",
            [
                f"- {_label(item['row'])}: was {item['was']} and is not in the later ledger at all. Missing is not closed."
                for item in delta["vanished"]
            ],
        )
    section(
        "Regressions",
        [
            f"- {_label(item['row'])}: {_state(item['row'])}. Was {item['was']}."
            for item in delta["regressions"]
        ],
    )
    section(
        "Clock changes",
        [
            f"- {_label(item['row'])}: {item['was']} -> {item['row']['clock']}, due {item['row'].get('due') or '-'}."
            for item in delta["clock_changes"]
        ],
    )
    section(
        f"Due within {delta['due_within']} days",
        [
            f"- {_label(item['row'])}: CAT {item['row'].get('cat', '?')}, due {item['due']}, {item['days']} day(s) out."
            for item in delta["due"]
        ],
    )
    section(
        f"Exceptions expiring within {delta['expiring_within']} days",
        [_exception_line(item) for item in delta["exceptions_expiring"]],
    )
    section(
        f"Exceptions that expired between {delta['before']} and {delta['after']}",
        [_exception_line(item) for item in delta["exceptions_expired"]],
    )
    section(
        "Hosts missing from the period",
        [f"- {item['host']}: {item['reason']}" for item in delta["hosts_missing"]],
    )
    gate_lines: list[str] = []
    for item in delta["gate_changes"]:
        gate_lines.append(f"- {item['host_short']} {item['control']}: {item['before_action']} -> {item['after_action']}")
        gate_lines.append(f"  Before: {item['before_reason']}")
        gate_lines.append(f"  After: {item['after_reason']}")
    section("Gate decisions that changed", gate_lines)
    section(
        "Backups that changed status",
        [
            f"- {item['host']}: {item['before']} -> {item['after']}."
            + (f" {item['reasons']}" if item["reasons"] else "")
            for item in delta["backup_changes"]
        ],
    )
    return "\n".join(lines).rstrip() + "\n"


def _open(row: dict) -> bool:
    return row.get("clock") != "closed"


def _scan_dates(row: dict) -> list[str]:
    dates = [point.get("date", "") for point in row.get("history") or [] if point.get("date")]
    if not dates and row.get("last_seen"):
        dates = [row["last_seen"]]
    return dates


def _last_scan(row: dict) -> str | None:
    dates = _scan_dates(row)
    return max(dates) if dates else None


def _rescanned(row: dict, since: date) -> bool:
    return any(parse_day(day) > since for day in _scan_dates(row))


def _sorted(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda item: (item["row"].get("host", ""), item["row"].get("control", "")))


def _short(row: dict) -> str:
    return row.get("host_short") or str(row.get("host", "")).split(".")[0]


def _label(row: dict) -> str:
    return f"{_short(row)} {row.get('control', row.get('slug', '?'))}"


def _state(row: dict) -> str:
    text = f"CAT {row.get('cat', '?')}, {row.get('clock', '?')}"
    if row.get("due"):
        text += f", due {row['due']}"
    if row.get("exception_id"):
        text += f", exception {row['exception_id']}"
    return text


def _exceptions(before: dict, after: dict, before_day: date, after_day: date, within: int) -> tuple[list[dict], list[dict]]:
    records: dict[str, dict] = {}
    for item in before.get("exceptions") or []:
        if item.get("id"):
            records[item["id"]] = item
    for item in after.get("exceptions") or []:
        if item.get("id"):
            records[item["id"]] = item
    horizon = after_day + timedelta(days=within)
    expiring, expired = [], []
    for item in records.values():
        if item.get("status") != "approved" or not item.get("expires"):
            continue
        try:
            ends = parse_day(item["expires"])
        except ValueError:
            continue
        entry = {
            "id": item["id"],
            "host": item.get("host", ""),
            "control": item.get("control", ""),
            "expires": ends.isoformat(),
            "days": (ends - after_day).days,
            "ticket": item.get("ticket", ""),
        }
        if after_day <= ends <= horizon:
            expiring.append(entry)
        elif before_day <= ends < after_day:
            expired.append(entry)
    key = lambda entry: (entry["expires"], entry["id"])  # noqa: E731
    return sorted(expiring, key=key), sorted(expired, key=key)


def _exception_line(item: dict) -> str:
    when = item["expires"]
    if item["days"] >= 0:
        tail = f"in force through {when}, {item['days']} day(s) left"
    else:
        tail = f"ended {when}"
    ticket = f" ({item['ticket']})" if item["ticket"] else ""
    return f"- {item['id']}{ticket} {item['host'].split('.')[0]} {item['control']}: {tail}."


def _missing_hosts(before: dict, after: dict, before_day: date, after_day: date) -> list[dict]:
    seen_before: dict[str, str] = {}
    for row in before["findings"]:
        seen_before.setdefault(row.get("host", "").lower(), row.get("host", ""))
    scanned_in_period: set[str] = set()
    last_scan: dict[str, str] = {}
    for row in after["findings"]:
        host = row.get("host", "").lower()
        for day in _scan_dates(row):
            if day > last_scan.get(host, ""):
                last_scan[host] = day
            if before_day < parse_day(day) <= after_day:
                scanned_in_period.add(host)
    missing: dict[str, dict] = {}
    for host, name in seen_before.items():
        if not host or host in scanned_in_period:
            continue
        if host in last_scan:
            reason = f"in the earlier ledger, no scan after {before_day.isoformat()}. Last scan {last_scan[host]}."
        else:
            reason = "in the earlier ledger, no rows in the later ledger."
        missing[host] = {"host": name, "reason": reason}
    for name in (after.get("apply_gate") or {}).get("unscanned") or []:
        host = name.lower()
        if host in missing:
            missing[host]["reason"] += " Also listed as unscanned by the later gate."
        else:
            missing[host] = {"host": name, "reason": "listed as unscanned by the later gate. No result dated this period."}
    return [missing[host] for host in sorted(missing)]


def _gate_changes(before: dict, after: dict) -> list[dict]:
    left = {item["slug"]: item for item in (before.get("apply_gate") or {}).get("decisions") or [] if item.get("slug")}
    right = {item["slug"]: item for item in (after.get("apply_gate") or {}).get("decisions") or [] if item.get("slug")}
    rows = []
    for slug, later in right.items():
        prior = left.get(slug)
        if prior is None or prior.get("action") == later.get("action"):
            continue
        rows.append(
            {
                "slug": slug,
                "host_short": later.get("host_short") or str(later.get("host", "")).split(".")[0],
                "control": later.get("control", ""),
                "before_action": prior.get("action"),
                "after_action": later.get("action"),
                "before_reason": prior.get("reason", ""),
                "after_reason": later.get("reason", ""),
            }
        )
    return sorted(rows, key=lambda item: (item["host_short"], item["control"]))


def _backup_changes(before: dict, after: dict) -> list[dict]:
    left = {item["host"].lower(): item for item in before.get("backups") or [] if item.get("host")}
    rows = []
    for item in after.get("backups") or []:
        prior = left.get(str(item.get("host", "")).lower())
        if prior is None or prior.get("status") == item.get("status"):
            continue
        rows.append(
            {
                "host": item["host"],
                "before": prior.get("status"),
                "after": item.get("status"),
                "reasons": " ".join(item.get("reasons") or []),
            }
        )
    return sorted(rows, key=lambda item: item["host"])
