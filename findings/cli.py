from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from findings.evidence import write_evidence, write_remediation_plan
from findings.ledger import build_ledger
from findings.parsers import load_scans
from findings.policy import load_policy, parse_day


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="findings", description="Offline findings ledger for enclave baselines.")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="Build the Integration Lab sample and write a ledger.")
    demo.add_argument("--today", default="2026-09-27")
    demo.add_argument("--out", default="web/src/data/ledger.json")
    demo.add_argument("--scans", default="fixtures/lab/scans")
    demo.add_argument("--evidence", default="")
    demo.add_argument("--plan", default="ansible/generated/lab-plan.yml")
    demo.add_argument("--gate", default="ansible/generated/apply-gate.json")
    demo.add_argument("--duties", default="fixtures/lab/duties.json")

    ingest = sub.add_parser("ingest", help="Build a ledger from exports you already have.")
    ingest.add_argument("--scan", action="append", required=True, help="File or directory of XCCDF, CKL, ACAS CSV, or vSphere snapshots.")
    ingest.add_argument("--hosts", required=True)
    ingest.add_argument("--exceptions", required=True)
    ingest.add_argument("--backups", required=True)
    ingest.add_argument("--services", required=True)
    ingest.add_argument("--site", required=True)
    ingest.add_argument("--milestones", required=True)
    ingest.add_argument("--duties", default="")
    ingest.add_argument("--policy", default="policy/default.json")
    ingest.add_argument("--today", default="")
    ingest.add_argument("--out", required=True)
    ingest.add_argument("--evidence", default="")
    ingest.add_argument("--gate", default="")

    evidence = sub.add_parser("evidence", help="Write an evidence pack from a ledger JSON file.")
    evidence.add_argument("--ledger", required=True)
    evidence.add_argument("--out", required=True)

    rehearse = sub.add_parser(
        "rehearse",
        help="Try gate changes on a copy. Does not write the lab record or the playbook gate.",
    )
    rehearse.add_argument("--today", default="2026-09-27")
    rehearse.add_argument("--lab", default="fixtures/lab")
    rehearse.add_argument("--scenario", default="all", choices=["all", "wsus-backup", "exception-lapsed", "signing-key", "operations-hold"])
    rehearse.add_argument("--out", default="dist/window")
    rehearse.add_argument(
        "--publish",
        action="store_true",
        help="Also write web/src/data/window.json so the Test window page matches this run.",
    )

    args = parser.parse_args(argv)
    if args.command == "demo":
        return _demo(args)
    if args.command == "ingest":
        return _ingest(args)
    if args.command == "evidence":
        ledger = json.loads(Path(args.ledger).read_text(encoding="utf-8"))
        write_evidence(ledger, Path(args.out))
        return 0
    if args.command == "rehearse":
        return _rehearse(args)
    return 1


def _demo(args: argparse.Namespace) -> int:
    from findings.lab import write_lab_scans

    scan_dir = Path(args.scans)
    write_lab_scans(scan_dir)
    ledger = _ledger_from_dir(
        scan_dir=scan_dir,
        hosts=_load(Path("fixtures/lab/hosts.json")),
        exceptions=_load(Path("fixtures/lab/exceptions.json")),
        backups=_load(Path("fixtures/lab/backups.json")),
        services=_load(Path("fixtures/lab/services.json")),
        site=_load(Path("fixtures/lab/site.json")),
        milestones=_load(Path("fixtures/lab/milestones.json")),
        duties=_load(Path(args.duties)) if args.duties else {},
        policy_path=Path("policy/default.json"),
        today=parse_day(args.today),
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
    if args.evidence:
        write_evidence(ledger, Path(args.evidence))
    if args.plan:
        write_remediation_plan(ledger, Path(args.plan))
    if args.gate:
        _write_gate(ledger, Path(args.gate))
    print(f"wrote {out}")
    return 0


def _ingest(args: argparse.Namespace) -> int:
    today = parse_day(args.today) if args.today else date.today()
    observations, problems = _read_scans([Path(raw) for raw in args.scan])
    if problems:
        return _reject(problems)
    ledger = build_ledger(
        observations,
        policy=load_policy(args.policy),
        today=today,
        hosts=_load(Path(args.hosts)),
        exceptions=_load(Path(args.exceptions)),
        backups=_load(Path(args.backups)),
        services=_load(Path(args.services)),
        site=_load(Path(args.site)),
        milestones=_load(Path(args.milestones)),
        duties=_load(Path(args.duties)) if args.duties else {},
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
    if args.evidence:
        write_evidence(ledger, Path(args.evidence))
    if args.gate:
        _write_gate(ledger, Path(args.gate))
    print(f"wrote {out}")
    return 0


# The lab record and the file the playbook reads. A rehearsal must not replace these.
PROTECTED_OUTPUTS = (
    Path("web/src/data/ledger.json"),
    Path("ansible/generated/apply-gate.json"),
    Path("ansible/generated/lab-plan.yml"),
)


def _rehearse(args: argparse.Namespace) -> int:
    from findings.window import publishable, rehearse, render_report

    out = Path(args.out)
    blocked = _blocked_output(out)
    if blocked:
        print(f"Refusing to write {out}. That path is the lab record the interview walks.", file=sys.stderr)
        return 2
    report = rehearse(Path(args.lab), today=parse_day(args.today), scenario=args.scenario)
    out.mkdir(parents=True, exist_ok=True)
    text = render_report(report)
    (out / "report.md").write_text(text, encoding="utf-8")
    (out / "report.json").write_text(json.dumps(publishable(report), indent=2) + "\n", encoding="utf-8")
    if args.publish:
        published = Path("web/src/data/window.json")
        published.parent.mkdir(parents=True, exist_ok=True)
        published.write_text(json.dumps(publishable(report), indent=2) + "\n", encoding="utf-8")
        print(f"wrote {published}")
    print(text, end="")
    print(f"wrote {out / 'report.md'}")
    return 0


def _blocked_output(path: Path) -> bool:
    resolved = path.resolve()
    lab = Path("fixtures/lab").resolve()
    if resolved == lab or lab in resolved.parents:
        return True
    for protected in PROTECTED_OUTPUTS:
        if resolved == protected.resolve():
            return True
    return False


def _ledger_from_dir(*, scan_dir: Path, hosts, exceptions, backups, services, site, milestones, duties, policy_path: Path, today: date) -> dict:
    observations, problems = _read_scans([scan_dir])
    if problems:
        raise SystemExit(_reject(problems))
    return build_ledger(
        observations,
        policy=load_policy(policy_path),
        today=today,
        hosts=hosts,
        exceptions=exceptions,
        backups=backups,
        services=services,
        site=site,
        milestones=milestones,
        duties=duties,
    )


def _write_gate(ledger: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    gate = ledger["apply_gate"]
    path.write_text(
        json.dumps({"decisions": gate["decisions"], "unscanned": gate["unscanned"]}, indent=2) + "\n",
        encoding="utf-8",
    )


def _read_scans(paths: list[Path]) -> tuple[list, list[str]]:
    observations = []
    problems: list[str] = []
    for path in paths:
        found, failed = load_scans(path)
        observations.extend(found)
        problems.extend(failed)
    return observations, problems


def _reject(problems: list[str]) -> int:
    print("No ledger was written. Fix these files and rerun:", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 2


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))
