from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

from findings.cli import main
from findings.evidence import write_evidence
from findings.lab import write_lab_scans
from findings.ledger import build_ledger
from findings.parsers import load_scans, parse_scan
from findings.policy import DEFAULT_POLICY

TODAY = date(2026, 9, 27)
MILESTONES = {"baseline": "2026-07-15", "previous": "2026-08-20", "current": "2026-09-20"}


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


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _demo(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Build the lab ledger and evidence pack under tmp_path. Returns (ledger, scans, attestation)."""
    scans = tmp_path / "scans"
    ledger = tmp_path / "ledger.json"
    evidence = tmp_path / "evidence"
    code = main(
        [
            "demo",
            "--out",
            str(ledger),
            "--evidence",
            str(evidence),
            "--plan",
            str(tmp_path / "plan.yml"),
            "--gate",
            str(tmp_path / "apply-gate.json"),
            "--scans",
            str(scans),
        ]
    )
    assert code == 0
    return ledger, scans, evidence / "attestation.json"


def test_ledger_sources_carry_hashes(tmp_path: Path):
    scans = tmp_path / "scans"
    write_lab_scans(scans)
    observations, problems = load_scans(scans)
    assert problems == []
    ledger = _ledger(observations)
    assert len({item["file"] for item in ledger["sources"]}) == len(list(scans.iterdir()))
    for item in ledger["sources"]:
        path = Path(item["file"])
        assert "\\" not in item["file"]
        assert item["sha256"] == _sha(path)
        assert item["bytes"] == path.stat().st_size


def test_sources_hash_from_disk_or_record_null(tmp_path: Path):
    path = tmp_path / "acas_2026-09-20.csv"
    path.write_text(
        "Plugin ID,CVE,CVSS,Risk,Host,Name,Synopsis\n"
        "187315,CVE-2023-48795,5.9,Medium,rhel-mission01.lab.local,Terrapin,SSH prefix truncation.\n",
        encoding="utf-8",
    )
    # parse_scan does not carry a hash, so the ledger hashes the file it can still find.
    observations = parse_scan(path)
    [source] = _ledger(observations)["sources"]
    assert source["sha256"] == _sha(path) and source["bytes"] == path.stat().st_size
    # A file that is gone by the time the ledger is built is recorded as null, not guessed.
    path.unlink()
    [source] = _ledger(observations)["sources"]
    assert source["sha256"] is None and source["bytes"] is None


def test_hash_is_taken_when_the_file_is_read(tmp_path: Path):
    scans = tmp_path / "scans"
    write_lab_scans(scans)
    target = scans / "acas_2026-09-20.csv"
    before = _sha(target)
    observations, _problems = load_scans(scans)
    target.unlink()
    ledger = _ledger(observations)
    entry = next(item for item in ledger["sources"] if item["file"].endswith("acas_2026-09-20.csv"))
    assert entry["sha256"] == before


def test_attestation_matches_ledger(tmp_path: Path):
    ledger_path, scans, attestation_path = _demo(tmp_path)
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    assert attestation["sources"] == ledger["sources"]
    assert all(item["sha256"] and item["bytes"] for item in attestation["sources"])
    # The manifest is the sha256sum layout, sorted, one line per distinct file.
    lines = sorted({f"{_sha(Path(item['file']))}  {item['file']}" for item in ledger["sources"]})
    assert len(lines) == len(list(scans.iterdir()))
    manifest = hashlib.sha256("".join(line + "\n" for line in lines).encode("utf-8")).hexdigest()
    assert attestation["manifest_sha256"] == manifest


def test_verify_passes_on_untouched_exports(tmp_path: Path, capsys):
    ledger, scans, attestation = _demo(tmp_path)
    capsys.readouterr()
    code = main(["verify", "--ledger", str(ledger), "--scan", str(scans), "--attestation", str(attestation)])
    out, err = capsys.readouterr()
    assert code == 0, err
    assert "0 mismatch, 0 missing" in out
    assert "attestation agrees with the ledger" in out
    assert err == ""


def test_verify_fails_when_one_byte_changes(tmp_path: Path, capsys):
    ledger, scans, _attestation = _demo(tmp_path)
    target = scans / "rhel-repo01_2026-09-20.xml"
    data = bytearray(target.read_bytes())
    data[-2] ^= 0x01
    target.write_bytes(bytes(data))
    capsys.readouterr()
    code = main(["verify", "--ledger", str(ledger), "--scan", str(scans)])
    out, err = capsys.readouterr()
    assert code == 1
    row = next(line for line in out.splitlines() if "rhel-repo01_2026-09-20.xml" in line)
    assert row.rstrip().endswith("mismatch")
    assert "rhel-repo01_2026-09-20.xml: mismatch" in err


def test_verify_fails_when_a_file_is_missing(tmp_path: Path, capsys):
    ledger, scans, _attestation = _demo(tmp_path)
    (scans / "wsus01_2026-09-20.ckl").unlink()
    capsys.readouterr()
    code = main(["verify", "--ledger", str(ledger), "--scan", str(scans)])
    out, err = capsys.readouterr()
    assert code == 1
    row = next(line for line in out.splitlines() if "wsus01_2026-09-20.ckl" in line)
    assert row.rstrip().endswith("missing")
    assert "wsus01_2026-09-20.ckl: missing" in err


def test_verify_reports_an_extra_file(tmp_path: Path, capsys):
    ledger, scans, _attestation = _demo(tmp_path)
    (scans / "ad01_2026-10-01.ckl").write_text("<CHECKLIST/>\n", encoding="utf-8")
    capsys.readouterr()
    code = main(["verify", "--ledger", str(ledger), "--scan", str(scans)])
    out, _err = capsys.readouterr()
    # Every source still matches, so this passes, but the extra file is named.
    assert code == 0
    row = next(line for line in out.splitlines() if "ad01_2026-10-01.ckl" in line)
    assert row.rstrip().endswith("extra")
    assert "1 extra file(s)" in out


def test_verify_fails_when_attestation_disagrees(tmp_path: Path, capsys):
    ledger, scans, attestation = _demo(tmp_path)
    record = json.loads(attestation.read_text(encoding="utf-8"))
    record["sources"][0]["sha256"] = "0" * 64
    attestation.write_text(json.dumps(record), encoding="utf-8")
    capsys.readouterr()
    code = main(["verify", "--ledger", str(ledger), "--scan", str(scans), "--attestation", str(attestation)])
    _out, err = capsys.readouterr()
    assert code == 1
    assert "does not agree with the ledger" in err
