"""Hashes of the source exports, so an evidence pack can be checked against the files handed over."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePath

CHUNK = 1024 * 1024

# Inputs that sit next to exports but are not exports. load_scans skips them too.
NOT_EXPORTS = frozenset({"hosts.json", "exceptions.json", "backups.json", "services.json", "site.json", "milestones.json"})


def hash_file(path: Path) -> tuple[str, int]:
    """Return (sha256 hex, size in bytes), reading the file in chunks."""
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def display_path(value: str) -> str:
    """Forward slashes, so the recorded path does not depend on the OS that built the ledger."""
    return PurePath(value).as_posix()


def manifest_lines(sources: list[dict]) -> list[str] | None:
    """Sorted "sha256  path" lines, one per distinct source file.

    Returns None when any source has no recorded hash. A manifest that skipped a
    file would read as if that file had been checked.
    """
    lines = set()
    for item in sources:
        sha = item.get("sha256")
        if not sha:
            return None
        lines.add(f"{sha}  {item['file']}")
    return sorted(lines)


def manifest_sha256(sources: list[dict]) -> str | None:
    """sha256 over the manifest lines, each ending in a newline (the layout sha256sum prints)."""
    lines = manifest_lines(sources)
    if lines is None:
        return None
    text = "".join(line + "\n" for line in lines)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def collect_files(paths: list[Path]) -> tuple[list[Path], list[str]]:
    """Every file under the given paths. A path that does not exist is returned as a problem."""
    files: list[Path] = []
    problems: list[str] = []
    for path in paths:
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(item for item in path.rglob("*") if item.is_file() and item.name not in NOT_EXPORTS))
        else:
            problems.append(f"{path}: scan path does not exist.")
    return files, problems


def verify_exports(sources: list[dict], scan_paths: list[Path]) -> tuple[list[dict], list[str]]:
    """Compare the ledger's recorded hashes with the files on disk, matched by file name.

    Each row has path, expected, actual, status. Status is ok, mismatch, missing,
    or extra. The problem list is what makes verification fail: any mismatch, any
    missing file, an unreadable scan path, or a ledger source without a hash.
    An extra file is reported in the rows but does not fail verification.
    """
    files, problems = collect_files(scan_paths)

    expected: dict[str, dict] = {}
    for item in sources:
        name = PurePath(item["file"]).name
        current = expected.get(name)
        if current is None:
            expected[name] = item
        elif current.get("sha256") != item.get("sha256") or current["file"] != item["file"]:
            problems.append(
                f"{name}: the ledger names two different sources with this file name "
                f"({current['file']}, {item['file']}). Matching by name cannot tell them apart."
            )

    actual: dict[str, list[Path]] = {}
    for path in files:
        actual.setdefault(path.name, []).append(path)

    rows: list[dict] = []
    for name in sorted(expected):
        item = expected[name]
        want = item.get("sha256")
        candidates = actual.pop(name, [])
        if not candidates:
            rows.append({"path": item["file"], "expected": want or "", "actual": "", "status": "missing"})
            problems.append(f"{item['file']}: missing. No file named {name} under the scan paths.")
            continue
        hashed = []
        for path in candidates:
            try:
                hashed.append((path, *hash_file(path)))
            except OSError as exc:
                problems.append(f"{path}: could not be read: {exc}")
        if not hashed:
            continue
        # Two files with the same name: the one that matches counts, the rest are extra.
        primary = next((entry for entry in hashed if want and entry[1] == want), hashed[0])
        path, got, size = primary
        if want and got == want:
            rows.append({"path": str(path), "expected": want, "actual": got, "status": "ok"})
        else:
            rows.append({"path": str(path), "expected": want or "", "actual": got, "status": "mismatch"})
            if not want:
                problems.append(f"{path}: the ledger recorded no sha256 for {item['file']}. Rebuild the ledger from the exports.")
            else:
                recorded = item.get("bytes")
                sizes = f" Size {size} bytes, ledger recorded {recorded}." if recorded is not None else ""
                problems.append(f"{path}: mismatch. Expected {want}, got {got}.{sizes}")
        for other_path, other_got, _size in hashed:
            if other_path != path:
                rows.append({"path": str(other_path), "expected": "", "actual": other_got, "status": "extra"})

    for name in sorted(actual):
        for path in actual[name]:
            try:
                got, _size = hash_file(path)
            except OSError as exc:
                got = ""
                problems.append(f"{path}: could not be read: {exc}")
            rows.append({"path": str(path), "expected": "", "actual": got, "status": "extra"})

    return rows, problems


def compare_attestation(ledger_sources: list[dict], attestation: dict) -> list[str]:
    """Problems where the attestation's hashes disagree with the ledger's. Empty when they agree."""
    problems: list[str] = []
    ledger_files = {item["file"]: (item.get("sha256"), item.get("bytes")) for item in ledger_sources}
    attested = attestation.get("sources") or []
    attested_files = {item.get("file", ""): (item.get("sha256"), item.get("bytes")) for item in attested}
    for path in sorted(set(ledger_files) | set(attested_files)):
        if path not in attested_files:
            problems.append(f"attestation: {path} is in the ledger but not in the attestation.")
        elif path not in ledger_files:
            problems.append(f"attestation: {path} is in the attestation but not in the ledger.")
        elif ledger_files[path] != attested_files[path]:
            want, want_size = ledger_files[path]
            got, got_size = attested_files[path]
            problems.append(
                f"attestation: {path} sha256 {got} ({got_size} bytes) does not agree with the ledger "
                f"sha256 {want} ({want_size} bytes)."
            )
    recomputed = manifest_sha256(ledger_sources)
    stated = attestation.get("manifest_sha256")
    if stated != recomputed:
        problems.append(f"attestation: manifest_sha256 {stated} does not agree with the ledger, which gives {recomputed}.")
    return problems
