"""The committed apply gate must match what the demo command writes today.

ansible/generated/apply-gate.json is the file the playbook reads before it edits
a host. If a change to the register moves a decision, this test fails and names
the host and control, so the gate file is regenerated on purpose and reviewed in
the same commit instead of drifting from the code.

The demo runs through the real entry point (python -m findings) from the
repository root, in a child interpreter started with -E -s. Those are the parts
of -I that ignore PYTHON* variables and the user site directory. -I itself also
implies -P, which leaves the working directory off sys.path, and then
`-m findings` cannot find the package unless it is installed. The demo
rewrites fixtures/lab/scans, which is deterministic, and sends every other
output into tmp_path.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
COMMITTED_GATE = REPO / "ansible" / "generated" / "apply-gate.json"
FIELDS = ("host", "control", "action", "reason", "tag", "probe", "bundle")


def _run_demo(tmp_path: Path) -> dict:
    gate_path = tmp_path / "apply-gate.json"
    command = [
        sys.executable,
        "-E",
        "-s",
        "-m",
        "findings",
        "demo",
        "--out",
        str(tmp_path / "ledger.json"),
        "--gate",
        str(gate_path),
        "--plan",
        str(tmp_path / "lab-plan.yml"),
        "--evidence",
        str(tmp_path / "evidence"),
    ]
    result = subprocess.run(command, cwd=REPO, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, f"demo exited {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    return json.loads(gate_path.read_text(encoding="utf-8"))


def _key(decision: dict) -> tuple[str, str]:
    return (decision["host"], decision["control"])


def _project(decision: dict) -> dict:
    return {field: decision.get(field) for field in FIELDS}


def _diff(expected: list[dict], actual: list[dict]) -> list[str]:
    lines: list[str] = []
    want = {_key(item): _project(item) for item in expected}
    got = {_key(item): _project(item) for item in actual}
    for key in sorted(want.keys() - got.keys()):
        lines.append(f"{key[0]} {key[1]}: in the committed gate, missing from the demo output")
    for key in sorted(got.keys() - want.keys()):
        lines.append(f"{key[0]} {key[1]}: new in the demo output, not in the committed gate")
    for key in sorted(want.keys() & got.keys()):
        for field in FIELDS:
            if want[key][field] != got[key][field]:
                lines.append(
                    f"{key[0]} {key[1]} {field}:\n"
                    f"    committed: {want[key][field]!r}\n"
                    f"    demo:      {got[key][field]!r}"
                )
    if not lines:
        order_want = [_key(item) for item in expected]
        order_got = [_key(item) for item in actual]
        if order_want != order_got:
            lines.append("same decisions, different order")
    return lines


def test_demo_gate_matches_the_committed_gate(tmp_path: Path):
    committed = json.loads(COMMITTED_GATE.read_text(encoding="utf-8"))
    generated = _run_demo(tmp_path)

    problems = _diff(committed["decisions"], generated["decisions"])
    if committed["unscanned"] != generated["unscanned"]:
        problems.append(
            "unscanned:\n"
            f"    committed: {committed['unscanned']!r}\n"
            f"    demo:      {generated['unscanned']!r}"
        )
    assert not problems, (
        "ansible/generated/apply-gate.json does not match `python -m findings demo`.\n"
        "Regenerate it with `python -m findings demo` and review the change.\n\n" + "\n".join(problems)
    )
