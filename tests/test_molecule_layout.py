"""Guards the Molecule scenarios under ansible/molecule/ without Docker or Ansible.

Molecule itself runs in CI (the molecule job in .github/workflows/ci.yml). This checks, on any
machine, that every scenario has its files, that each gate parses, names rhel-repo01.lab.local,
and says what the scenario expects, and that the signing step prepare runs accepts each gate.
Standard library only: the YAML files are checked as text.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from findings.signing import GateSignatureError, sign_gate, verify_gate

ROOT = Path(__file__).resolve().parents[1]
MOLECULE = ROOT / "ansible" / "molecule"
HOST = "rhel-repo01.lab.local"
SCENARIOS = ("unsigned", "refused", "probe", "allow")
SCENARIO_FILES = ("molecule.yml", "prepare.yml", "converge.yml", "verify.yml", "gate.json")
SHARED_FILES = (
    "shared/prepare.yml",
    "shared/tasks/checksums.yml",
    "shared/tasks/assert_untouched.yml",
    "shared/tasks/run_playbook.yml",
)
# Each row: (sign the gate, import a GPG key) as the scenario's group_vars say.
FLAGS = {
    "unsigned": (False, False),
    "refused": (True, False),
    "probe": (True, False),
    "allow": (True, True),
}


def _yaml_files() -> list[Path]:
    return sorted(MOLECULE.rglob("*.yml"))


def _gate(scenario: str) -> dict:
    return json.loads((MOLECULE / scenario / "gate.json").read_text(encoding="utf-8"))


def _by_tag(scenario: str) -> dict[str, dict]:
    return {row["tag"]: row for row in _gate(scenario)["decisions"]}


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_scenario_has_every_file(scenario: str) -> None:
    for name in SCENARIO_FILES:
        assert (MOLECULE / scenario / name).is_file(), f"{scenario}/{name} is missing"


def test_shared_files_exist() -> None:
    for name in SHARED_FILES:
        assert (MOLECULE / name).is_file(), f"{name} is missing"


def test_yaml_files_are_plain_documents() -> None:
    files = _yaml_files()
    # molecule.yml, prepare.yml, converge.yml, verify.yml per scenario, plus the shared files.
    assert len(files) == len(SCENARIOS) * 4 + len(SHARED_FILES)
    for path in files:
        data = path.read_bytes()
        assert data.startswith(b"---\n"), f"{path} does not start with a document marker"
        assert b"\r" not in data, f"{path} has CR line endings"
        assert b"\t" not in data, f"{path} has a tab"
        assert data.endswith(b"\n") and not data.endswith(b"\n\n"), f"{path} must end with one newline"


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_molecule_yml_names_the_lab_host(scenario: str) -> None:
    text = (MOLECULE / scenario / "molecule.yml").read_text(encoding="utf-8")
    assert f"  - name: {HOST}\n" in text
    assert "  name: docker\n" in text
    assert "pre_build_image: true" in text
    assert "privileged: false" in text
    assert "      - rhel\n" in text, "the platform must be in the rhel group site.yml targets"
    assert "findings_tier: lab" in text
    assert 'findings_ledger_file: ""' in text
    assert f"scenario:\n  name: {scenario}\n" in text
    sequence = text.split("test_sequence:", 1)[1]
    assert "idempotence" not in sequence
    for step in ("create", "prepare", "converge", "verify", "destroy"):
        assert f"    - {step}\n" in sequence
    sign, import_key = FLAGS[scenario]
    assert f"gate_test_sign_gate: {str(sign).lower()}" in text
    assert f"gate_test_import_signing_key: {str(import_key).lower()}" in text


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_prepare_uses_the_shared_playbook(scenario: str) -> None:
    text = (MOLECULE / scenario / "prepare.yml").read_text(encoding="utf-8")
    assert "ansible.builtin.import_playbook: ../shared/prepare.yml" in text


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_gate_has_the_generated_shape_and_names_the_lab_host(scenario: str) -> None:
    generated = json.loads((ROOT / "ansible" / "generated" / "apply-gate.json").read_text(encoding="utf-8"))
    keys = set(generated["decisions"][0])
    gate = _gate(scenario)
    assert set(gate) == set(generated)
    assert gate["decisions"], f"{scenario} gate has no decisions"
    for row in gate["decisions"]:
        assert set(row) == keys
        assert row["host"] == HOST
        assert row["slug"] == f"rhel-repo01--{row['control']}"
        assert row["tag"], "every row needs a tag, or the role cannot match it to --tags"
    assert len({row["as_of"] for row in gate["decisions"]}) == 1


def test_refused_gate_refuses_gpgcheck() -> None:
    row = _by_tag("refused")["gpgcheck"]
    assert (row["control"], row["action"]) == ("RHEL-08-010370", "refuse")


def test_probe_gate_checks_for_the_signing_key() -> None:
    row = _by_tag("probe")["gpgcheck"]
    assert (row["control"], row["action"], row["probe"]) == ("RHEL-08-010370", "probe", "rpm -q gpg-pubkey")


def test_allow_gate_allows_three_tags_and_holds_ssh_root() -> None:
    rows = _by_tag("allow")
    assert {tag: rows[tag]["action"] for tag in rows} == {
        "gpgcheck": "allow",
        "localpkg": "allow",
        "pwquality": "allow",
        "ssh-root": "window",
    }


def test_unsigned_gate_is_the_allow_gate() -> None:
    # The only difference between the two scenarios is the signature.
    assert _gate("unsigned") == _gate("allow")


def test_converge_runs_site_with_the_expected_tags() -> None:
    expected = {
        "unsigned": ["gpgcheck,localpkg,pwquality"],
        "refused": ["gpgcheck"],
        "probe": ["gpgcheck"],
        "allow": ["ssh-root", "gpgcheck,localpkg,pwquality"],
    }
    for scenario, tags in expected.items():
        text = (MOLECULE / scenario / "converge.yml").read_text(encoding="utf-8")
        assert re.findall(r"gate_test_tags: (\S+)", text) == tags, scenario
        assert "gate_test_playbook: site.yml" in text


def test_allow_verify_runs_revert() -> None:
    text = (MOLECULE / "allow" / "verify.yml").read_text(encoding="utf-8")
    assert "gate_test_playbook: revert.yml" in text
    assert "gate_test_file_hashes == gate_test_baseline" in text


def test_ci_runs_every_scenario() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "  molecule:\n" in ci
    assert "scenario: [unsigned, refused, probe, allow]" in ci
    assert "molecule test -s ${{ matrix.scenario }}" in ci


def _ssh_keygen() -> str:
    exe = shutil.which("ssh-keygen")
    if exe is None:
        pytest.skip("ssh-keygen is not installed")
    return exe


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_prepare_signing_step_accepts_the_gate(scenario: str, tmp_path: Path) -> None:
    """What shared/prepare.yml does on the controller, without Ansible."""
    exe = _ssh_keygen()
    key = tmp_path / "findings-gate"
    subprocess.run([exe, "-t", "ed25519", "-N", "", "-C", "molecule-gate-test", "-q", "-f", str(key)], check=True)
    fields = Path(str(key) + ".pub").read_text(encoding="utf-8").split()
    allowed = tmp_path / "allowed_signers"
    allowed.write_bytes(f"findings-register {fields[0]} {fields[1]}\n".encode("utf-8"))
    gate = tmp_path / "apply-gate.json"
    gate.write_bytes((MOLECULE / scenario / "gate.json").read_bytes())
    sign, _ = FLAGS[scenario]
    if sign:
        sign_gate(gate, key)
        assert verify_gate(gate, allowed, "findings-register")["decisions"]
    else:
        with pytest.raises(GateSignatureError, match="No signature"):
            verify_gate(gate, allowed, "findings-register")
