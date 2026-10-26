from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from findings import signing
from findings.cli import main
from findings.signing import GateSignatureError, sign_gate, signature_path, verify_gate

GATE = Path("ansible/generated/apply-gate.json")
TODAY = "2026-09-27"
IDENTITY = "findings-register"


def _require_ssh_keygen() -> str:
    exe = shutil.which("ssh-keygen")
    if exe is None:
        pytest.skip("ssh-keygen is not installed")
    return exe


@pytest.fixture
def signer(tmp_path: Path) -> dict:
    exe = _require_ssh_keygen()
    key = tmp_path / "keys" / "gate_key"
    key.parent.mkdir()
    subprocess.run([exe, "-t", "ed25519", "-N", "", "-C", "test", "-q", "-f", str(key)], check=True)
    public = Path(str(key) + ".pub").read_text(encoding="utf-8").split()
    allowed = tmp_path / "allowed_signers"
    # ssh-keygen reads this file byte for byte; keep LF line endings on Windows too.
    allowed.write_bytes(f"{IDENTITY} {public[0]} {public[1]}\n".encode("utf-8"))
    gate = tmp_path / "gate" / "apply-gate.json"
    gate.parent.mkdir()
    gate.write_bytes(GATE.read_bytes())
    return {"key": key, "allowed": allowed, "gate": gate}


def test_sign_and_verify_round_trip(signer: dict):
    sig = sign_gate(signer["gate"], signer["key"])
    assert sig == signature_path(signer["gate"])
    assert sig.is_file()
    parsed = verify_gate(signer["gate"], signer["allowed"], IDENTITY, generated_for=TODAY)
    assert any(item["action"] == "refuse" for item in parsed["decisions"])

    code = main(
        [
            "verify-gate",
            "--gate",
            str(signer["gate"]),
            "--allowed-signers",
            str(signer["allowed"]),
            "--identity",
            IDENTITY,
        ]
    )
    assert code == 0


def test_cli_sign_prints_the_allowed_signers_line(signer: dict, capsys):
    code = main(["sign", "--gate", str(signer["gate"]), "--key", str(signer["key"])])
    assert code == 0
    out = capsys.readouterr().out
    assert "allowed_signers line: findings-register ssh-ed25519 " in out
    assert signature_path(signer["gate"]).is_file()


def test_one_changed_byte_fails(signer: dict, capsys):
    sign_gate(signer["gate"], signer["key"])
    data = bytearray(signer["gate"].read_bytes())
    at = data.index(b'"refuse"') + 1
    data[at] = ord("R")
    signer["gate"].write_bytes(bytes(data))
    with pytest.raises(GateSignatureError, match="did not verify"):
        verify_gate(signer["gate"], signer["allowed"], IDENTITY)
    code = main(
        [
            "verify-gate",
            "--gate",
            str(signer["gate"]),
            "--allowed-signers",
            str(signer["allowed"]),
            "--identity",
            IDENTITY,
        ]
    )
    assert code != 0
    assert "findings sign" in capsys.readouterr().err


def test_refuse_flipped_to_allow_fails(signer: dict):
    sign_gate(signer["gate"], signer["key"])
    gate = json.loads(signer["gate"].read_text(encoding="utf-8"))
    for item in gate["decisions"]:
        if item["action"] == "refuse":
            item["action"] = "allow"
    signer["gate"].write_text(json.dumps(gate, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(GateSignatureError, match="did not verify"):
        verify_gate(signer["gate"], signer["allowed"], IDENTITY)


def test_wrong_identity_fails(signer: dict):
    sign_gate(signer["gate"], signer["key"])
    with pytest.raises(GateSignatureError, match="did not verify"):
        verify_gate(signer["gate"], signer["allowed"], "someone-else")


def test_stale_as_of_fails(signer: dict, tmp_path: Path):
    gate = json.loads(signer["gate"].read_text(encoding="utf-8"))
    for item in gate["decisions"]:
        item["as_of"] = "2026-09-20"
    signer["gate"].write_text(json.dumps(gate, indent=2) + "\n", encoding="utf-8")
    sign_gate(signer["gate"], signer["key"])
    # The signature itself is good. Only the date is old.
    verify_gate(signer["gate"], signer["allowed"], IDENTITY)
    with pytest.raises(GateSignatureError, match="stale"):
        verify_gate(signer["gate"], signer["allowed"], IDENTITY, generated_for=TODAY)

    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({"generated_for": TODAY}), encoding="utf-8")
    code = main(
        [
            "verify-gate",
            "--gate",
            str(signer["gate"]),
            "--allowed-signers",
            str(signer["allowed"]),
            "--identity",
            IDENTITY,
            "--ledger",
            str(ledger),
        ]
    )
    assert code != 0


def test_missing_signature_fails(signer: dict, capsys):
    with pytest.raises(GateSignatureError, match="No signature"):
        verify_gate(signer["gate"], signer["allowed"], IDENTITY)
    code = main(
        [
            "verify-gate",
            "--gate",
            str(signer["gate"]),
            "--allowed-signers",
            str(signer["allowed"]),
            "--identity",
            IDENTITY,
        ]
    )
    assert code != 0
    assert "findings sign" in capsys.readouterr().err


def test_demo_signs_the_gate_as_it_is_written(signer: dict, tmp_path: Path):
    gate_path = tmp_path / "out" / "apply-gate.json"
    code = main(
        [
            "demo",
            "--out",
            str(tmp_path / "out" / "ledger.json"),
            "--plan",
            str(tmp_path / "out" / "plan.yml"),
            "--gate",
            str(gate_path),
            "--scans",
            str(tmp_path / "scans"),
            "--sign-key",
            str(signer["key"]),
        ]
    )
    assert code == 0
    assert signature_path(gate_path).is_file()
    ledger = json.loads((tmp_path / "out" / "ledger.json").read_text(encoding="utf-8"))
    verify_gate(gate_path, signer["allowed"], IDENTITY, generated_for=ledger["generated_for"])


def test_missing_ssh_keygen_fails_closed(tmp_path: Path, monkeypatch):
    gate = tmp_path / "apply-gate.json"
    gate.write_bytes(GATE.read_bytes())
    signature_path(gate).write_text("not a real signature\n", encoding="utf-8")
    allowed = tmp_path / "allowed_signers"
    allowed.write_text("findings-register ssh-ed25519 AAAA\n", encoding="utf-8")
    monkeypatch.setattr(signing.shutil, "which", lambda name: None)
    with pytest.raises(GateSignatureError, match="ssh-keygen was not found"):
        verify_gate(gate, allowed, IDENTITY)
    with pytest.raises(GateSignatureError, match="ssh-keygen was not found"):
        sign_gate(gate, allowed)


def test_missing_allowed_signers_fails(tmp_path: Path):
    gate = tmp_path / "apply-gate.json"
    gate.write_bytes(GATE.read_bytes())
    signature_path(gate).write_text("not a real signature\n", encoding="utf-8")
    with pytest.raises(GateSignatureError, match="allowed signers"):
        verify_gate(gate, tmp_path / "allowed_signers", IDENTITY)


def test_rehearse_has_no_signing_option_and_writes_no_signature(tmp_path: Path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("rehearse must not sign anything")

    monkeypatch.setattr("findings.cli.sign_gate", refuse)
    monkeypatch.setattr(signing, "sign_gate", refuse)
    sigs_before = sorted(Path(".").glob("ansible/generated/*.sig"))

    for flag in ("--sign-key", "--signer-identity", "--key"):
        with pytest.raises(SystemExit):
            main(["rehearse", "--out", str(tmp_path / "window"), flag, "x"])

    code = main(["rehearse", "--out", str(tmp_path / "window"), "--today", TODAY])
    assert code == 0
    assert list(tmp_path.rglob("*.sig")) == []
    assert sorted(Path(".").glob("ansible/generated/*.sig")) == sigs_before


def test_site_play_verifies_before_the_role():
    play = Path("ansible/site.yml").read_text(encoding="utf-8")
    verify_at = play.index("'verify-gate'")
    assert verify_at < play.index("roles:")
    for needle in (
        "delegate_to: localhost",
        "run_once: true",
        "check_mode: false",
        "changed_when: false",
        "allowed_signers",
        "findings sign",
    ):
        assert needle in play[verify_at:], needle
    ignored = Path(".gitignore").read_text(encoding="utf-8").splitlines()
    assert "ansible/allowed_signers" in ignored
    assert "ansible/generated/*.sig" in ignored
    example = Path("ansible/allowed_signers.example").read_text(encoding="utf-8")
    assert "findings-register ssh-ed25519 AAAA" in example
