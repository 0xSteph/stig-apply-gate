"""Sign the apply gate and check the signature before the playbook reads it.

This wraps OpenSSH signatures (ssh-keygen -Y, OpenSSH 8.2 or newer). Signing writes
<gate>.sig next to the gate. Verifying needs an allowed_signers file and the identity
the signer was listed under. Every failure raises GateSignatureError, so a caller
that does not catch it stops instead of reading an unverified gate.

ssh-keygen is always run with an argument list, never through a shell.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

NAMESPACE = "findings-gate"
DEFAULT_IDENTITY = "findings-register"
VERIFY_TIMEOUT_SECONDS = 60


class GateSignatureError(Exception):
    """The gate is not signed, the signature did not verify, or the gate is stale."""


def signature_path(gate: Path) -> Path:
    return gate.with_name(gate.name + ".sig")


def sign_hint(gate: Path) -> str:
    return (
        f"Sign it on the controller: python -m findings sign --gate {gate} --key <private key>, "
        "then list the public key in ansible/allowed_signers as "
        f"'{DEFAULT_IDENTITY} ssh-ed25519 AAAA...'."
    )


def find_ssh_keygen(ssh_keygen: str | None = None) -> str:
    found = ssh_keygen or shutil.which("ssh-keygen")
    if not found:
        raise GateSignatureError(
            "ssh-keygen was not found on PATH. The gate cannot be signed or verified without it. "
            "Install OpenSSH 8.2 or newer on this machine and rerun."
        )
    return found


def sign_gate(gate: Path, key: Path, *, ssh_keygen: str | None = None) -> Path:
    """Write <gate>.sig with the private key at `key`. Returns the signature path."""
    gate = Path(gate)
    key = Path(key)
    if not gate.is_file():
        raise GateSignatureError(f"No gate file at {gate}. Build the gate before signing it.")
    if not key.is_file():
        raise GateSignatureError(f"No private key at {key}.")
    exe = find_ssh_keygen(ssh_keygen)
    sig = signature_path(gate)
    # Remove an old signature first, so a failed run cannot leave a signature for an older gate.
    sig.unlink(missing_ok=True)
    result = subprocess.run(
        [exe, "-Y", "sign", "-n", NAMESPACE, "-f", str(key), str(gate)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not sig.is_file():
        sig.unlink(missing_ok=True)
        detail = (result.stderr or result.stdout).strip() or f"exit code {result.returncode}"
        raise GateSignatureError(f"ssh-keygen could not sign {gate}: {detail}")
    return sig


def public_key_line(key: Path, identity: str) -> str | None:
    """The allowed_signers line for the public half of `key`, when <key>.pub is next to it."""
    pub = Path(str(key) + ".pub")
    if not pub.is_file():
        return None
    parts = pub.read_text(encoding="utf-8").split()
    if len(parts) < 2:
        return None
    return f"{identity} {parts[0]} {parts[1]}"


def gate_as_of(gate: dict) -> str | None:
    """The day the gate was computed for. Every decision must agree."""
    top = gate.get("as_of")
    days = {item.get("as_of") for item in gate.get("decisions", [])}
    if top:
        days.add(top)
    days.discard(None)
    if len(days) > 1:
        raise GateSignatureError(f"The gate mixes decisions from different days: {', '.join(sorted(days))}.")
    return next(iter(days), None)


def verify_gate(
    gate: Path,
    allowed_signers: Path,
    identity: str,
    *,
    generated_for: str | None = None,
    ssh_keygen: str | None = None,
) -> dict:
    """Check the signature on `gate` and return the parsed gate.

    The bytes that were verified are the bytes that are parsed, so the file cannot
    change between the check and the read inside this call. When `generated_for` is
    given (the ledger's generated_for), the gate's as_of must equal it.
    """
    gate = Path(gate)
    allowed_signers = Path(allowed_signers)
    sig = signature_path(gate)
    if not gate.is_file():
        raise GateSignatureError(f"No gate file at {gate}.")
    if not sig.is_file():
        raise GateSignatureError(f"No signature at {sig}. The gate is not trusted until it is signed. {sign_hint(gate)}")
    if not allowed_signers.is_file():
        raise GateSignatureError(
            f"No allowed signers file at {allowed_signers}. "
            "Copy ansible/allowed_signers.example to ansible/allowed_signers and put the signing public key in it."
        )
    if not identity:
        raise GateSignatureError("No signer identity was given.")
    exe = find_ssh_keygen(ssh_keygen)
    data = gate.read_bytes()
    try:
        result = subprocess.run(
            [exe, "-Y", "verify", "-f", str(allowed_signers), "-I", identity, "-n", NAMESPACE, "-s", str(sig)],
            input=data,
            capture_output=True,
            timeout=VERIFY_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise GateSignatureError(f"ssh-keygen did not finish verifying {gate} within {VERIFY_TIMEOUT_SECONDS} seconds.") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip() or f"exit code {result.returncode}"
        raise GateSignatureError(
            f"The signature on {gate} did not verify for {identity} against {allowed_signers}. "
            f"ssh-keygen said: {detail}. Do not run the play against this file. "
            f"Rebuild the gate if it was edited by hand. {sign_hint(gate)}"
        )
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateSignatureError(f"{gate} is signed but is not readable JSON: {exc}") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("decisions"), list):
        raise GateSignatureError(f"{gate} is signed but has no decisions list.")
    if generated_for:
        as_of = gate_as_of(parsed)
        if as_of is None:
            raise GateSignatureError(
                f"{gate} has no as_of date, so it cannot be matched to the ledger generated for {generated_for}."
            )
        if as_of != generated_for:
            raise GateSignatureError(
                f"{gate} is as of {as_of}, but the ledger was generated for {generated_for}. "
                f"The signed gate is stale. Rebuild the gate from the current ledger and sign it again. {sign_hint(gate)}"
            )
    return parsed
