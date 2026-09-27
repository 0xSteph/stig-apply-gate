#!/usr/bin/env python3
"""Read-only ESXi posture check.

Snapshot mode is the one to use on an admin workstation that already has the
JSON. Govc mode only runs reads, and it exits if SSH or NTP is missing from
the service list instead of assuming those services are stopped.

  python vmware/collect_esxi_posture.py --snapshot path/to/esxi.json

  GOVC_URL=https://vcenter.example GOVC_USERNAME=user GOVC_PASSWORD=secret \\
    python vmware/collect_esxi_posture.py --govc --host esxi01.example
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from findings.vsphere import checks_from_snapshot, snapshot_from_govc_outputs  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Read ESXi lockdown, SSH, NTP, and syslog. Change nothing.")
    parser.add_argument("--snapshot", help="JSON snapshot. See fixtures/lab/scans for the shape.")
    parser.add_argument("--govc", action="store_true", help="Collect with govc. Reads only.")
    parser.add_argument("--host", dest="target", help="ESXi host name, required with --govc.")
    parser.add_argument("--insecure", action="store_true", help="Set GOVC_INSECURE=1 for a lab certificate.")
    args = parser.parse_args()

    if args.snapshot:
        snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    elif args.govc:
        if not args.target:
            parser.error("--host is required with --govc")
        snapshot = _from_govc(args.target, insecure=args.insecure)
    else:
        parser.error("pass --snapshot or --govc")

    print(json.dumps(checks_from_snapshot(snapshot), indent=2))
    return 0


def _from_govc(host: str, insecure: bool) -> dict:
    env = os.environ.copy()
    if insecure:
        env["GOVC_INSECURE"] = "1"
    services = _run(["govc", "host.service.ls", "-json", "-host", host], env)
    info = _run(["govc", "host.info", "-json", "-host", host], env)
    syslog = _run(["govc", "host.esxcli", "-host", host, "system", "syslog", "config", "get"], env)
    return snapshot_from_govc_outputs(host, date.today().isoformat(), services, info, syslog)


def _run(command: list[str], env: dict[str, str]) -> str:
    try:
        completed = subprocess.run(command, check=True, capture_output=True, text=True, env=env)
    except FileNotFoundError as exc:
        raise SystemExit("govc is not on PATH. Use --snapshot with JSON collected elsewhere.") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.stderr.strip() or f"{command[0]} failed") from exc
    return completed.stdout


if __name__ == "__main__":
    raise SystemExit(main())
