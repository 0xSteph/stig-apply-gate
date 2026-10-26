#!/usr/bin/env python3
"""Read-only vSphere posture check: ESXi hosts, vCenter, and virtual machines.

Snapshot mode is the one to use on an admin workstation that already has the
JSON. It needs no vCenter. The snapshot's top-level `kind` picks the checks:

  no kind, or "esxi-posture"  lockdown, SSH, NTP, syslog on one ESXi host
  "vcenter-posture"           NTP, syslog forwarding, SSO lockout and password
                              lifetime, vSphere Client session timeout
  "vm-posture"                the isolation and console advanced settings on
                              one VM, reported under the ledger host name of
                              its guest (rhel-mission01.lab.local, not the
                              inventory name), so the rows join that host

See fixtures/lab/scans for one of each.

  python vmware/collect_esxi_posture.py --snapshot path/to/snapshot.json

Govc mode only runs reads. These are the exact commands, and nothing else:

  --kind esxi (the default)
    govc host.service.ls -json -host <host>
    govc host.info -json -host <host>
    govc host.esxcli -host <host> system syslog config get
  --kind vcenter
    govc about -json
  --kind vm
    govc vm.info -json -e <vm>

ESXi: if SSH or NTP is missing from the service list, it exits instead of
assuming those services are stopped.

vCenter: `govc about` must report ApiType VirtualCenter. Appliance NTP,
syslog forwarding, the SSO lockout and password policy, and the vSphere Client
session timeout are not in the vSphere API that govc reads. They are written
as null, with the reason in `probe_errors`, and the register reports those
rows as not reviewed. Fill them in a snapshot from the VAMI (Time, Syslog) and
the SSO configuration pages, or leave them not reviewed. Nothing here invents
a value.

VM: `govc vm.info -json` must return exactly one VM and its
config.extraConfig list. A setting absent from that list is unset on the VM
and is written as null. If the list itself is missing, the read was
incomplete and the collector exits. `govc vm.option.info` and
`govc object.collect` are reads too, but this collector does not need them.

  GOVC_URL=https://vcenter.example GOVC_USERNAME=user GOVC_PASSWORD=secret \\
    python vmware/collect_esxi_posture.py --govc --host esxi01.example

  python vmware/collect_esxi_posture.py --govc --kind vcenter --host vcenter01.example
  python vmware/collect_esxi_posture.py --govc --kind vm --vm rhel-mission01 \\
    --as-host rhel-mission01.example --save rhel-mission01-vm_2026-09-20.json

--save writes the snapshot the checks were computed from, which is the file
the register reads. Put a date in its name.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from findings.vsphere import (  # noqa: E402
    checks_for_snapshot,
    snapshot_from_govc_outputs,
    vcenter_snapshot_from_govc_outputs,
    vm_snapshot_from_govc_outputs,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read ESXi, vCenter, or VM posture. Change nothing.")
    parser.add_argument("--snapshot", help="JSON snapshot. See fixtures/lab/scans for the shapes.")
    parser.add_argument("--govc", action="store_true", help="Collect with govc. Reads only.")
    parser.add_argument("--kind", choices=("esxi", "vcenter", "vm"), default="esxi", help="What --govc reads. Default esxi.")
    parser.add_argument("--host", dest="target", help="ESXi or vCenter host name, required with --govc for esxi and vcenter.")
    parser.add_argument("--vm", help="VM inventory name, required with --govc --kind vm.")
    parser.add_argument("--as-host", help="Ledger host name for the VM's guest. Defaults to the VM name.")
    parser.add_argument("--save", help="Write the collected snapshot JSON here.")
    parser.add_argument("--insecure", action="store_true", help="Set GOVC_INSECURE=1 for a lab certificate.")
    args = parser.parse_args()

    try:
        if args.snapshot:
            snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        elif args.govc:
            snapshot = _from_govc(args, parser)
        else:
            parser.error("pass --snapshot or --govc")
        checks = checks_for_snapshot(snapshot)
    except ValueError as exc:
        raise SystemExit(f"refusing: {exc}") from exc

    if args.save:
        Path(args.save).write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(checks, indent=2))
    return 0


def _from_govc(args: argparse.Namespace, parser: argparse.ArgumentParser) -> dict:
    env = os.environ.copy()
    if args.insecure:
        env["GOVC_INSECURE"] = "1"
    today = date.today().isoformat()
    if args.kind == "vm":
        if not args.vm:
            parser.error("--vm is required with --govc --kind vm")
        vcenter = urlparse(env.get("GOVC_URL", "")).hostname or env.get("GOVC_URL", "")
        if not vcenter:
            parser.error("GOVC_URL must name the vCenter for --kind vm")
        info = _run(["govc", "vm.info", "-json", "-e", args.vm], env)
        return vm_snapshot_from_govc_outputs(args.vm, vcenter, today, info, ledger_host=args.as_host)
    if not args.target:
        parser.error("--host is required with --govc")
    if args.kind == "vcenter":
        about = _run(["govc", "about", "-json"], env)
        return vcenter_snapshot_from_govc_outputs(args.target, today, about)
    services = _run(["govc", "host.service.ls", "-json", "-host", args.target], env)
    info = _run(["govc", "host.info", "-json", "-host", args.target], env)
    syslog = _run(["govc", "host.esxcli", "-host", args.target, "system", "syslog", "config", "get"], env)
    return snapshot_from_govc_outputs(args.target, today, services, info, syslog)


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
