# Findings Register

A findings register for the exports an enclave already produces. You give it OpenSCAP or SCC XCCDF, a STIG Viewer checklist, an ACAS or Nessus CSV, and a read-only ESXi snapshot. It gives back CAT clocks, drift, exceptions, a backup check, and an evidence pack.

Shops already do this in Excel, eMASS, ACAS, SCC, and Evaluate-STIG. This does not replace those tools and it does not scan anything. It is the transcription after the exports exist: which rows are still open, which clock they are on, which ones are safe to hand to Ansible, and which ones are not.

There is no model and no network call. The result is the rule ids and the dates in the files.

The part that is not another tracker: `ansible/generated/apply-gate.json`. The playbook reads it before editing a file and stops when a signed exception is still in force, two hosts take time from each other, a disruptive change lands on a backup that missed its policy, a pass depends on another host that is still failing, a predecessor check such as `rpm -q gpg-pubkey` fails, or one restart would land before the rest of that service's changes. A host with no scan this period is not treated as clean. The stop for a signature lifts the day after the exception expires.

Integration Lab, the sample, is an unclassified stand-in for a small ground site: one domain controller (DNS and DHCP), WSUS, a RHEL 8 repository, one mission host, and vSphere. The scan files are synthetic. Rule identifiers that include a vulnerability number are public STIG identifiers. Titles and results were written for this lab. The register does not redistribute benchmark text.

## Run the sample

```bash
python3 -m pytest
python3 -m findings demo --out web/src/data/ledger.json --evidence dist/evidence
cd web && npm install && npm run dev -- --port 43123 --hostname 0.0.0.0
```

The sample clock is pinned to 27 Sep 2026 so the overdue rows stay overdue when someone clones the repo later. Pass `--today` to move it.

Try a change without touching that record:

```bash
python3 -m findings rehearse
```

That copies the lab inputs, moves one fact at a time, and writes `dist/window/report.md`. It does not write `fixtures/lab`, `web/src/data/ledger.json`, or `ansible/generated/apply-gate.json`. `dist/` is gitignored. Pass `--publish` when the Test window page should match the run you just made.

The four cases are the WSUS backup brought back inside policy, the ESXi SSH exception dated yesterday, the lab signing key marked imported, and that same key with the repository host marked operations. The operations case stays refused. The playbook inventory is the lab, and a host with `findings_tier=production` fails before any file is copied. A maintenance window is the scheduled time to apply a change the lab already proved, with someone at the console and a rollback.

Open the overview and read the note for the ISSO before the tables. The handoff page is red on purpose.

## Use your own exports

```bash
python3 -m findings ingest \
  --scan /path/to/exports \
  --hosts fixtures/lab/hosts.json \
  --exceptions fixtures/lab/exceptions.json \
  --backups fixtures/lab/backups.json \
  --services fixtures/lab/services.json \
  --site fixtures/lab/site.json \
  --milestones fixtures/lab/milestones.json \
  --policy policy/default.json \
  --today 2026-09-27 \
  --out ledger.json \
  --evidence dist/evidence
```

Put a date (`2026-09-20`) in checklist and CSV filenames. XCCDF uses `TestResult start-time`. JSON snapshots use `observed_at`.

Supported inputs:

- XCCDF 1.2 results, including the benchmark `Rule` block SCC and OpenSCAP write next to the results
- STIG Viewer CKL, including severity override
- ACAS or Nessus CSV with a Host column, Risk, Plugin ID, CVE, and CVSS
- An ESXi snapshot from `vmware/collect_esxi_posture.py`

A `.nessus` XML file is not read. Export CSV from the console first.

Same finding, three identifiers. A checklist row `RHEL-08-010550` / `V-230296` and an XCCDF result `SV-230296r858711_rule` become one clock. ACAS is findings-only: a plugin that disappears while the host is still in the later file is closed. A host that is missing from the later file is not.

## When a file does not read

The command stops. It prints the path and the reason, and it does not write a ledger.

That covers a broken XML file, a checklist with no findings, a CSV with no header, a CSV whose columns do not include Host, a blank host cell, a result value that is not Open / NotAFinding / Not_Applicable / Not_Reviewed / pass / fail, an empty directory, and a `.nessus` file. A file that failed is not treated as a host that passed.

Fix the export or re-export it, then rerun. The register will not guess a column or a status.

## Clocks and exceptions

`policy/default.json` is the ISSM's policy, not a guess baked into the code.

- CAT I 30 days, CAT II 90, CAT III 365
- STIG high / medium / low map to CAT I / II / III
- CVSS, for vulnerability exports only: 7.0 and above is CAT I, 4.0 and above is CAT II
- A regression restarts the clock
- An approved exception pauses it until the end date
- A pending exception does not
- The day after the end date, the finding is due

Classes on each open row:

| Class | Meaning |
| --- | --- |
| automate | Safe to hand to Ansible unattended, after a dry run |
| change-window | Restarts a service or reboots. One visit per host |
| gpo | Domain-joined. Fix the GPO, not the local policy |
| blocked | Closing it now would be a false pass |
| do-not-automate | A script would pass the scanner and break the mission, or violate a signed exception |

## Try a change without applying it

The register never logs into a host. The Ansible role is separate, and the only unattended tags are the ones marked `automate`.

Dry run on one host. This prints the diff and writes nothing, including the backup:

```bash
ansible-playbook -i ansible/inventory/lab.ini ansible/site.yml \
  --check --diff \
  --limit rhel-repo01.lab.local \
  --tags gpgcheck,localpkg,pwquality
```

`gpgcheck`, `localpkg`, and `pwquality` edit files. `ssh-root` and `audit` are `change-window`: the first restarts sshd, the second installs a package. Leave them off an unattended run.

Apply the same tags on one host when the diff looks right:

```bash
ansible-playbook -i ansible/inventory/lab.ini ansible/site.yml \
  --limit rhel-repo01.lab.local \
  --tags gpgcheck,localpkg,pwquality
```

Before those edits, the role copies `/etc/yum.repos.d/*.repo`, `/etc/dnf/dnf.conf`, `/etc/security/pwquality.conf`, and `/etc/ssh/sshd_config` to `/var/backups/findings-register/<timestamp>/` and writes that path to `latest-path.txt`. A dry run does not create this copy.

## Put the file changes back

```bash
ansible-playbook -i ansible/inventory/lab.ini ansible/revert.yml \
  --limit rhel-repo01.lab.local
```

That restores the saved files. It does not restart sshd. It does not remove the audit package. If a config file did not exist before the run, and the play created it, revert deletes that file.

If sshd was restarted and you need the running daemon to pick up the restored file, do that from the console after you have read the file:

```bash
ansible-playbook -i ansible/inventory/lab.ini ansible/revert.yml \
  --limit rhel-repo01.lab.local \
  --tags restart-sshd
```

On Windows, `windows/Invoke-BaselineAudit.ps1` with no switches only reports. `-Apply` saves the FS-SMB1 install state and then removes the feature. `-Revert` reinstalls it only if that saved state says it was installed. `-Apply` and `-Revert` together are refused. Neither switch writes a password policy. On a domain member that change is a GPO.

## When something breaks

- GPG checking stops a package install when the key was never imported. The finding goes green and `dnf` starts failing. Revert the repo files, or import the key, then install again.
- Restarting sshd drops the session you used to restart it. That tag stays in a change window, with someone at the console. Revert restores `sshd_config` and leaves the daemon alone until you restart it on purpose.
- Removing SMBv1 wants a reboot before the finding is really closed. `-Revert` puts the feature back from the saved state and warns about the reboot. It cannot undo a reboot that already happened.
- The domain controller time finding is left alone. ESXi syncs from the DC and the DC syncs from ESXi. A script that "fixes" one side makes the other worse.
- ESXi SSH stays up when an exception says it is break-glass. Stopping it would violate that signature.

## What else is in the repo

- `ansible/` — RHEL role, the dry-run play, and `revert.yml`. Read `ansible/generated/lab-plan.yml` before you choose tags.
- `windows/Invoke-BaselineAudit.ps1` — report by default. `-Apply` and `-Revert` only touch FS-SMB1.
- `vmware/collect_esxi_posture.py` — lockdown, SSH, NTP, and syslog. Snapshot mode needs no vCenter. `--govc` runs read-only `govc` commands and refuses to guess if SSH or NTP is missing from the service list.
- `docs/runbooks/` — the pages that exist. DHCP and vCenter are missing on purpose, and the handoff gate says so.
- `dist/evidence/` after `python3 -m findings demo` — POA&M CSV, per-host notes, drift, exceptions, and an attestation that names the source files.

Python 3.11 or newer. The register uses the standard library only. The review UI is a Next.js app in `web/` and reads `web/src/data/ledger.json`.
