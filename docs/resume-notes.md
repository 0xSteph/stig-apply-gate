# Resume notes

Working notes for later resume bullets. The lab is synthetic and unclassified. Do not describe it as a production enclave, a clearance, or a system you administered for a customer.

## What this is

Findings register for an integration lab that stands in for a small ground site: a domain controller (DNS and DHCP), WSUS, a RHEL 8 repository, one mission host, and vSphere. It reads the exports those shops already produce (OpenSCAP or SCC XCCDF, STIG Viewer checklists, ACAS or Nessus CSV, a read-only ESXi snapshot) and decides which open rows are safe to hand to Ansible.

It does not scan a host and it does not log into one. Clocks, exceptions, and the apply gate are computed from the files. There is no model call.

Figures, for the README and the register: `docs/figures/lab-site.svg` (plate 1, the six hosts) and `docs/figures/gate.svg` (plate 2, lab versus operations). On the site, the time marks between the domain controller and ESXi move. They are drawing plates, not a product screenshot.

## What to say it shows

- Maintained hardened-baseline judgment across Windows Server, RHEL, and VMware, including which fixes are a GPO, a change window, or a false pass.
- Built an apply gate that stops a playbook when a signed exception is in force, two hosts take time from each other, a disruptive change lands on a backup outside RPO or restore-test policy, a pass depends on another host that is still failing, a predecessor check is unmet, or one restart would land before the rest of that service's changes.
- Kept the lab record stable and rehearsed changes on a copy, so a test never rewrote the ledger or the gate file the play reads.
- Refused the same change on an operations host that the lab copy would allow. A maintenance window is the scheduled apply, with someone present and a rollback, after the lab has proved it.
- Wrote the evidence pack an ISSM would walk: POA&M, drift, exceptions, per-host notes, and a handoff that stays red until the site is actually ready to leave the people who built it.

## Interview walk, unchanged lab

Sample clock 27 Sep 2026. Handoff is not ready.

1. Repository GPG check on rhel-repo01, `RHEL-08-010370`, oldest CAT I. Action is probe. `gpgcheck=1` before the signing key is imported stops every install from that repo.
2. SMBv1 on wsus01, `WN22-00-000380`. Action is refuse. The backup is outside the 24-hour RPO and the restore test is outside 90 days. Do not uninstall a feature on a box you cannot restore.
3. Time loop. ad01 `WN22-DC-000060` and esxi01 `ESXI-80-000124` take time from each other. Fixing either side leaves the loop and can start failing Kerberos logons.
4. Mission host `RHEL-08-010550` is a bundle with the OpenSSH findings. One sshd restart, with someone at the console. Three restarts drops the only path to the box. For a space ground system, that host is the one you do not take down to make a scan green.

Then the handoff page: late CAT I, expired exception, audit regression with no engineer note, missed backup, stale restore test, no runbook for DHCP or vCenter.

## What the test window proves

Command: `python -m findings rehearse`

Output: `dist/window/report.md` only, unless `--publish` updates `web/src/data/window.json`.

| Case | What moves on the copy | Result |
| --- | --- | --- |
| wsus-backup | WSUS last backup 27 Sep 2026 02:00 UTC and restore test 1 Sep 2026 | Backup stop lifts. Action becomes window. Someone still has to be at the console for the reboot. |
| exception-lapsed | EX-014 expires 26 Sep 2026 | Signature stop lifts. Action stays refuse. Closing SSH from a playbook still removes break-glass. |
| signing-key | `rpm -q gpg-pubkey` marked met | Repository GPG rows become allow. Dry-run before a real run. |
| operations-hold | Signing key met, and rhel-repo01 marked production | Stays refuse. The lab twin of this change is allow. |

RPO alone does not lift the WSUS stop while the restore test is still stale. Both have to be inside policy.

The playbook asserts `findings_tier` is not `production` and the inventory host is in the lab DNS suffix before it copies a file.

## Draft bullets

- Built an offline findings register that turns SCAP, STIG Viewer, and ACAS exports into CAT clocks, exception state, and an Ansible apply gate for a Windows, RHEL, and vSphere lab.
- Encoded stops for signed exceptions, NTP loops between a domain controller and ESXi, hollow passes, backup RPO and restore tests, and bundled service restarts so a playbook cannot close a finding by breaking the host.
- Separated lab proof from operations: rehearsal runs on a copy of the records, and a production-tier host is refused until the same change has been proved in the lab.

## Do not claim

- That this ran in a classified environment, or that you hold a clearance because the project exists.
- That the tool scans, remediates a fleet, or replaces eMASS, ACAS, or SCC.
- That the sample findings are a DISA benchmark redistribution. Identifiers that include a vulnerability number are public STIG ids. Titles and results were written for this lab.
