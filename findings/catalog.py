"""Remediation judgment for the sample controls.

The class is the decision, not a suggestion to run everything.
`automate` is safe to hand to Ansible on the next patch window.
`change-window` restarts a service or reboots.
`gpo` must be fixed in Group Policy, not on the local box.
`blocked` cannot be closed honestly until something else exists.
`do-not-automate` will pass a scanner and break the mission, or hide the real defect.
"""

from __future__ import annotations

CATALOG: dict[str, dict] = {
    "RHEL-08-010370": {
        "class": "automate",
        "summary": "Set gpgcheck=1 on the lab repo files after the signing key is imported.",
        "why": "Unsigned packages from the lab repo are a CAT I on the host that publishes them. The fix is a one-line repo change, and it fails closed: dnf will refuse packages until the key is present, which is what you want.",
        "verify": "grep -H '^gpgcheck' /etc/yum.repos.d/*.repo && rpm -q gpg-pubkey",
        "avoid": "Do not flip the bit and walk away. If the key was never imported, the next patch window stops cold.",
    },
    "RHEL-08-010371": {
        "class": "automate",
        "summary": "Set localpkg_gpgcheck=True in /etc/dnf/dnf.conf.",
        "why": "This stops a locally copied RPM from installing without a signature. It does not restart services.",
        "verify": "grep ^localpkg_gpgcheck /etc/dnf/dnf.conf",
        "avoid": "Kickstart images that drop unsigned local RPMs during build will start failing. Fix the image, do not disable the check.",
    },
    "RHEL-08-010550": {
        "class": "change-window",
        "summary": "Set PermitRootLogin no and restart sshd with someone at the console.",
        "why": "The effective check is `sshd -T | grep permitrootlogin`, not a grep of the file. A restart drops every session on that daemon.",
        "verify": "sshd -T | grep -i permitrootlogin",
        "avoid": "Do not restart sshd on the mission host from the only remote session you have.",
    },
    "RHEL-08-020230": {
        "class": "automate",
        "summary": "Set minlen = 15 in /etc/security/pwquality.conf.",
        "why": "This binds the next password change. It does not expire current passwords.",
        "verify": "grep ^minlen /etc/security/pwquality.conf",
        "avoid": "Existing local accounts stay as they are until the password is changed. Say that in the POA&M comment so an assessor does not call it a false close.",
    },
    "RHEL-08-030180": {
        "class": "change-window",
        "summary": "Install the audit package and confirm auditd is running before the next scan.",
        "why": "The September scan regressed. The package was present in August. Treat it as a patch-window casualty, not a new design question.",
        "verify": "rpm -q audit && systemctl is-active auditd",
        "avoid": "Loading a full audit ruleset on a mission box can stall the host. Install the package first, add rules in the same window, and watch the bench.",
    },
    "WN22-00-000380": {
        "class": "change-window",
        "summary": "Uninstall the FS-SMB1 feature. Plan the reboot.",
        "why": "SMBv1 on the WSUS server is how a lab share becomes the easy pivot. The STIG severity is medium. The expired exception is what made it late.",
        "verify": "Get-WindowsFeature -Name FS-SMB1",
        "avoid": "Do not uninstall SMBv1 on a domain controller in the same change. This finding is the WSUS host.",
    },
    "WN22-AC-000070": {
        "class": "gpo",
        "severity_verified": False,
        "summary": "Link the password-policy GPO to the member server OU. Do not secedit the box.",
        "why": "wsus01 is domain-joined. A local policy edit looks fixed until the next gpupdate, or it fights the domain policy. The domain controller OU already has the setting.",
        "verify": "gpresult /h report.html and confirm the winning GPO for MinimumPasswordLength.",
        "avoid": "A script that writes the local security policy will not survive domain join, and it will confuse the next person who reads secedit.",
    },
    "WN22-DC-000060": {
        "class": "do-not-automate",
        "severity_verified": False,
        "summary": "Fix the NTP hierarchy before touching Kerberos clock tolerance.",
        "why": "The domain controller is taking time from ESXi, and ESXi is taking time from the domain controller. Tightening the five-minute tolerance on the DC will start failing Kerberos logons while the loop is still there.",
        "verify": "w32tm /query /status /verbose",
        "avoid": "Do not 'remediate' this with a policy script. The failing ESXi NTP finding is the actual work.",
    },
    "ESXI-80-000008": {
        "class": "do-not-automate",
        "summary": "Leave lockdown enabled. Strict mode is a separate decision.",
        "why": "Normal lockdown is already on. Strict lockdown disables the DCUI. If vCenter is unreachable during a campaign, strict mode strands the host.",
        "verify": "Lockdown mode reads Normal or Strict.",
        "avoid": "Do not flip a passing host to Strict to 'be safer' without a console plan.",
    },
    "ESXI-80-000193": {
        "class": "do-not-automate",
        "summary": "Leave SSH as the approved break-glass path until the exception expires.",
        "why": "An approved exception is not a failure you quietly close. Stopping SSH from a playbook would violate the exception and remove the path the change record depends on.",
        "verify": "SSH running, source limited to the jump host, exception still inside its end date.",
        "avoid": "Automation that stops SSH because the STIG says so will fight the ISSO's signature.",
    },
    "ESXI-80-000124": {
        "class": "change-window",
        "summary": "Point ESXi at two time sources that do not sync from this host, then fix the DC.",
        "why": "Mission timestamps and Kerberos both assume this clock is real. The current peer is the domain controller that trusts this host.",
        "verify": "NTP service running, at least one source that is not ad01, offset stable.",
        "avoid": "Adding ad01 as the only NTP server makes the STIG check look closer to passing and keeps the loop.",
    },
    "ESXI-80-000114": {
        "class": "blocked",
        "summary": "Do not set a logHost until the collector is actually up.",
        "why": "An empty syslog target is an honest failure. Pointing it at a hostname that does not answer turns it into a false pass and you lose the logs.",
        "verify": "Syslog.global.logHost is a collector that received a test event.",
        "avoid": "A one-line advanced setting is not remediation if nothing is listening.",
    },
    "CVE-2024-6387": {
        "class": "change-window",
        "summary": "Update OpenSSH from the lab repo in the same window as the SSH STIG items.",
        "why": "This is the unauthenticated sshd signal-handler race. It shares a reboot-free but session-killing restart with PermitRootLogin.",
        "verify": "rpm -q openssh-server and confirm the package is newer than the vulnerable build.",
        "avoid": "Do not restart sshd twice. Land the package, the root-login setting, and the audit package, then restart once.",
    },
    "CVE-2023-48795": {
        "class": "change-window",
        "summary": "Take the OpenSSH update that includes the strict key-exchange countermeasure.",
        "why": "Terrapin is a protocol downgrade. It closes with the same package update as CVE-2024-6387 on this host.",
        "verify": "ssh -Q kex includes the strict KEX algorithms after the update.",
        "avoid": "Disabling ChaCha20 by hand to silence the plugin is a local workaround, not the fix, and it surprises the next scan.",
    },
}


def lookup(control: str) -> dict:
    entry = CATALOG.get(control)
    if entry:
        return entry
    return {
        "class": "manual",
        "summary": "No safe automated fix is recorded for this control.",
        "why": "This register does not invent a remediation. Read the current STIG, decide if it is safe, and record the decision.",
        "verify": "Re-scan the single rule after the change.",
        "avoid": "Do not apply a whole-benchmark playbook because one row was open.",
    }
