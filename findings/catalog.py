"""Remediation judgment for the sample controls.

The class is the decision, not a suggestion to run everything.
`automate` is safe to hand to Ansible on the next patch window.
`change-window` restarts a service or reboots.
`gpo` must be fixed in Group Policy, not on the local box.
`blocked` cannot be closed honestly until something else exists.
`do-not-automate` will pass a scanner and break the mission, or hide the real defect.
`manual` is made by a person in a console no playbook here reaches, such as vCenter.
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
    "VCSA-80-000158": {
        "class": "blocked",
        "summary": "Point vCenter at the same two time sources ESXi gets, once they exist.",
        "why": "vCenter takes time from esxi01, and esxi01 is in a loop with the domain controller. A server name in the NTP list passes the check without making the clock authoritative.",
        "verify": "VAMI Time shows NTP with sources that are not esxi01 or ad01, each listed as Reachable.",
        "avoid": "Do not swap esxi01 for ad01. That moves vCenter onto the other half of the same loop.",
    },
    "VCSA-80-000148": {
        "class": "blocked",
        "summary": "Do not add a syslog forwarding target until the collector is actually up.",
        "why": "An empty forwarding list is an honest failure. A target that does not answer passes the check and loses the logs.",
        "verify": "VAMI Syslog lists the collector as Reachable, and the collector received a test event.",
        "avoid": "Do not invent a target to turn the row green.",
    },
    "VCSA-80-000023": {
        "class": "manual",
        "summary": "Set the SSO lockout to three failed logins in vCenter.",
        "why": "The SSO lockout policy is set in the vSphere Client under Single Sign On, not on a host a playbook reaches. The next vcenter-posture snapshot is the proof.",
        "verify": "Lockout policy: maximum failed login attempts 3.",
        "avoid": "Know who can unlock an SSO account before you tighten it, and which service accounts log in with a password.",
    },
    "VCSA-80-000266": {
        "class": "manual",
        "summary": "Set the SSO unlock time to 0 so an administrator unlocks locked accounts.",
        "why": "The setting lives in the SSO lockout policy in vCenter, not on a host a playbook reaches. The next vcenter-posture snapshot is the proof.",
        "verify": "Lockout policy: unlock time 0 seconds.",
        "avoid": "With unlock time 0, a locked service account stays locked. Check the service accounts before a weekend.",
    },
    "VCSA-80-000079": {
        "class": "manual",
        "summary": "Set the SSO password lifetime to 90 days or less.",
        "why": "The SSO password policy is set in vCenter. It binds the next password change and does not expire current passwords at once.",
        "verify": "Password policy: maximum lifetime 90 days or less.",
        "avoid": "Do not shorten it on the day of a campaign. Service account passwords expire on the same clock.",
    },
    "VCSA-80-000089": {
        "class": "manual",
        "summary": "Set the vSphere Client session timeout to 15 minutes in vCenter.",
        "why": "The session timeout is vCenter client configuration, changed in the vSphere Client by someone with the right role. No playbook in this repo reaches it, and the next vcenter-posture snapshot is the proof.",
        "verify": "vSphere Client configuration: session timeout 15 minutes or less.",
        "avoid": "Do not shorten it in the middle of a console session someone else is using. They lose that session.",
    },
    "VMCH-80-000189": {
        "class": "manual",
        "summary": "Set isolation.tools.copy.disable to true on the VM in vCenter.",
        "why": "This is a VM advanced setting, changed in vCenter, not on the guest. The benchmark says it takes effect at the next cold start, not a guest reboot, and the next vm-posture snapshot is the proof.",
        "verify": "vm-posture snapshot shows isolation.tools.copy.disable true, or unset.",
        "avoid": "Do not power the mission VM off to apply it outside a window the mission owner agreed to.",
    },
    "VMCH-80-000191": {
        "class": "manual",
        "summary": "Set isolation.tools.dnd.disable to true on the VM in vCenter.",
        "why": "This is a VM advanced setting, changed in vCenter, not on the guest. The benchmark says it takes effect at the next cold start, not a guest reboot, and the next vm-posture snapshot is the proof.",
        "verify": "vm-posture snapshot shows isolation.tools.dnd.disable true, or unset.",
        "avoid": "Do not power the mission VM off to apply it outside a window the mission owner agreed to.",
    },
    "VMCH-80-000192": {
        "class": "manual",
        "summary": "Set isolation.tools.paste.disable to true on the VM in vCenter.",
        "why": "This is a VM advanced setting, changed in vCenter, not on the guest. The benchmark says it takes effect at the next cold start, not a guest reboot, and the next vm-posture snapshot is the proof.",
        "verify": "vm-posture snapshot shows isolation.tools.paste.disable true, or unset.",
        "avoid": "Do not power the mission VM off to apply it outside a window the mission owner agreed to.",
    },
    "VMCH-80-000193": {
        "class": "manual",
        "summary": "Set isolation.tools.diskShrink.disable to true on the VM in vCenter.",
        "why": "This is a VM advanced setting, changed in vCenter, not on the guest. The benchmark says it takes effect at the next cold start, not a guest reboot, and the next vm-posture snapshot is the proof.",
        "verify": "vm-posture snapshot shows isolation.tools.diskShrink.disable true, or unset.",
        "avoid": "Do not power the mission VM off to apply it outside a window the mission owner agreed to.",
    },
    "VMCH-80-000194": {
        "class": "manual",
        "summary": "Set isolation.tools.diskWiper.disable to true on the VM in vCenter.",
        "why": "This is a VM advanced setting, changed in vCenter, not on the guest. The benchmark says it takes effect at the next cold start, not a guest reboot, and the next vm-posture snapshot is the proof.",
        "verify": "vm-posture snapshot shows isolation.tools.diskWiper.disable true, or unset.",
        "avoid": "Do not power the mission VM off to apply it outside a window the mission owner agreed to.",
    },
    "VMCH-80-000195": {
        "class": "manual",
        "summary": "Set RemoteDisplay.maxConnections to 1 on the VM in vCenter.",
        "why": "This is a VM advanced setting, changed in vCenter, not on the guest. Unlike the isolation settings, unset is a finding here. It takes effect at the next cold start, and the next vm-posture snapshot is the proof.",
        "verify": "vm-posture snapshot shows RemoteDisplay.maxConnections 1.",
        "avoid": "With one console session, a second person who opens the console takes it from the first. Say so before someone is mid-change.",
    },
    "VMCH-80-000197": {
        "class": "manual",
        "summary": "Set isolation.device.connectable.disable to true on the VM in vCenter.",
        "why": "This is a VM advanced setting, changed in vCenter, not on the guest. The benchmark says it takes effect at the next cold start, not a guest reboot, and the next vm-posture snapshot is the proof.",
        "verify": "vm-posture snapshot shows isolation.device.connectable.disable true, or unset.",
        "avoid": "Do not power the mission VM off to apply it outside a window the mission owner agreed to. If the mission loads media from a virtual CD-ROM, connect it from vCenter afterwards, not from the guest.",
    },
    "VMCH-80-000198": {
        "class": "manual",
        "summary": "Set tools.guestlib.enableHostInfo to false on the VM in vCenter.",
        "why": "This is a VM advanced setting, changed in vCenter, not on the guest. The benchmark says it takes effect at the next cold start, not a guest reboot, and the next vm-posture snapshot is the proof.",
        "verify": "vm-posture snapshot shows tools.guestlib.enableHostInfo false, or unset.",
        "avoid": "A performance agent in the guest that reads host details stops reporting them. Ask the mission owner first.",
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
