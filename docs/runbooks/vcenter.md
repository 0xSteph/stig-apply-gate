# vCenter

Host: vcenter01.lab.local. One appliance manages esxi01 and the lab VMs. ESXi lockdown mode depends on it: with lockdown on, vCenter is how you reach the host.

## Check

- VAMI (port 5480) Time shows NTP, and the sources are not esxi01 or ad01. Today vCenter takes time from esxi01, which is in a loop with ad01. That row passes the scan and is still listed as a hollow pass until ESXi has two real sources.
- VAMI Syslog lists the forwarding target as Reachable, and the collector received a test event. The snapshot records the target, not whether it answers.
- Single Sign On lockout policy: three failed attempts, unlock time 0. Password policy: lifetime 90 days or less.
- vSphere Client session timeout is 15 minutes or less. It was left at the 120-minute default here.
- `python vmware/collect_esxi_posture.py --snapshot <vcenter snapshot>` reads every row. A row that says "was not read" is not a pass. Read it in the VAMI or the SSO pages and record it in the next snapshot.
- Before a change to a VM advanced setting, agree the cold start with the mission owner. The isolation settings do not take effect on a guest reboot.

## What not to do

- Do not point vCenter at ad01 to fix time. That moves it onto the other half of the same loop.
- Do not add a syslog target that nobody has confirmed is listening. That passes the check and loses the logs.
- Do not reboot vCenter in the same window as an ESXi change that depends on it. With lockdown on, the DCUI is the only other way in.
- Do not tighten the SSO lockout before you know who can unlock an account. With unlock time 0, a locked service account stays locked until an administrator acts.
