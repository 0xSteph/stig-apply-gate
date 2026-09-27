# WSUS

Host: wsus01.lab.local. It is a member server, not a domain controller.

## Check

- Last synchronization succeeded, and the content volume has free space. The missed RPO in the ledger was a full content volume, not a mystery agent failure.
- `Get-WindowsFeature FS-SMB1` is not Installed. The exception for the payload dropbox ended on 1 Sep.
- Clients in the lab group received the last approved patch set. Approve in the lab group before you approve anything that reaches ad01.

## What not to do

- Do not uninstall SMBv1 and reboot while the backup is failing.
- Do not set the password policy locally. Link the domain GPO to the member server OU and run `gpupdate`, then `gpresult`.
