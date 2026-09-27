# Active Directory

Host: ad01.lab.local. This lab has one domain controller. Treat it that way.

## What is healthy

- `dcdiag /v` finishes without replication errors. With one DC, replication errors mean something else is wrong, not a missing partner.
- `repadmin /showrepl` is quiet.
- System state backup from last night exists. The ledger is the check, not a guess.

## What not to do

- Do not reboot ad01 in the same window as WSUS.
- Do not tighten Kerberos clock tolerance while ESXi and this DC are each other's time source. Fix ESXi NTP first, then re-check `w32tm /query /status /verbose`.
- Do not demote it to "make the STIG easier."

## If it is down

Restore system state to an isolated VM and confirm SYSVOL before you put it back on the lab network. The last successful isolated restore is recorded on the backup page.
