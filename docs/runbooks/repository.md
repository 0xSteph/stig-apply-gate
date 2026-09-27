# DNF repository

Host: rhel-repo01.lab.local. Every other RHEL host installs from here. If this repo will accept an unsigned package, the rest of the lab will too.

## Check

- `gpgcheck=1` on every file in `/etc/yum.repos.d`.
- `rpm -q gpg-pubkey` shows the lab key before you turn checks on. Otherwise the next patch window stops.
- `localpkg_gpgcheck=True` in `/etc/dnf/dnf.conf`.
- A package install from a second host succeeds after the change.

## What not to do

- Do not publish a package you built on a laptop straight into the repo directory. Sign it, then publish it.
- Do not restart sshd here as part of the GPG change. Root SSH is already closed on this host.
