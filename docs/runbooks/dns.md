# DNS

DNS for Integration Lab is the Active Directory zone on ad01. There is no second resolver.

## Check

- `nslookup rhel-mission01.lab.local ad01.lab.local` answers with 10.8.1.21.
- The AD zone is AD-integrated. Do not create a second primary on WSUS.

## What not to do

- Do not point clients at a public resolver to "test." The lab names are not public, and a client that fails over will look healthy while directory logons are broken.
- Do not restart the DNS service as a first step. Restarting Netlogon and DNS together on the only DC drops logons.
