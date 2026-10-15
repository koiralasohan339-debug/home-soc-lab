# Discovery: Multiple Recon Commands

**MITRE ATT&CK:** T1087 (Account Discovery), T1033 (System Owner/User Discovery), T1057 (Process Discovery)
**Data source:** Sysmon Event ID 1 (Process Creation)
**Log source:** WinEventLog:Microsoft-Windows-Sysmon/Operational

## Detection logic
Flags 3+ distinct discovery binaries (whoami, net, systeminfo, nltest, quser)
spawned from the same parent process in a 15-minute window — the pattern of an
attacker enumerating a freshly compromised host.

## SPL
[paste the query]

## Testing
Triggered with: whoami, net user, net group, systeminfo, ipconfig (screenshot below)
Validated the alert fired; tuned out <admin baseline> false positive.

## Limitations
- A patient attacker spacing commands >15 min apart evades the count threshold.
- Living-off-the-land via PowerShell cmdlets (Get-LocalUser) bypasses these binaries — separate detection needed.
