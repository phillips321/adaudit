# adaudit
PowerShell Script to perform a quick AD audit
```
_____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
                 by phillips321
```

If you have any decent powershell one liners that could be used in the script please let me know. I'm trying to keep this script as a single file with no requirements on external tools (other than ntdsutil and cmd.exe)

Run directly on a DC using a DA. If you don't trust the code I suggest reading it first and you'll see it's all harmless! (But shouldn't you be doing that anyway with code you download off the net and then run as DA??)

## What this does
* Device Information
  * Get-HostDetails
* Domain Audit
  * Get-LastWUDate
  * Get-DCEval
  * Get-TimeSource
  * Get-PrivilegedGroupMembership
  * Get-MachineAccountQuota
  * Get-DefaultDomainControllersPolicy
  * Get-SMB1Support
  * Get-FunctionalLevel
  * Get-DCsNotOwnedByDA
  * Get-ReplicationType
  * Get-RecycleBinState
  * Get-CriticalServicesStatus
  * Get-RODC
* Domain Trust Audit
  * Get-DomainTrusts
* User Accounts Audit
  * Get-InactiveAccounts
  * Get-DisabledAccounts
  * Get-LockedAccounts
  * Get-AdminAccountChecks
  * Get-NULLSessions
  * Get-PrivilegedGroupAccounts
  * Get-ProtectedUsers
* Password Information Audit
  * Get-AccountPassDontExpire
  * Get-UserPasswordNotChangedRecently
  * Get-PasswordPolicy
  * Get-PasswordQuality
* Dumps NTDS.dit
  * Get-NTDSdit
* Computer Objects Audit
  * Get-OldBoxes
* GPO audit (and checking SYSVOL for passwords)
  * Get-GPOtoFile
  * Get-GPOsPerOU
  * Get-SYSVOLXMLS
  * Get-GPOEnum
* Check Generic Group AD Permissions
  * Get-OUPerms
* Check For Existence of LAPS in domain
  * Get-LAPSStatus
* Check For Existence of Authentication Polices and Silos
  * Get-AuthenticationPoliciesAndSilos
* Check for insecure DNS zones
  * Get-DNSZoneInsecure
* Check for newly created users and groups
  * Get-RecentChanges
* Check for ADCS vulnerabiltiies, ESC1,2,3,4 and 8. 
* Check for high value kerberoastable accounts 
* Check for ASREPRoastable accounts
* Check for dangerous ACL permissions on Users, Groups and Computers. 

## Runtime Args
The following switches can be used in combination
* -installdeps installs optionnal features (DSInternals)
* -hostdetails retrieves hostname and other useful audit info
* -domainaudit retrieves information about the AD such as functional level
* -trusts retrieves information about any doman trusts
* -accounts identifies account issues such as expired, disabled, etc...
* -passwordpolicy retrieves password policy information
* -ntds dumps the NTDS.dit file using ntdsutil
* -oldboxes identified outdated OSs like XP/2003 joined to the domain
* -gpo dumps the GPOs in XML and HTML for later analysis
* -ouperms checks generic OU permission issues
* -laps checks if LAPS is installed
* -authpolsilos checks for existence of authentication policies and silos
* -insecurednszone checks for insecure DNS zones
* -recentchanges checks for newly created users and groups (last 30 days)
* -adcs checks for ADCS vulnerabiltiies, ESC1,2,3,4 and 8.
* -acl checks for dangerous ACL permissions on Users, Groups and Computers. 
* -spn checks for high value kerberoastable accounts 
* -asrep checks for ASREPRoastable accounts
* -all runs all checks, e.g. AdAudit.ps1 -all
