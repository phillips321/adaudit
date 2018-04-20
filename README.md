# adaudit
PowerShell Script to perform a quick AD audit

If you have any decent powershell one lines missing please let me know. I'm trying to keep this script as a single file with no requirements on external tools (other than ntdsutil and cmd.exe)

Run directly on a DC using a DA. If you dont trust the code I suggest reading it first and you'll see it's all harmless! (But shouldn't you be doing that anyway with code you download off the net and then run as DA??)

Performs the following functions:
* Password Policy Findings --> Get-PasswordPolicy Get-UserPasswordNotChangedRecently
* Looking for accounts that dont expire --> Get-AccountPassDontExpire
* Looking for inactive/disabled accounts --> Get-InactiveAccounts Get-DisabledAccounts
* Looking for server 2003/XP machines connected to domain --> Get-OldBoxes
* AD Findings --> Get-MachineAccountQuota Get-SMB1Support
* Domain Trust Findings" ; Get-DomainTrusts
* GPO Findings --> Get-GPOtoHTML --> Get-GPOsPerOU
* Trying to find SysVOL xml files containg cpassword --> Get-SYSVOLXMLS
* Trying to save NTDS.dit--> Get-NTDSdit
