<#
phillips321.co.uk ADAudit.ps1
Changlog:
    v2.0 - Multiple Additions and knocked off lots of the todo list
    v1.9 - Fixed bug, that used Administrator account name instead of UID 500 and a bug with inactive accounts timespan
    v1.8 - Added check for last time 'Administrator' account logged on.
    v1.6 - Added Get-FunctionalLevel and krbtgt password last changed check
    v1.5 - Added Get-HostDetails to output simple info like username, hostname, etc...
    v1.4 - Added Get-WinVersion version to assist with some checks (SMBv1 currently)
    v1.3 - Added XML output for GPO (for offline processing using grouper https://github.com/l0ss/Grouper/blob/master/grouper.psm1)
    v1.2 - Added check for modules
    v1.1 - Fixed bug where SYSVOL research returns empty
    v1.0 - First release
ToDo:
  Trusts without domain filtering
  Inactive domain trusts
  Accounts with sid history matching the domain
  Schema Admins group not empty
  DCs with null session Enabled
  DCs not owned by Domain Admins: Get-ADComputer -server fruit.com -LDAPFilter "(&(objectCategory=computer)(|(primarygroupid=521)(primarygroupid=516)))" -properties name, ntsecuritydescriptor | select name,{$_.ntsecuritydescriptor.Owner}
#>
$versionnum = "v2.0"
function Write-Both(){#writes to console screen and output file
    Write-Host "$args"; Add-Content -Path "$outputdir\consolelog.txt" -Value "$args"}
function Get-MachineAccountQuota{#get number of machines a user can add to a domain
    $MachineAccountQuota = (Get-ADDomain | select -exp DistinguishedName | get-adobject -prop 'ms-DS-MachineAccountQuota' | select -exp ms-DS-MachineAccountQuota)
    if ($MachineAccountQuota -gt 0){ Write-Both "    [!] Domain users can add $MachineAccountQuota devices to the domain!" }
}
function Get-PasswordPolicy{
    if (!(Get-ADDefaultDomainPasswordPolicy).PasswordComplexity) { Write-Both "    [!] Password Complexity not enabled" }
    if ((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold -lt 5) {Write-Both "    [!] Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold)" }
    if ((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength -lt 14) {Write-Both "    [!] Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)" }
    if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled) {Write-Both "    [!] Reversible encryption is enabled" }
    if ((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge -eq "00:00:00") {Write-Both "    [!] Passwords do not expire" }
    if ((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount -lt 12) {Write-Both "    [!] Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)" }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).NoLmHash -eq 0) {Write-Both "    [!] LM Hashes are stored!" }
}
function Get-DomainTrusts{#lists domain trusts if they are bad
    ForEach ($trust in (Get-ADObject -Filter {objectClass -eq "trustedDomain"} -Properties TrustPartner,TrustDirection,trustType)){
        if ($trust.TrustDirection -eq 2){Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain!" }
        if ($trust.TrustDirection -eq 3){Write-Both "    [!] Bidirectional trust with domain $($trust.Name)!" }
    }
}
function Get-WinVersion(){
    $WinVersion = [single]([string][environment]::OSVersion.Version.Major + "." + [string][environment]::OSVersion.Version.Minor)
    return [single]$WinVersion
}
function Get-SMB1Support{#check if server supports SMBv1
    if ([single](Get-WinVersion) -le [single]6.1){# NT6.1 or less detected so checking reg key
        if (!(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters).SMB1 -eq 0){Write-Both "    [!] SMBv1 is not disabled"}
    }
    elseif ([single](Get-WinVersion) -ge [single]6.2){#NT6.2 or greater detected so using powershell function
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol){Write-Both "    [!] SMBv1 is enabled!"}
    }
}
function Get-UserPasswordNotChangedRecently{#Reports users that haven't changed passwords in more than 90 days
    $count = 0
    $DaysAgo=(Get-Date).AddDays(-90)
    ForEach ($account in (get-aduser -filter {PwdLastSet -lt $DaysAgo} -properties passwordlastset)){
        if ($account.PasswordLastSet){$datelastchanged = $account.PasswordLastSet} else {$datelastchanged = "Never"}
        Add-Content -Path "$outputdir\accounts_with_old_passwords.txt" -Value "User $($account.SamAccountName) has not changed thier password since $datelastchanged"
        $count++
    }
    if ($count -gt 0){Write-Both "    [!] $count accounts with passwords older than 90days, see accounts_with_old_passwords.txt"}
    $krbtgtPasswordDate = (get-aduser -Filter {samaccountname -eq "krbtgt"} -Properties PasswordLastSet).PasswordLastSet 
    if ($krbtgtPasswordDate -lt (Get-Date).AddDays(-180)){Write-Both "    [!] krbtgt password not changed since $krbtgtPasswordDate!"}
}
function Get-GPOtoFile{#oututs complete GPO report
    if (Test-Path "$outputdir\GPOReport.html") { Remove-Item "$outputdir\GPOReport.html" -Recurse; }
    Get-GPOReport -All -ReportType HTML -Path "$outputdir\GPOReport.html"
    Write-Both "    [+] GPO Report saved to GPOReport.html"
    if (Test-Path "$outputdir\GPOReport.xml") { Remove-Item "$outputdir\GPOReport.xml" -Recurse; }
    Get-GPOReport -All -ReportType XML -Path "$outputdir\GPOReport.xml"
    Write-Both "    [+] GPO Report saved to GPOReport.xml, now run Grouper offline using the following command"
    Write-Both "    [+]     PS>Import-Module Grouper.psm1 ; Invoke-AuditGPOReport -Path C:\GPOReport.xml -Level 3"
}
function Get-GPOsPerOU{#Lists all OUs and which GPOs apply to them
    foreach ($ouobject in Get-ADOrganizationalUnit -Filter *){
        $combinedgpos = ($(((Get-GPInheritance -Target $ouobject).InheritedGpoLinks) | select DisplayName) | ForEach-Object { $_.DisplayName }) -join ','
        Add-Content -Path "$outputdir\ous_inheritedGPOs.txt" -Value "$($ouobject.Name) Inherits these GPOs: $combinedgpos"
   }
   Write-Both "    [+] Inhertied GPOs saved to ous_inheritedGPOs.txt"
}
function Get-NTDSdit{#dumps NTDS.dit, SYSTEM and SAM for password cracking
    if (Test-Path "$outputdir\ntds.dit") { Remove-Item "$outputdir\ntds.dit" -Recurse; }
    $outputdirntds='\"' + $outputdir + '\ntds.dit\"'
    $command = "ntdsutil `"ac in ntds`" `"ifm`" `"cr fu $outputdirntds `" q q"
    $hide = cmd.exe /c "$command" 2>&1
    Write-Both "    [+] NTDS.dit, SYSTEM & SAM saved to output folder"
    Write-Both "    [+] Use secretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL -outputfile customer"
}
function Get-SYSVOLXMLS{#finds XML files in SYSVOL (thanks --> https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
    $XMLFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'
    if ($XMLFiles){
        foreach ($File in $XMLFiles) {
            $Filename = Split-Path $File -Leaf
            $Distinguishedname = (split-path (split-path (split-path( split-path (split-path $File -Parent) -parent ) -parent ) -parent) -Leaf).Substring(1).TrimEnd('}')
            [xml]$Xml = Get-Content ($File)
            $count=0
            if ($Xml.innerxml -like "*cpassword*"){
                if (!(Test-Path "$outputdir\sysvol")) { New-Item -ItemType directory -Path "$outputdir\sysvol" | out-null }
                Write-Both "    [!] cpassword found in file, copying to output folder"
                Write-Both "        $File"
                copy-item -Path $File -Destination $outputdir\sysvol\$Distinguishedname.$Filename
                $count++
            }
        }
    }
    if ($count -eq 0){Write-Both "    ...cpassword not found in the $($XMLFiles.count) XML files found."}
}
function Get-InactiveAccounts{#lists accounts not used in past 180 days plus some checks for admin accounts
    $count = 0
    ForEach ($account in (Search-ADaccount -AccountInactive -Timespan 180 -UsersOnly)){
        if ($account.Enabled){
            if ($account.LastLogonDate){$userlastused = $account.LastLogonDate} else {$userlastused = "Never"}
            Add-Content -Path "$outputdir\accounts_inactive.txt" -Value "User $($account.SamAccountName) has not logged on since $userlastused"
            $count++
        }
    }
    if ($count -gt 0){Write-Both "    [!] $count inactive user accounts(180days), see accounts_inactive.txt"}
}
function Get-AdminAccountChecks{# checks if Administrator account has been renamed, replaced and is no longer used.
    $AdministratorSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value)+"-500"
    $AdministratorSAMAccountName = (Get-ADUser -Filter {SID -eq $AdministratorSID} -properties SamAccountName).SamAccountName
    if ($AdministratorSAMAccountName -eq "Administrator"){Write-Both "    [!] Local Administrator account (UID500) has not been renamed"}
    elseif (!(Get-ADUser -Filter {samaccountname -eq "Administrator"})){Write-Both "    [!] Local Admini account renamed to $AdministratorSAMAccountName, but a dummy account not made in it's place!"}
    $AdministratorLastLogonDate =  (Get-ADUser -Filter {SID -eq $AdministratorSID}  -properties lastlogondate).lastlogondate 
    if ($AdministratorLastLogonDate -gt (Get-Date).AddDays(-180)){Write-Both "    [!] UID500 (LocalAdmini) account is still used, last used $AdministratorLastLogonDate!"}
}
function Get-DisabledAccounts{#lists disabled accounts
    $count = 0
    ForEach ($account in (Search-ADaccount -AccountInactive -Timespan "180" -UsersOnly)){
        if (!($account.Enabled)){
            if ($account.LastLogonDate){$userlastused = $account.LastLogonDate} else {$userlastused = "Never"}
            Add-Content -Path "$outputdir\accounts_disabled.txt" -Value "Accont $($account.SamAccountName) is disabled"
            $count++
        }
    }
    if ($count -gt 0){Write-Both "    [!] $count disabled user accounts, see accounts_disabled.txt"}
}
function Get-AccountPassDontExpire{#lists accounts who's passwords dont expire
    $count = 0
    ForEach ($account in (Search-ADAccount -PasswordNeverExpires -UsersOnly)){
        Add-Content -Path "$outputdir\accounts_passdontexpire.txt" -Value "$($account.SamAccountName), $($account.UserPrincipalName)"
        $count++
    }
    if ($count -gt 0){Write-Both "    [!] There are $count accounts that don't expire, see accounts_passdontexpire.txt"}
}
function Get-OldBoxes{#lists server 2003/XP machines
    $count = 0
    ForEach ($machine in (Get-ADComputer -Filter {OperatingSystem -Like "*2003*" -or OperatingSystem -Like "*XP*"} -Property *)){
        Add-Content -Path "$outputdir\machines_old.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address)"
        $count++
    }
    if ($count -gt 0){Write-Both "    [!] We found $count machines running server 2003/XP! see machines_old.txt"}
}
function Get-HostDetails{#gets basic information about the host
    Write-Both "    [+] Device Name:  $env:ComputerName"
    Write-Both "    [+] Domain Name:  $env:UserDomain"
    Write-Both "    [+] User Name:  $env:UserName"
    Write-Both "    [+] NT Version:  $(Get-WinVersion)"
    $IPAddresses = [net.dns]::GetHostAddresses("")|Select -Expa IP*
    ForEach ($ip in $IPAddresses){Write-Both "    [+] IP Address:  $ip"}
}
function Get-FunctionalLevel{# Gets the functional level for domain and forest
    $DomainLevel = (Get-ADDomain).domainMode
    if ($DomainLevel -eq "Windows2000Domain" -and [single](Get-WinVersion) -gt 5.0){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"}
    if ($DomainLevel -eq "Windows2003InterimDomain" -and [single](Get-WinVersion) -gt 5.1){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"}
    if ($DomainLevel -eq "Windows2003Domain" -and [single](Get-WinVersion) -gt 5.2){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"}
    if ($DomainLevel -eq "Windows2008Domain" -and [single](Get-WinVersion) -gt 6.0){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"}
    if ($DomainLevel -eq "Windows2008R2Domain" -and [single](Get-WinVersion) -gt 6.1){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"}
    if ($DomainLevel -eq "Windows2012Domain" -and [single](Get-WinVersion) -gt 6.2){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"}
    if ($DomainLevel -eq "Windows2012R2Domain" -and [single](Get-WinVersion) -gt 6.3){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"}
    $ForestLevel = (Get-ADForest).ForestMode
    if ($ForestLevel -eq "Windows2000Forest" -and [single](Get-WinVersion) -gt 5.0){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2003InterimForest" -and [single](Get-WinVersion) -gt 5.1){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2003Forest" -and [single](Get-WinVersion) -gt 5.2){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2008Forest" -and [single](Get-WinVersion) -gt 6.0){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2008R2Forest" -and [single](Get-WinVersion) -gt 6.1){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2012Forest" -and [single](Get-WinVersion) -gt 6.2){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2012R2Forest" -and [single](Get-WinVersion) -gt 6.3){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
}
$outputdir = (Get-Item -Path ".\").FullName + "\" + $env:computername
$starttime = get-date
if (!(Test-Path "$outputdir")) { New-Item -ItemType directory -Path $outputdir | out-null }
Write-Both " _____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
$versionnum                  by phillips321
"
Write-Both "[*] Script start time $starttime"
if (Get-Module -ListAvailable -Name ActiveDirectory){import-module ActiveDirectory} else {write-host "[!] ActiveDirectory module not installed, exiting..." ; exit}
if (Get-Module -ListAvailable -Name ServerManager){import-module ServerManager} else {write-host "[!] ServerManager module not installed, exiting..." ; exit}
if (Get-Module -ListAvailable -Name GroupPolicy){import-module GroupPolicy} else {write-host "[!] GroupPolicy module not installed, exiting..." ; exit}
write-host "[+] Outputting to $outputdir"
Write-Both "[*] Device Information" ; Get-HostDetails
Write-Both "[*] ActiveDirectory Audit" ; Get-MachineAccountQuota ; Get-SMB1Support; Get-FunctionalLevel 
Write-Both "[*] Domain Trust Audit" ; Get-DomainTrusts
Write-Both "[*] Accounts Audit" ; Get-InactiveAccounts ; Get-DisabledAccounts ; Get-AdminAccountChecks
Write-Both "[*] Password Information Audit" ; Get-AccountPassDontExpire ; Get-PasswordPolicy ; Get-UserPasswordNotChangedRecently
Write-Both "[*] Trying to save NTDS.dit, please wait..."; Get-NTDSdit
Write-Both "[*] Computer Objects Audit" ; Get-OldBoxes
Write-Both "[*] GPO audit (and checking SYSVOL for passwords)"  ; Get-GPOtoFile ; Get-GPOsPerOU ; Get-SYSVOLXMLS
$endtime = get-date
Write-Both "[*] Script end time $endtime"
