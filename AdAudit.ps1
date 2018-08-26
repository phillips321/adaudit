<#
phillips321.co.uk ADAudit.ps1
Changelog:
    v3.2 - Added seach for DCs not owned by Domain Admins group
    v3.1 - Added progress to functions that have count
        - added check for transitive trusts
    v3.0 - Added ability to choose functions before runtime
        - cleaned up get-ouperms output
    v2.5 - Bug fixes to version check for 2012R2 or greater specific checks
    v2.4 - Forked project. Added Get-OUPerms. Get-LAPSStatus, Get-AdminSDHolders, Get-ProtectedUsers and Get-AuthenticationPoliciesAndSilos functions. Also added FineGrainedPasswordPolicies to Get-PasswordPolicy and changed order slightly
    v2.3 - Added more useful user output to .txt files (Cheers DK)
    v2.2 - Minor typo fix
    v2.1 - Added check for null sessions
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
  Need to check what computers have LAPS assigned using: see adsecurity.org/?p=3164 objects ms-Mcs-AdmPwd or AdmPwdExpirationTime 
    Get-ADComputer -Filter {ms-mcs-admpwd -like '<not set>'} -Properties * 
  Inactive domain trusts
  Accounts with sid history matching the domain
  Schema Admins group not empty
  DCs with null session Enabled
#>
[cmdletbinding()]
param (
  [switch]$hostdetails = $false,
  [switch]$domainaudit = $false,
  [switch]$trusts = $false,
  [switch]$accounts = $false,
  [switch]$passwordpolicy = $false,
  [switch]$ntds = $false,
  [switch]$oldboxes = $false,
  [switch]$gpo = $false,
  [switch]$ouperms = $false,
  [switch]$laps = $false,
  [switch]$authpolsilos = $false,
  [switch]$all = $false
)
$versionnum = "v3.2"
function Write-Both(){#writes to console screen and output file
    Write-Host "$args"; Add-Content -Path "$outputdir\consolelog.txt" -Value "$args"}

function Get-OUPerms{#Check for non-standard perms for authenticated users, domain users, users and everyone groups
    $count = 0
    $progresscount = 0
    $objects = (Get-ADObject -Filter *)
    $totalcount = $objects.count
    foreach ($object in $objects) {
        $progresscount++
        Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount*100)
        $output = (Get-Acl AD:$object).Access | where-object {($_.IdentityReference -eq 'NT Authority\Authenticated Users') -or ($_.IdentityReference -eq 'Everyone') -or ($_.IdentityReference -like '*\Domain Users') -or ($_.IdentityReference -eq 'BUILTIN\Users')} | Where-Object {($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.AccessControlType -ne 'Deny')}
		if ($output -ne $null) {$count++ ; Add-Content -Path "$outputdir\ou_permissions.txt" -Value  "OU: $object.DistinguishedName"; Add-Content -Path "$outputdir\ou_permissions.txt" -Value "[!] Rights: $($output.IdentityReference) $($output.ActiveDirectoryRights) $($output.AccessControlType)"}
    }
    if ($count -gt 0){Write-Both "    [!] Issue identified, see $outputdir\ou_permissions.txt"}
}

function Get-LAPSStatus{#Check for presence of LAPS in domain
        try{
        Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$((Get-ADDomain).DistinguishedName)" -ErrorAction Stop | Out-Null
        Write-Both "    [!] LAPS Installed in domain"
	    #TODO: Need to check what computers have LAPS assigned using: Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd
    }
    catch{
        Write-Both "    [!] LAPS Not Installed in domain"
    }
}

function Get-AdminSDHolders{#lists users and groups with AdminSDHolder set
    $count = 0
    $usersdaccounts = Get-ADUser -LDAPFilter "(admincount=1)"
    $totalcount = $usersdaccounts.count
    ForEach ($account in $usersdaccounts){
        Write-Progress -Activity "Searching for users who are SD holders..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        Add-Content -Path "$outputdir\accounts_userAdminSDHolder.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    if ($count -gt 0){Write-Both "    [!] There are $count accounts with AdminSDHolder set, see accounts_useradminsdholder.txt"}

    $count = 0
    $groupsdaccounts = Get-ADGroup -LDAPFilter "(admincount=1)"
    $totalcount = $groupsdaccounts.count
    ForEach ($account in $groupsdaccounts){
        Write-Progress -Activity "Searching for groups who are SD holders..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        Add-Content -Path "$outputdir\accounts_groupAdminSDHolder.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    if ($count -gt 0){Write-Both "    [!] There are $count groups with AdminSDHolder set, see accounts_groupsadminsdholder.txt"}
}

function Get-ProtectedUsers{#lists users in "Protected Users" group (2012R2 and above)
    if ([single](Get-WinVersion) -ge [single]6.3){#NT6.3 or greater detected so running this script
        $count = 0
        $protectedaccounts = (Get-ADGroup "Protected Users" -Properties members).Members
        $totalcount = $protectedaccounts.count
        ForEach ($members in $protectedaccounts){
            Write-Progress -Activity "Searching for ptoected users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
            $account = Get-ADObject $members -Properties samaccountname
            Add-Content -Path "$outputdir\accounts_protectedusers.txt" -Value "$($account.SamAccountName) ($($account.Name))"
            $count++
        }
        if ($count -gt 0){Write-Both "    [!] There are $count accounts in the 'Protected Users' group, see accounts_protectedusers.txt"}
    }
}
function Get-AuthenticationPoliciesAndSilos {#lists any authentication policies and silos (2012R2 and above)
    if ([single](Get-WinVersion) -ge [single]6.3){#NT6.2 or greater detected so running this script
        $count = 0
        foreach ($policy in Get-ADAuthenticationPolicy -Filter *) {Write-both "    [!] Found $policy Authentication Policy" ; $count++}
        if ($count -lt 1){Write-Both "    [!] There were no AD Authentication Policies found in the domain"}
        $count = 0
        foreach ($policysilo in Get-ADAuthenticationPolicySilo -Filter *) {Write-both "    [!] Found $policysilo Authentication Policy Silo" ; $count++}
        if ($count -lt 1){Write-Both "    [!] There were no AD Authentication Policy Silos found in the domain"}
    }
}

function Get-MachineAccountQuota{#get number of machines a user can add to a domain
    $MachineAccountQuota = (Get-ADDomain | select -exp DistinguishedName | get-adobject -prop 'ms-DS-MachineAccountQuota' | select -exp ms-DS-MachineAccountQuota)
    if ($MachineAccountQuota -gt 0){ Write-Both "    [!] Domain users can add $MachineAccountQuota devices to the domain!" }
}
function Get-PasswordPolicy{
	Write-Both 	"    [+] Checking default password policy"
    if (!(Get-ADDefaultDomainPasswordPolicy).PasswordComplexity) { Write-Both "    [!] Password Complexity not enabled" }
    if ((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold -lt 5) {Write-Both "    [!] Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold)" }
    if ((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength -lt 14) {Write-Both "    [!] Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)" }
    if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled) {Write-Both "    [!] Reversible encryption is enabled" }
    if ((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge -eq "00:00:00") {Write-Both "    [!] Passwords do not expire" }
    if ((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount -lt 12) {Write-Both "    [!] Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)" }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).NoLmHash -eq 0) {Write-Both "    [!] LM Hashes are stored!" }
	Write-Both 	"    [-] Finished checking default password policy"

	Write-Both 	"    [+] Checking fine-grained password policies if they exist"
	#foreach ($finegrainedpolicy in Get-ADFineGrainedPasswordPolicy -Filter *) { Write-Both "    [!] Policy: $finegrainedpolicy"; Write-Both "    [!] Applies to: ($($finegrainedpolicy).AppliesTo)"
	foreach ($finegrainedpolicy in Get-ADFineGrainedPasswordPolicy -Filter *) {$finegrainedpolicyappliesto=$finegrainedpolicy.AppliesTo; Write-Both "    [!] Policy: $finegrainedpolicy"; Write-Both "    [!] AppliesTo: $($finegrainedpolicyappliesto)"
	if (!($finegrainedpolicy).PasswordComplexity) { Write-Both "    [!] Password Complexity not enabled" }
    if (($finegrainedpolicy).LockoutThreshold -lt 5) {Write-Both "    [!] Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold)" }
    if (($finegrainedpolicy).MinPasswordLength -lt 14) {Write-Both "    [!] Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)" }
    if (($finegrainedpolicy).ReversibleEncryptionEnabled) {Write-Both "    [!] Reversible encryption is enabled" }
    if (($finegrainedpolicy).MaxPasswordAge -eq "00:00:00") {Write-Both "    [!] Passwords do not expire" }
    if (($finegrainedpolicy).PasswordHistoryCount -lt 12) {Write-Both "    [!] Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)" } }
	Write-Both 	"    [-] Finished checking fine-grained password policy"
}

function Get-NULLSessions{
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymous -eq 0) {Write-Both "    [!] RestrictAnonymous is set to 0!" }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymousSam -eq 0) {Write-Both "    [!] RestrictAnonymousSam is set to 0!" }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).everyoneincludesanonymous -eq 1) {Write-Both "    [!] EveryoneIncludesAnonymous is set to 1!" }
}
function Get-DomainTrusts{#lists domain trusts if they are bad
    ForEach ($trust in (Get-ADObject -Filter {objectClass -eq "trustedDomain"} -Properties TrustPartner,TrustDirection,trustType,trustAttributes)){
        if ($trust.TrustDirection -eq 2){
            if ($trust.TrustAttributes -ne 1){ # 1 means trust is non-transitive so we chack for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"}
            else {Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain!"}
        }
        if ($trust.TrustDirection -eq 3){
            if ($trust.TrustAttributes -ne 1){ # 1 means trust is non-transitive so we chack for anything but that
                Write-Both "    [!] Bidirectional trust with domain $($trust.Name) and it is Transitive!" }
            else {Write-Both "    [!] Bidirectional trust with domain $($trust.Name)!"}
        }
    }
}
function Get-WinVersion{
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
    $accountsoldpasswords = get-aduser -filter {PwdLastSet -lt $DaysAgo} -properties passwordlastset
    $totalcount= $accountsoldpasswords.count
    ForEach ($account in $accountsoldpasswords){
        Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        if ($account.PasswordLastSet){$datelastchanged = $account.PasswordLastSet} else {$datelastchanged = "Never"}
        Add-Content -Path "$outputdir\accounts_with_old_passwords.txt" -Value "User $($account.SamAccountName) ($($account.Name)) has not changed thier password since $datelastchanged"
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
    $count = 0
    $ousgpos = Get-ADOrganizationalUnit -Filter *
    $totalcount = $ousgpos.count
    foreach ($ouobject in $ousgpos){
        Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Currently identifed $count OUs" -PercentComplete ($count / $totalcount*100)
        $combinedgpos = ($(((Get-GPInheritance -Target $ouobject).InheritedGpoLinks) | select DisplayName) | ForEach-Object { $_.DisplayName }) -join ','
        Add-Content -Path "$outputdir\ous_inheritedGPOs.txt" -Value "$($ouobject.Name) Inherits these GPOs: $combinedgpos"
        $count++
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
        $count = 0
        $progresscount = 0
        $totalcount = $XMLFiles.count
        foreach ($File in $XMLFiles) {
            $progresscount++
            Write-Progress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Currently searched through $count" -PercentComplete ($progresscount / $totalcount*100)
            $Filename = Split-Path $File -Leaf
            $Distinguishedname = (split-path (split-path (split-path( split-path (split-path $File -Parent) -parent ) -parent ) -parent) -Leaf).Substring(1).TrimEnd('}')
            [xml]$Xml = Get-Content ($File)
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
    $progresscount = 0
    $inactiveaccounts = Search-ADaccount -AccountInactive -Timespan 180 -UsersOnly
    $totalcount = $inactiveaccounts.count
    ForEach ($account in $inactiveaccounts){
        $progresscount++
        Write-Progress -Activity "Searching for inactive users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount*100)
        if ($account.Enabled){
            if ($account.LastLogonDate){$userlastused = $account.LastLogonDate} else {$userlastused = "Never"}
            Add-Content -Path "$outputdir\accounts_inactive.txt" -Value "User $($account.SamAccountName) ($($account.Name)) has not logged on since $userlastused"
            $count++
        }
    }
    if ($count -gt 0){Write-Both "    [!] $count inactive user accounts(180days), see accounts_inactive.txt"}
}
function Get-AdminAccountChecks{# checks if Administrator account has been renamed, replaced and is no longer used.
    $AdministratorSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value)+"-500"
    $AdministratorSAMAccountName = (Get-ADUser -Filter {SID -eq $AdministratorSID} -properties SamAccountName).SamAccountName
    if ($AdministratorSAMAccountName -eq "Administrator"){Write-Both "    [!] Local Administrator account (UID500) has not been renamed"}
    elseif (!(Get-ADUser -Filter {samaccountname -eq "Administrator"})){Write-Both "    [!] Local Admini account renamed to $AdministratorSAMAccountName ($($account.Name)), but a dummy account not made in it's place!"}
    $AdministratorLastLogonDate =  (Get-ADUser -Filter {SID -eq $AdministratorSID}  -properties lastlogondate).lastlogondate
    if ($AdministratorLastLogonDate -gt (Get-Date).AddDays(-180)){Write-Both "    [!] UID500 (LocalAdmini) account is still used, last used $AdministratorLastLogonDate!"}
}
function Get-DisabledAccounts{#lists disabled accounts
    $disabledaccounts = Search-ADaccount -AccountDisabled -UsersOnly
    $count = 0
    $totalcount = $disabledaccounts.count
    ForEach ($account in $disabledaccounts){
        Write-Progress -Activity "Searching for disabled users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        if ($account.LastLogonDate){$userlastused = $account.LastLogonDate} else {$userlastused = "Never"}
        Add-Content -Path "$outputdir\accounts_disabled.txt" -Value "Account $($account.SamAccountName) ($($account.Name)) is disabled"
        $count++
    }
    if ($count -gt 0){Write-Both "    [!] $count disabled user accounts, see accounts_disabled.txt"}
}
function Get-AccountPassDontExpire{#lists accounts who's passwords dont expire
    $count = 0
    $nonexpiringpasswords = Search-ADAccount -PasswordNeverExpires -UsersOnly
    $totalcount = $nonexpiringpasswords.count
    ForEach ($account in $nonexpiringpasswords){
        Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        Add-Content -Path "$outputdir\accounts_passdontexpire.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    if ($count -gt 0){Write-Both "    [!] There are $count accounts that don't expire, see accounts_passdontexpire.txt"}
}
function Get-OldBoxes{#lists server 2003/XP machines
    $count = 0
    $oldboxes = Get-ADComputer -Filter {OperatingSystem -Like "*2003*" -or OperatingSystem -Like "*XP*"} -Property *
    $totalcount = $oldboxes.count
    ForEach ($machine in $oldboxes){
        Write-Progress -Activity "Searching for 2003/XP devices joined to the domain..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        Add-Content -Path "$outputdir\machines_old.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address)"
        $count++
    }
    if ($count -gt 0){Write-Both "    [!] We found $count machines running server 2003/XP! see machines_old.txt"}
}
function Get-DCsNotOwnedByDA {#searches for DC objects not owned by the Domain Admins group
    $count = 0
    $progresscount = 0
    $domaincontrollers = Get-ADComputer -Filter {PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521} -Property *
    $totalcount = $domaincontrollers.count
    ForEach ($machine in $domaincontrollers){
        $progresscount++
        Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount*100)
        if ($machine.ntsecuritydescriptor.Owner -ne "$env:UserDomain\Domain Admins"){
            Add-Content -Path "$outputdir\dcs_not_owned_by_da.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address), owned by $($machine.ntsecuritydescriptor.Owner)"
            $count++
        }
    }
    if ($count -gt 0){Write-Both "    [!] We found $count DCs not owned by Domains Admins group! see dcs_not_owned_by_da.tx"}
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
    if ($DomainLevel -eq "Windows2016Domain" -and [single](Get-WinVersion) -gt 10.0){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"}
    $ForestLevel = (Get-ADForest).ForestMode
    if ($ForestLevel -eq "Windows2000Forest" -and [single](Get-WinVersion) -gt 5.0){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2003InterimForest" -and [single](Get-WinVersion) -gt 5.1){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2003Forest" -and [single](Get-WinVersion) -gt 5.2){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2008Forest" -and [single](Get-WinVersion) -gt 6.0){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2008R2Forest" -and [single](Get-WinVersion) -gt 6.1){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2012Forest" -and [single](Get-WinVersion) -gt 6.2){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2012R2Forest" -and [single](Get-WinVersion) -gt 6.3){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
    if ($ForestLevel -eq "Windows2016Forest" -and [single](Get-WinVersion) -gt 10.0){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"}
}

$outputdir = (Get-Item -Path ".\").FullName + "\" + $env:computername
$starttime = get-date
$scriptname = $MyInvocation.MyCommand.Name
if (!(Test-Path "$outputdir")) { New-Item -ItemType directory -Path $outputdir | out-null }
Write-Both " _____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
$versionnum                  by phillips321
"
$running=$false
Write-Both "[*] Script start time $starttime"
if (Get-Module -ListAvailable -Name ActiveDirectory){import-module ActiveDirectory} else {write-host "[!] ActiveDirectory module not installed, exiting..." ; exit}
if (Get-Module -ListAvailable -Name ServerManager){import-module ServerManager} else {write-host "[!] ServerManager module not installed, exiting..." ; exit}
if (Get-Module -ListAvailable -Name GroupPolicy){import-module GroupPolicy} else {write-host "[!] GroupPolicy module not installed, exiting..." ; exit}
write-host "[+] Outputting to $outputdir"
if ($hostdetails -Or $all) { $running=$true; Write-Both "[*] Device Information" ; Get-HostDetails }
if ($domainaudit -Or $all) { $running=$true; Write-Both "[*] Domain Audit" ; Get-MachineAccountQuota ; Get-SMB1Support; Get-FunctionalLevel ; Get-DCsNotOwnedByDA }
if ($trusts -Or $all) { $running=$true; Write-Both "[*] Domain Trust Audit" ; Get-DomainTrusts }
if ($accounts -Or $all) { $running=$true; Write-Both "[*] Accounts Audit" ; Get-InactiveAccounts ; Get-DisabledAccounts ; Get-AdminAccountChecks ; Get-NULLSessions; Get-AdminSDHolders; Get-ProtectedUsers }
if ($passwordpolicy -Or $all) { $running=$true; Write-Both "[*] Password Information Audit" ; Get-AccountPassDontExpire ; Get-UserPasswordNotChangedRecently; Get-PasswordPolicy }
if ($ntds -Or $all) { $running=$true; Write-Both "[*] Trying to save NTDS.dit, please wait..."; Get-NTDSdit }
if ($oldboxes -Or $all) { $running=$true; Write-Both "[*] Computer Objects Audit" ; Get-OldBoxes }
if ($gpo -Or $all) { $running=$true; Write-Both "[*] GPO audit (and checking SYSVOL for passwords)"  ; Get-GPOtoFile ; Get-GPOsPerOU ; Get-SYSVOLXMLS }
if ($ouperms -Or $all) { $running=$true; Write-Both "[*] Check Generic Group AD Permissions" ; Get-OUPerms }
if ($laps -Or $all) { $running=$true; Write-Both "[*] Check For Existence of LAPS in domain" ; Get-LAPSStatus }
if ($authpolsilos -Or $all) { $running=$true; Write-Both "[*] Check For Existence of Authentication Polices and Silos" ; Get-AuthenticationPoliciesAndSilos }
if (!$running) { Write-Both "[!] No arguments selected;" 
    Write-Both "[!] Other options are as follows, they can be used in combination"
    Write-Both "    -hostdetails retrieves hostname and other useful audit info"
    Write-Both "    -domainaudit retrieves information about the AD such as functional level"
    Write-Both "    -trusts retrieves information about any doman trusts"
    Write-Both "    -accounts identifies account issues such as expired, disabled, etc..."
    Write-Both "    -passwordpolicy retrieves password policy information "
    Write-Both "    -ntds dumps the NTDS.dit file using ntdsutil"
    Write-Both "    -oldboxes identified outdated OSs like XP/2003 joined to the domain"
    Write-Both "    -gpo dumps the GPOs in XML and HTML for later analysis"
    Write-Both "    -ouperms checks generic OU permission issues"
    Write-Both "    -laps checks if LAPS is installed"
    Write-Both "    -authpolsilos checks for existenece of authentication policies and silos"
    Write-Both "    -all runs all checks, e.g. $scriptname -all"
}
$endtime = get-date
Write-Both "[*] Script end time $endtime"
