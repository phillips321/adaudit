<#
phillips321.co.uk ADAudit.ps1
Changelog:
    v4.4 - Reinstated nessus fix and put output in a list for findings, changed Get-AdminSDHolders with Get-PrivilegedGroupAccounts
    v4.3 - Temp fix with nessus output
    v4.2 - Bug fix on cpassword count
    v4.1 - Loads of fixes. Works with Powershellv2 again now, filtered out disabled accounts, improved domain trusts checking, ouperms improvements and filtering, check for w2k, fixed typos/spelling and various other fixes.
    v4.0 - Added XML output for import to CheckSecCanopy
    v3.5 - Added KB more references for internal use
    v3.4 - Added KB references for internal use
    v3.3 - Added a greater level of accuracy to Inactive Accounts (thanks exceedio)
    v3.2 - Added search for DCs not owned by Domain Admins group
    v3.1 - Added progress to functions that have count, added check for transitive trusts
    v3.0 - Added ability to choose functions before runtime, cleaned up get-ouperms output
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
$versionnum = "v4.3"
function Write-Both(){#writes to console screen and output file
    Write-Host "$args"; Add-Content -Path "$outputdir\consolelog.txt" -Value "$args"}
function Write-Nessus-Header(){#creates nessus XML file header
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<?xml version=`"1.0`" ?><AdAudit>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<Report name=`"$env:ComputerName`" xmlns:cm=`"http://www.nessus.org/cm`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportHost name=`"$env:ComputerName`"><HostProperties></HostProperties>"
}
function Write-Nessus-Finding( [string]$pluginname, [string]$pluginid, [string]$pluginexample){
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportItem port=`"0`" svc_name=`"`" protocol=`"`" severity=`"0`" pluginID=`"ADAudit_$pluginid`" pluginName=`"$pluginname`" pluginFamily=`"Windows`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<description>There's an issue with $pluginname</description>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_type>remote</plugin_type><risk_factor>Low</risk_factor>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<solution>CCS Recommends fixing the issues with $pluginname on the host</solution>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<synopsis>There's an issue with the $pluginname settings on the host</synopsis>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_output>$pluginexample</plugin_output></ReportItem>"
}
function Write-Nessus-Footer(){
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "</ReportHost></Report></AdAudit>"
}
function Get-OUPerms{#Check for non-standard perms for authenticated users, domain users, users and everyone groups
    $count = 0
    $progresscount = 0
    $objects = (Get-ADObject -Filter *)
    $totalcount = $objects.count
    foreach ($object in $objects) {
        $progresscount++
        Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount*100)
        $output = (Get-Acl AD:$object).Access | where-object {($_.IdentityReference -eq 'NT Authority\Authenticated Users') -or ($_.IdentityReference -eq 'Everyone') -or ($_.IdentityReference -like '*\Domain Users') -or ($_.IdentityReference -eq 'BUILTIN\Users')} | Where-Object {($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny')}
		if ($output -ne $null) {$count++ ; Add-Content -Path "$outputdir\ou_permissions.txt" -Value  "OU: $object"; Add-Content -Path "$outputdir\ou_permissions.txt" -Value "[!] Rights: $($output.IdentityReference) $($output.ActiveDirectoryRights) $($output.AccessControlType)"}
    }
    if ($count -gt 0){
        Write-Both "    [!] Issue identified, see $outputdir\ou_permissions.txt"
        Write-Nessus-Finding "OUPermissions" "KB551" (Get-Content -Raw -Path "$outputdir\ou_permissions.txt")
    }
}
function Get-LAPSStatus{#Check for presence of LAPS in domain
        try{
        Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$((Get-ADDomain).DistinguishedName)" -ErrorAction Stop | Out-Null
        Write-Both "    [!] LAPS Installed in domain"
	    #TODO: Need to check what computers have LAPS assigned using: Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd
    }
    catch{
        Write-Both "    [!] LAPS Not Installed in domain (KB258)"
        Write-Nessus-Finding "LAPSMissing" "KB258" "LAPS Not Installed in domain"
    }
}

Function Get-PrivilegedGroupAccounts{#lists users in Admininstrators, DA and EA groups
    $privilegedusers = Get-ADGroupMember administrators -Recursive
    $privilegedusers += Get-ADGroupMember "domain admins" -Recursive
    $privilegedusers += Get-ADGroupMember "enterprise admins" -Recursive
    $privusersunique = $privilegedusers | Sort-Object -Unique
    $count = 0
    $totalcount = $privilegedusers.count

    ForEach ($account in $privusersunique){
        Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        Add-Content -Path "$outputdir\accounts_userPrivileged.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    if ($count -gt 0){
        Write-Both "    [!] There are $count accounts in privileged groups, see accounts_userPrivileged.txt (KB426)"
        Write-Nessus-Finding "AdminSDHolders" "KB426" (Get-Content -Raw -Path "$outputdir\accounts_userPrivileged.txt")
    }
}

function Get-ProtectedUsers{#lists users in "Protected Users" group (2012R2 and above)
    $DomainLevel = (Get-ADDomain).domainMode
    if ($DomainLevel -eq "Windows2012Domain" -or $DomainLevel -eq "Windows2012R2Domain" -or $DomainLevel -eq "Windows2016Domain"){#Checking for 2012 or above domain functional level
        $count = 0
        $protectedaccounts = (Get-ADGroup "Protected Users" -Properties members).Members
        $totalcount = $protectedaccounts.count
        ForEach ($members in $protectedaccounts){
            Write-Progress -Activity "Searching for ptoected users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
            $account = Get-ADObject $members -Properties samaccountname
            Add-Content -Path "$outputdir\accounts_protectedusers.txt" -Value "$($account.SamAccountName) ($($account.Name))"
            $count++
        }
        if ($count -gt 0){
            Write-Both "    [!] There are $count accounts in the 'Protected Users' group, see accounts_protectedusers.txt"
            Write-Nessus-Finding "ProtectedUsers" "KB549" (Get-Content -Raw -Path "$outputdir\accounts_protectedusers.txt")
        }
    }
    else {Write-Both "    [-] Not Windows 2012 Domain Functional level or above, skipping Get-ProtectedUsers check."}
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
    if ($MachineAccountQuota -gt 0){
        Write-Both "    [!] Domain users can add $MachineAccountQuota devices to the domain! (KB251)"
        Write-Nessus-Finding "DomainAccountQuota" "KB251" "Domain users can add $MachineAccountQuota devices to the domain"
        }
}
function Get-PasswordPolicy{
	Write-Both 	"    [+] Checking default password policy"
    if (!(Get-ADDefaultDomainPasswordPolicy).PasswordComplexity) { Write-Both "    [!] Password Complexity not enabled (KB262)" ; Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled"}
    if ((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold -lt 5) {Write-Both "    [!] Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold) (KB263)"  ; Write-Nessus-Finding "LockoutThreshold" "KB263" "Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold)"}
    if ((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength -lt 14) {Write-Both "    [!] Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength) (KB262)" ; Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)" }
    if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled) {Write-Both "    [!] Reversible encryption is enabled" }
    if ((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge -eq "00:00:00") {Write-Both "    [!] Passwords do not expire (KB254)"  ; Write-Nessus-Finding "PasswordsDoNotExpire" "KB254" "Passwords do not expire"}
    if ((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount -lt 12) {Write-Both "    [!] Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount) (KB262)" ; Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)"}
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).NoLmHash -eq 0) {Write-Both "    [!] LM Hashes are stored! (KB510)" ; Write-Nessus-Finding "LMHashesAreStored" "KB510" "LM Hashes are stored" }
	Write-Both 	"    [-] Finished checking default password policy"

	Write-Both 	"    [+] Checking fine-grained password policies if they exist"
	#foreach ($finegrainedpolicy in Get-ADFineGrainedPasswordPolicy -Filter *) { Write-Both "    [!] Policy: $finegrainedpolicy"; Write-Both "    [!] Applies to: ($($finegrainedpolicy).AppliesTo)"
	foreach ($finegrainedpolicy in Get-ADFineGrainedPasswordPolicy -Filter *) {$finegrainedpolicyappliesto=$finegrainedpolicy.AppliesTo; Write-Both "    [!] Policy: $finegrainedpolicy"; Write-Both "    [!] AppliesTo: $($finegrainedpolicyappliesto)"
	if (!($finegrainedpolicy).PasswordComplexity) { Write-Both "    [!] Password Complexity not enabled (KB262)" ; Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled for $finegrainedpolicy"}
    if (($finegrainedpolicy).LockoutThreshold -lt 5) {Write-Both "    [!] Lockout threshold is less than 5, currently set to $($finegrainedpolicy).LockoutThreshold) (KB263)"  ; Write-Nessus-Finding "LockoutThreshold" "KB263" " Lockout threshold for $finegrainedpolicy is less than 5, currently set to $(($finegrainedpolicy).LockoutThreshold)" }
    if (($finegrainedpolicy).MinPasswordLength -lt 14) {Write-Both "    [!] Minimum password length is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength) (KB262)"  ; Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length for $finegrainedpolicy is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength)"}
    if (($finegrainedpolicy).ReversibleEncryptionEnabled) {Write-Both "    [!] Reversible encryption is enabled" }
    if (($finegrainedpolicy).MaxPasswordAge -eq "00:00:00") {Write-Both "    [!] Passwords do not expire (KB254)" }
    if (($finegrainedpolicy).PasswordHistoryCount -lt 12) {Write-Both "    [!] Passwords history is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount) (KB262)"  ; Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history for $finegrainedpolicy is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount)"} }
	Write-Both 	"    [-] Finished checking fine-grained password policy"
}
function Get-NULLSessions{
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymous -eq 0) {Write-Both "    [!] RestrictAnonymous is set to 0! (KB81)" ; Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0"}
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymousSam -eq 0) {Write-Both "    [!] RestrictAnonymousSam is set to 0! (KB81)" ; Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0" }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).everyoneincludesanonymous -eq 1) {Write-Both "    [!] EveryoneIncludesAnonymous is set to 1! (KB81)" ; Write-Nessus-Finding "NullSessions" "KB81" "EveryoneIncludesAnonymous is set to 1" }
}
function Get-DomainTrusts{#lists domain trusts if they are bad
    ForEach ($trust in (Get-ADObject -Filter {objectClass -eq "trustedDomain"} -Properties TrustPartner,TrustDirection,trustType,trustAttributes)){
        if ($trust.TrustDirection -eq 2){
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4){ # 1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."}
            else{
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"}
        }
        if ($trust.TrustDirection -eq 3){
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4){ # 1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."}
            else{
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"}
        }
    }
}
function Get-WinVersion{
    $WinVersion = [single]([string][environment]::OSVersion.Version.Major + "." + [string][environment]::OSVersion.Version.Minor)
    return [single]$WinVersion
}
function Get-SMB1Support{#check if server supports SMBv1
    if ([single](Get-WinVersion) -le [single]6.1){# NT6.1 or less detected so checking reg key
        if (!(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters).SMB1 -eq 0){
            Write-Both "    [!] SMBv1 is not disabled (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
    elseif ([single](Get-WinVersion) -ge [single]6.2){#NT6.2 or greater detected so using powershell function
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol){
            Write-Both "    [!] SMBv1 is enabled! (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
}
function Get-UserPasswordNotChangedRecently{#Reports users that haven't changed passwords in more than 90 days
    $count = 0
    $DaysAgo=(Get-Date).AddDays(-90)
    $accountsoldpasswords = get-aduser -filter {PwdLastSet -lt $DaysAgo -and enabled -eq "true"} -properties passwordlastset
    $totalcount= $accountsoldpasswords.count
    ForEach ($account in $accountsoldpasswords){
        Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        if ($account.PasswordLastSet){$datelastchanged = $account.PasswordLastSet} else {$datelastchanged = "Never"}
        Add-Content -Path "$outputdir\accounts_with_old_passwords.txt" -Value "User $($account.SamAccountName) ($($account.Name)) has not changed their password since $datelastchanged"
        $count++
    }
    if ($count -gt 0){
        Write-Both "    [!] $count accounts with passwords older than 90days, see accounts_with_old_passwords.txt (KB550)"
        Write-Nessus-Finding "AccountsWithOldPasswords" "KB550" (Get-Content -Raw -Path "$outputdir\accounts_with_old_passwords.txt")
    }
    $krbtgtPasswordDate = (get-aduser -Filter {samaccountname -eq "krbtgt"} -Properties PasswordLastSet).PasswordLastSet
    if ($krbtgtPasswordDate -lt (Get-Date).AddDays(-180)){
        Write-Both "    [!] krbtgt password not changed since $krbtgtPasswordDate! (KB253)"
        Write-Nessus-Finding "krbtgtPasswordNotChanged" "KB253" "krbtgt password not changed since $krbtgtPasswordDate"
    }
}
function Get-GPOtoFile{#oututs complete GPO report
    if (Test-Path "$outputdir\GPOReport.html") { Remove-Item "$outputdir\GPOReport.html" -Recurse; }
    Get-GPOReport -All -ReportType HTML -Path "$outputdir\GPOReport.html"
    Write-Both "    [+] GPO Report saved to GPOReport.html"
    if (Test-Path "$outputdir\GPOReport.xml") { Remove-Item "$outputdir\GPOReport.xml" -Recurse; }
    Get-GPOReport -All -ReportType XML -Path "$outputdir\GPOReport.xml"
    Write-Both "    [+] GPO Report saved to GPOReport.xml, now run Grouper offline using the following command (KB499)"
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
   Write-Both "    [+] Inherited GPOs saved to ous_inheritedGPOs.txt"
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
    $count = 0
    if ($XMLFiles){
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
                Write-Both "    [!] cpassword found in file, copying to output folder (KB329)"
                Write-Both "        $File"
                copy-item -Path $File -Destination $outputdir\sysvol\$Distinguishedname.$Filename
                $count++
            }
        }
    }
    if ($count -eq 0){
        Write-Both "    ...cpassword not found in the $($XMLFiles.count) XML files found."
    } else {
           $GPOxml = (Get-Content "$outputdir\sysvol\*.xml" -ErrorAction SilentlyContinue)
           $GPOxml = $GPOxml -replace "<", "&lt;";  
           $GPOxml = $GPOxml -replace ">", "&gt;"; 
           Write-Nessus-Finding "GPOPasswordStorage" "KB329" "$GPOxml"
           }
}
function Get-InactiveAccounts{#lists accounts not used in past 180 days plus some checks for admin accounts
    $count = 0
    $progresscount = 0
    $inactiveaccounts = Search-ADaccount -AccountInactive -Timespan (New-TimeSpan -Days 180) -UsersOnly | Where-Object {$_.Enabled -eq $true}
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
    if ($count -gt 0){
        Write-Both "    [!] $count inactive user accounts(180days), see accounts_inactive.txt (KB500)"
        Write-Nessus-Finding "InactiveAccounts" "KB500" (Get-Content -Raw -Path "$outputdir\accounts_inactive.txt")
    }
}
function Get-AdminAccountChecks{# checks if Administrator account has been renamed, replaced and is no longer used.
    $AdministratorSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value)+"-500"
    $AdministratorSAMAccountName = (Get-ADUser -Filter {SID -eq $AdministratorSID} -properties SamAccountName).SamAccountName
    if ($AdministratorSAMAccountName -eq "Administrator"){
        Write-Both "    [!] Local Administrator account (UID500) has not been renamed (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Administrator account (UID500) has not been renamed"
    }
    elseif (!(Get-ADUser -Filter {samaccountname -eq "Administrator"})){
        Write-Both "    [!] Local Administrator account renamed to $AdministratorSAMAccountName ($($account.Name)), but a dummy account not made in it's place! (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Admini account renamed to $AdministratorSAMAccountName ($($account.Name)), but a dummy account not made in it's place"
    }
    $AdministratorLastLogonDate =  (Get-ADUser -Filter {SID -eq $AdministratorSID}  -properties lastlogondate).lastlogondate
    if ($AdministratorLastLogonDate -gt (Get-Date).AddDays(-180)){
        Write-Both "    [!] UID500 (LocalAdministrator) account is still used, last used $AdministratorLastLogonDate! (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "UID500 (LocalAdmini) account is still used, last used $AdministratorLastLogonDate"
    }
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
    if ($count -gt 0){
        Write-Both "    [!] $count disabled user accounts, see accounts_disabled.txt (KB501)"
        Write-Nessus-Finding "DisabledAccounts" "KB501" (Get-Content -Raw -Path "$outputdir\accounts_disabled.txt")
    }
}
function Get-AccountPassDontExpire{#lists accounts who's passwords dont expire
    $count = 0
    $nonexpiringpasswords = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object {$_.Enabled -eq $true}
    $totalcount = $nonexpiringpasswords.count
    ForEach ($account in $nonexpiringpasswords){
        Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        Add-Content -Path "$outputdir\accounts_passdontexpire.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    if ($count -gt 0){
        Write-Both "    [!] There are $count accounts that don't expire, see accounts_passdontexpire.txt (KB254)"
        Write-Nessus-Finding "AccountsThatDontExpire" "KB254" (Get-Content -Raw -Path "$outputdir\accounts_passdontexpire.txt")
    }
}
function Get-OldBoxes{#lists server 2000/2003/XP machines
    $count = 0
    $oldboxes = Get-ADComputer -Filter {OperatingSystem -Like "*2003*" -and Enabled -eq "true" -or OperatingSystem -Like "*XP*" -and Enabled -eq "true" -or OperatingSystem -Like "*2000*" -and Enabled -eq "true"} -Property *
    $totalcount = $oldboxes.count
    ForEach ($machine in $oldboxes){
        Write-Progress -Activity "Searching for 2003/XP devices joined to the domain..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount*100)
        Add-Content -Path "$outputdir\machines_old.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address)"
        $count++
    }
    if ($count -gt 0){
        Write-Both "    [!] We found $count machines running server 2003/XP! see machines_old.txt (KB3/37/38/KB259)"
        Write-Nessus-Finding "OldBoxes" "KB259" (Get-Content -Raw -Path "$outputdir\machines_old.txt")
    }
}
function Get-DCsNotOwnedByDA {#searches for DC objects not owned by the Domain Admins group
    $count = 0
    $progresscount = 0
    $domaincontrollers = Get-ADComputer -Filter {PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521} -Property *
    $totalcount = $domaincontrollers.count
    if ($totalcount -gt 0){
        ForEach ($machine in $domaincontrollers){
            $progresscount++
            Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount*100)
            if ($machine.ntsecuritydescriptor.Owner -ne "$env:UserDomain\Domain Admins"){
                Add-Content -Path "$outputdir\dcs_not_owned_by_da.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address), owned by $($machine.ntsecuritydescriptor.Owner)"
                $count++
            }
        }
    }
    if ($count -gt 0){
        Write-Both "    [!] We found $count DCs not owned by Domains Admins group! see dcs_not_owned_by_da.tx"
        Write-Nessus-Finding "DCsNotByDA" "KB547" (Get-Content -Raw -Path "$outputdir\dcs_not_owned_by_da.txt")
    }
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
    if ($DomainLevel -eq "Windows2000Domain" -and [single](Get-WinVersion) -gt 5.0){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel"}
    if ($DomainLevel -eq "Windows2003InterimDomain" -and [single](Get-WinVersion) -gt 5.1){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel"}
    if ($DomainLevel -eq "Windows2003Domain" -and [single](Get-WinVersion) -gt 5.2){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel"}
    if ($DomainLevel -eq "Windows2008Domain" -and [single](Get-WinVersion) -gt 6.0){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel"}
    if ($DomainLevel -eq "Windows2008R2Domain" -and [single](Get-WinVersion) -gt 6.1){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel"}
    if ($DomainLevel -eq "Windows2012Domain" -and [single](Get-WinVersion) -gt 6.2){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel"}
    if ($DomainLevel -eq "Windows2012R2Domain" -and [single](Get-WinVersion) -gt 6.3){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel"}
    if ($DomainLevel -eq "Windows2016Domain" -and [single](Get-WinVersion) -gt 10.0){Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel"}
    $ForestLevel = (Get-ADForest).ForestMode
    if ($ForestLevel -eq "Windows2000Forest" -and [single](Get-WinVersion) -gt 5.0){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel"}
    if ($ForestLevel -eq "Windows2003InterimForest" -and [single](Get-WinVersion) -gt 5.1){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel"}
    if ($ForestLevel -eq "Windows2003Forest" -and [single](Get-WinVersion) -gt 5.2){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel"}
    if ($ForestLevel -eq "Windows2008Forest" -and [single](Get-WinVersion) -gt 6.0){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel"}
    if ($ForestLevel -eq "Windows2008R2Forest" -and [single](Get-WinVersion) -gt 6.1){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel"}
    if ($ForestLevel -eq "Windows2012Forest" -and [single](Get-WinVersion) -gt 6.2){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel"}
    if ($ForestLevel -eq "Windows2012R2Forest" -and [single](Get-WinVersion) -gt 6.3){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel"}
    if ($ForestLevel -eq "Windows2016Forest" -and [single](Get-WinVersion) -gt 10.0){Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!"; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel"}
}
function Get-GPOEnum{#Loops GPOs for some important domain-wide settings
    $AllowedJoin = @();
    $HardenNTLM = @();
    $DenyNTLM = @();
    $AuditNTLM = @();
    $NTLMAuthExceptions = @();
    $EncryptionTypesNotConfigured = $true;
    $AdminLocalLogonAllowed = $true;
    $AdminRPDLogonAllowed = $true;
    $AdminNetworkLogonAllowed = $true;
    $AllGPOs = Get-GPO -All | sort DisplayName;
    foreach ($GPO in $AllGPOs){
        $GPOreport = Get-GPOReport -Guid $GPO.id -ReportType Xml;
        #Look for GPO that allows join PC to domain
        $permissionindex = $GPOreport.IndexOf('<q1:Name>SeMachineAccountPrivilege</q1:Name>');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeMachineAccountPrivilege'}).member) ){
                $obj = New-Object -TypeName psobject;
                $obj | Add-Member -MemberType NoteProperty -Name GPO -Value $GPO.DisplayName;
                $obj | Add-Member -MemberType NoteProperty -Name SID -Value $member.sid.'#text';
                $obj | Add-Member -MemberType NoteProperty -Name Name -Value $member.name.'#text';

                $AllowedJoin += $obj;
            }
        }
        #Look for GPO that hardens NTLM
        $permissionindex = $GPOreport.IndexOf('NoLMHash</q1:KeyName>');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            $value = $xmlreport.gpo.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.keyname -Match 'NoLMHash'};
            $obj = New-Object -TypeName psobject;
            $obj | Add-Member -MemberType NoteProperty -Name GPO -Value $GPO.DisplayName;
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "NoLMHash $($value.Display.DisplayBoolean)";
            $HardenNTLM += $obj;
        }
        $permissionindex = $GPOreport.IndexOf('LmCompatibilityLevel</q1:KeyName>');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            $value = $xmlreport.gpo.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.keyname -Match 'LmCompatibilityLevel'};
            $obj = New-Object -TypeName psobject;
            $obj | Add-Member -MemberType NoteProperty -Name GPO -Value $GPO.DisplayName;
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "LmCompatibilityLevel $($value.Display.DisplayString)";
            $HardenNTLM += $obj;
        }
        #Look for GPO that denies NTLM
        $permissionindex = $GPOreport.IndexOf('RestrictNTLMInDomain</q1:KeyName>');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            $value = $xmlreport.gpo.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.keyname -Match 'RestrictNTLMInDomain'};
            $obj = New-Object -TypeName psobject;
            $obj | Add-Member -MemberType NoteProperty -Name GPO -Value $GPO.DisplayName;
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "RestrictNTLMInDomain $($value.Display.DisplayString)";
            $DenyNTLM += $obj;
        }
        #Look for GPO that audits NTLM
        $permissionindex = $GPOreport.IndexOf('AuditNTLMInDomain</q1:KeyName>');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            $value = $xmlreport.gpo.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.keyname -Match 'AuditNTLMInDomain'};
            $obj = New-Object -TypeName psobject;
            $obj | Add-Member -MemberType NoteProperty -Name GPO -Value $GPO.DisplayName;
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditNTLMInDomain $($value.Display.DisplayString)";
            $AuditNTLM += $obj;
        }
        $permissionindex = $GPOreport.IndexOf('AuditReceivingNTLMTraffic</q1:KeyName>');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            $value = $xmlreport.gpo.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.keyname -Match 'AuditReceivingNTLMTraffic'};
            $obj = New-Object -TypeName psobject;
            $obj | Add-Member -MemberType NoteProperty -Name GPO -Value $GPO.DisplayName;
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditReceivingNTLMTraffic $($value.Display.DisplayString)";
            $AuditNTLM += $obj;
        }
        #Look for GPO that allows NTLM exclusions
        $permissionindex = $GPOreport.IndexOf('DCAllowedNTLMServers</q1:KeyName>');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            foreach ($member in (($xmlreport.gpo.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.keyname -Match 'DCAllowedNTLMServers'}).SettingStrings.Value) ){
                $NTLMAuthExceptions += $member;
            }
        }
        #Validate Kerberos Encryption algorythm
        $permissionindex = $GPOreport.IndexOf('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes');
        if($permissionindex -gt 0){
            $EncryptionTypesNotConfigured = $false;
            $xmlreport = [xml]$GPOreport;
            $EncryptionTypes = $xmlreport.gpo.Computer.ExtensionData.Extension.SecurityOptions.Display.DisplayFields.Field;
            if(($EncryptionTypes | Where-Object {$_.name -eq 'DES_CBC_CRC'} | select -ExpandProperty value) -eq 'true'){
                Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_CRC for Kerberos!";
            }elseif(($EncryptionTypes | Where-Object {$_.name -eq 'DES_CBC_MD5'} | select -ExpandProperty value) -eq 'true'){
                Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_MD5 for Kerberos!";
            }elseif(($EncryptionTypes | Where-Object {$_.name -eq 'RC4_HMAC_MD5'} | select -ExpandProperty value) -eq 'true'){
                Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled RC4_HMAC_MD5 for Kerberos!";
            }elseif(($EncryptionTypes | Where-Object {$_.name -eq 'AES128_HMAC_SHA1'} | select -ExpandProperty value) -eq 'false'){
                Write-Both "    [!] AES128_HMAC_SHA1 not enabled for Kerberos!";
            }elseif(($EncryptionTypes | Where-Object {$_.name -eq 'AES256_HMAC_SHA1'} | select -ExpandProperty value) -eq 'false'){
                Write-Both "    [!] AES256_HMAC_SHA1 not enabled for Kerberos!";
            }elseif(($EncryptionTypes | Where-Object {$_.name -eq 'Future encryption types'} | select -ExpandProperty value) -eq 'false'){
                Write-Both "    [!] Future encryption types not enabled for Kerberos!";
            }
        }
        #Validates Admins local logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyInteractiveLogonRight');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeDenyInteractiveLogonRight'}).member)){
                if($member.name.'#text' -match 'Schema Admins' -or $member.name.'#text' -match 'Domain Admins' -or $member.name.'#text' -match 'Enterprise Admins'){
                    $AdminLocalLogonAllowed = $false;
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyInteractiveLogonRight $($member.name.'#text')";
                }
            }
        }
        #Validates Admins RDP logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyRemoteInteractiveLogonRight');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeDenyRemoteInteractiveLogonRight'}).member)){
                if($member.name.'#text' -match 'Schema Admins' -or $member.name.'#text' -match 'Domain Admins' -or $member.name.'#text' -match 'Enterprise Admins'){
                    $AdminRPDLogonAllowed = $false;
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyRemoteInteractiveLogonRight $($member.name.'#text')";
                }
            }
        }
        #Validates Admins network logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyNetworkLogonRight');
        if($permissionindex -gt 0){
            $xmlreport = [xml]$GPOreport;
            foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeDenyNetworkLogonRight'}).member)){
                if($member.name.'#text' -match 'Schema Admins' -or $member.name.'#text' -match 'Domain Admins' -or $member.name.'#text' -match 'Enterprise Admins'){
                    $AdminNetworkLogonAllowed = $false;
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyNetworkLogonRight $($member.name.'#text')";
                }
            }
        }
    }
    #Output for join PC to domain
    foreach($record in $AllowedJoin){
        Write-Both "    [+] GPO [$($record.GPO)] allows [$($record.Name)] to join computers to domain";
    }
    #Output for Admins local logon restrictions
    if($AdminLocalLogonAllowed){
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise local logon across domain!!!";
    }
    #Output for Admins RDP logon restrictions
    if($AdminRPDLogonAllowed){
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise RDP logon across domain!!!";
    }
    #Output for Admins network logon restrictions
    if($AdminNetworkLogonAllowed){
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise network logon across domain!!!";
    }
    #Output for Validate Kerberos Encryption algorythm
    if($EncryptionTypesNotConfigured){
        Write-Both "    [!] RC4_HMAC_MD5 enabled for Kerberos across domain!!!";
    }
    #Output for deny NTLM
    if($DenyNTLM.count -eq 0){
        if($HardenNTLM.count -eq 0){
            Write-Both "    [!] No GPO denies NTLM authentication!";
            Write-Both "    [!] No GPO explicitely restricts LM or NTLMv1!";
        }else{
            Write-Both "    [+] NTLM authentication hardening implemented, but NTLM not denied";
            foreach($record in $HardenNTLM){
                Write-Both "        [-] $($record.value)";
                Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]";
            }
        }
    }else{
        foreach($record in $DenyNTLM){
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]";
        }
    }
    #Output for NTLM exceptions
    if($NTLMAuthExceptions.count -ne 0){
        foreach($record in $NTLMAuthExceptions){
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM auth exceptions $($record)";
        }
    }
    #Output for NTLM audit
    if($AuditNTLM.count -eq 0){
        Write-Both "    [!] No GPO enables NTLM audit authentication!";
    }else{
        foreach($record in $DenyNTLM){
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM audit GPO [$($record.gpo)] with value [$($record.value)]";
        }
    }
}
function Get-PrivilegedGroupMembership{#List Domain Admins, Enterprise Admins and Schema Admins members
    $SchemaMembers = Get-ADGroup 'Schema Admins' | Get-ADGroupMember;
    $EnterpriseMembers = Get-ADGroup 'Enterprise Admins' | Get-ADGroupMember;
    $DomainAdminsMembers = Get-ADGroup 'Domain Admins' | Get-ADGroupMember;
    if(($SchemaMembers | measure).count -ne 0){
            Write-Both "    [!] Schema Admins not empty!!!";
        foreach($member in $SchemaMembers){
            Add-Content -Path "$outputdir\schema_admins.txt" -Value "$($member.objectClass) $($member.name)";
        }
    }
    if(($EnterpriseMembers | measure).count -ne 0){
            Write-Both "    [!] Enterprise Admins not empty!!!";
        foreach($member in $EnterpriseMembers){
            Add-Content -Path "$outputdir\enterprise_admins.txt" -Value "$($member.objectClass) $($member.name)";
        }
    }
    foreach($member in $DomainAdminsMembers){
        Add-Content -Path "$outputdir\domain_admins.txt" -Value "$($member.objectClass) $($member.name)";
    }
}
function Get-DCEval{#Basic validation of all DCs in forest
    #Collect all DCs in forest
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest();
    $ADs = Get-ADDomainController -Filter  { Site -like "*" }
    #Validatee OS version of DCs
    if( ( $ads.operatingsystem | select -Unique ).count -eq 1 ){
        Write-Both "    [+] All DCs are the same OS version of $($ads.operatingsystem | select -Unique)";
    }else{
        Write-Both "    [!] Operating system differs across DCs!!!";
        if( ( $ads | Where-Object {$_.OperatingSystem -Match '2003'} ) -ne $null ){
            Write-Both "        [+] Domain controllers with WS 2003";
            $ads | Where-Object {$_.OperatingSystem -Match '2003'} | ForEach-Object {Write-Both "            [-] $($_.Name)"};
        }
        if( ( $ads | Where-Object {$_.OperatingSystem -Match '2008 !(R2)'} ) -ne $null ){
            Write-Both "        [+] Domain controllers with WS 2008";
            $ads | Where-Object {$_.OperatingSystem -Match '2008 !(R2)'} | ForEach-Object {Write-Both "            [-] $($_.Name)"};
        }
        if( ( $ads | Where-Object {$_.OperatingSystem -Match '2008 R2'}) -ne $null ){
            Write-Both "        [+] Domain controllers with WS 2008 R2";
            $ads | Where-Object {$_.OperatingSystem -Match '2008 R2'} | ForEach-Object {Write-Both "            [-] $($_.Name)"};
        }
        if( ( $ads | Where-Object {$_.OperatingSystem -Match '2012 !(R2)'} ) -ne $null ){
            Write-Both "        [+] Domain controllers with WS 2012";
            $ads | Where-Object {$_.OperatingSystem -Match '2012 !(R2)'} | ForEach-Object {Write-Both "            [-] $($_.Name)"};
        }
        if( ( $ads | Where-Object {$_.OperatingSystem -Match '2012 R2'} ) -ne $null ){
            Write-Both "        [+] Domain controllers with WS 2012 R2";
            $ads | Where-Object {$_.OperatingSystem -Match '2012 R2'} | ForEach-Object {Write-Both "            [-] $($_.Name)"};
        }
        if( ( $ads | Where-Object {$_.OperatingSystem -Match '2016'} ) -ne $null ){
            Write-Both "        [+] Domain controllers with WS 2016";
            $ads | Where-Object {$_.OperatingSystem -Match '2016'} | ForEach-Object {Write-Both "            [-] $($_.Name)"};
        }
    }
    #Validate DCs hotfix level
    if( (( $ads | Select-object OperatingSystemHotfix -Unique ) | measure).count -eq 1 -or ( $ads | Select-object OperatingSystemHotfix -Unique ) -eq $null ){
        Write-Both "    [+] All DCs have the same hotfix of [$($ads | Select-Object OperatingSystemHotFix -Unique | ForEach-Object {$_.OperatingSystemHotfix})]";
    }else{
        Write-Both "    [!] Hotfix level differs across DCs!!!";
        $ads | ForEach-Object {Write-Both "        [-] DC $($_.Name) hotfix [$($_.OperatingSystemHotfix)]"};
    }
    #Validate DCs Service Pack level
    if( (( $ads | Select-object OperatingSystemServicePack -Unique ) | measure).count -eq 1 -or ( $ads | Select-Object OperatingSystemServicePack -Unique ) -eq $null){
        Write-Both "    [+] All DCs have the same Service Pack of [$($ads | Select-Object OperatingSystemServicePack -Unique | ForEach-Object {$_.OperatingSystemServicePack})]";
    }else{
        Write-Both "    [!] Service Pack level differs across DCs!!!";
        $ads | ForEach-Object {Write-Both "        [-] DC $($_.Name) Service Pack [$($_.OperatingSystemServicePack)]"};
    }
    #Validate DCs OS Version
    if( (( $ads |  Select-object OperatingSystemVersion -Unique ) | measure).count -eq 1 -or ( $ads | Select-Object OperatingSystemVersion -Unique ) -eq $null){
        Write-Both "    [+] All DCs have the same OS Version of [$($ads | Select-Object OperatingSystemVersion -Unique | ForEach-Object {$_.OperatingSystemVersion})]";
    }else{
        Write-Both "    [!] OS Version differs across DCs!!!";
        $ads | ForEach-Object {Write-Both "        [-] DC $($_.Name) OS Version [$($_.OperatingSystemVersion)]"};
    }
    #List sites without GC
    $SitesWithNoGC = $false;
    foreach($Site in $Forest.Sites){
        if(($ads | Where-Object {$_.Site -eq $Site.Name} | Where-Object {$_.IsGlobalCatalog -eq $True}) -eq $null) {$SitesWithNoGC = $true;Add-Content -Path "$outputdir\sites_no_gc.txt" -Value "$($Site.Name)"; }
    }
    Write-Both "    [!] You have sites with no Global Catalog!";
    #Does one DC holds all FSMO
    if(($ADs | Where-Object {$_.OperationMasterRoles -ne $null} | measure).count -eq 1){
        Write-Both "    [!] DC $($ADs | Where-Object {$_.OperationMasterRoles -ne $null} | select -ExpandProperty hostname) holds all FSMO roles!";
    }
    #DCs with weak Kerberos algorhythm (*CH* Changed below to look for msDS-SupportedEncryptionTypes to work with 2008R2)
    $ADcomputers = $ads | ForEach-Object {Get-ADComputer $_.Name -Properties msDS-SupportedEncryptionTypes};
    $WeakKerberos = $false;
    foreach($DC in $ADcomputers){# (*CH* Need to define all combinations here, only done 28 and 31 so far) (31 = "DES, RC4, AES128, AES256", 28 = "RC4, AES128, AES256")
        if( $DC."msDS-SupportedEncryptionTypes" -eq 28 -or $DC."msDS-SupportedEncryptionTypes" -eq 31 ){
            $WeakKerberos = $true;
            Add-Content -Path "$outputdir\dcs_weak_kerberos_ciphersuite.txt" -Value "$($DC.DNSHostName) $($dc."msDS-SupportedEncryptionTypes")";
        }
    }
    Write-Both "    [!] You have DCs with RC4 or DES allowed for Kerberos!!!";

}
function Get-DefaultDomainControllersPolicy{#Enumerates Default Domain Controllers Policy for default unsecure and excessive options
    $ExcessiveDCInteractiveLogon = $false;
    $ExcessiveDCBackupPermissions = $false;
    $ExcessiveDCRestorePermissions = $false;
    $ExcessiveDCDriverPermissions = $false;
    $ExcessiveDCLocalShutdownPermissions = $false;
    $ExcessiveDCRemoteShutdownPermissions = $false;
    $ExcessiveDCTimePermissions = $false;
    $ExcessiveDCBatchLogonPermissions = $false;
    $ExcessiveDCRDPLogonPermissions = $false;
    $GPO = Get-GPO 'Default Domain Controllers Policy';
    $GPOreport = Get-GPOReport -Guid $GPO.id -ReportType Xml;
    #Interactive local logon
    $permissionindex = $GPOreport.IndexOf('SeInteractiveLogonRight');
    if($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy'){
        $xmlreport = [xml]$GPOreport;
        foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeInteractiveLogonRight'}).member)){
            if($member.name.'#text' -ne 'BUILTIN\Administrators' -and $member.name.'#text' -ne 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'){
                $ExcessiveDCInteractiveLogon = $true;
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeInteractiveLogonRight $($member.name.'#text')";
            }
        }
    }
    #batch logon
    $permissionindex = $GPOreport.IndexOf('SeBatchLogonRight');
    if($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy'){
        $xmlreport = [xml]$GPOreport;
        foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeBatchLogonRight'}).member)){
            if($member.name.'#text' -ne 'BUILTIN\Administrators'){
                $ExcessiveDCBatchLogonPermissions = $true;
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeBatchLogonRight $($member.name.'#text')";
            }
        }
    }
    #RDP logon
    $permissionindex = $GPOreport.IndexOf('SeInteractiveLogonRight');
    if($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy'){
        $xmlreport = [xml]$GPOreport;
        foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeInteractiveLogonRight'}).member)){
            if($member.name.'#text' -ne 'BUILTIN\Administrators' -and $member.name.'#text' -ne 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'){
                $ExcessiveDCRDPLogonPermissions = $true;
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeInteractiveLogonRight $($member.name.'#text')";
            }
        }
    }
    #backup
    $permissionindex = $GPOreport.IndexOf('SeBackupPrivilege');
    if($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy'){
        $xmlreport = [xml]$GPOreport;
        foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeBackupPrivilege'}).member)){
            if($member.name.'#text' -ne 'BUILTIN\Administrators'){
                $ExcessiveDCBackupPermissions = $true;
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeBackupPrivilege $($member.name.'#text')";
            }
        }
    }
    #restore
    $permissionindex = $GPOreport.IndexOf('SeRestorePrivilege');
    if($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy'){
        $xmlreport = [xml]$GPOreport;
        foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeRestorePrivilege'}).member)){
            if($member.name.'#text' -ne 'BUILTIN\Administrators'){
                $ExcessiveDCRestorePermissions = $true;
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRestorePrivilege $($member.name.'#text')";
            }
        }
    }
    #load driver
    $permissionindex = $GPOreport.IndexOf('SeLoadDriverPrivilege');
    if($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy'){
        $xmlreport = [xml]$GPOreport;
        foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeLoadDriverPrivilege'}).member)){
            if($member.name.'#text' -ne 'BUILTIN\Administrators'){
                $ExcessiveDCDriverPermissions = $true;
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeLoadDriverPrivilege $($member.name.'#text')";
            }
        }
    }
    #local shutdown
    $permissionindex = $GPOreport.IndexOf('SeShutdownPrivilege');
    if($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy'){
        $xmlreport = [xml]$GPOreport;
        foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeShutdownPrivilege'}).member)){
            if($member.name.'#text' -ne 'BUILTIN\Administrators'){
                $ExcessiveDCLocalShutdownPermissions = $true;
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeShutdownPrivilege $($member.name.'#text')";
            }
        }
    }
    #remote shutdown
    $permissionindex = $GPOreport.IndexOf('SeRemoteShutdownPrivilege');
    if($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy'){
        $xmlreport = [xml]$GPOreport;
        foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeRemoteShutdownPrivilege'}).member)){
            if($member.name.'#text' -ne 'BUILTIN\Administrators'){
                $ExcessiveDCRemoteShutdownPermissions = $true;
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRemoteShutdownPrivilege $($member.name.'#text')";
            }
        }
    }
    #change time
    $permissionindex = $GPOreport.IndexOf('SeSystemTimePrivilege');
    if($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy'){
        $xmlreport = [xml]$GPOreport;
        foreach($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.name -eq 'SeSystemTimePrivilege'}).member)){
            if($member.name.'#text' -ne 'BUILTIN\Administrators' -and $member.name.'#text' -ne 'NT AUTHORITY\LOCAL SERVICE'){
                $ExcessiveDCTimePermissions = $true;
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeSystemTimePrivilege $($member.name.'#text')";
            }
        }
    }
    #Output for Default Domain Controllers Policy
    if($ExcessiveDCInteractiveLogon -or $ExcessiveDCBackupPermissions -or $ExcessiveDCRestorePermissions -or $ExcessiveDCDriverPermissions -or $ExcessiveDCLocalShutdownPermissions -or $ExcessiveDCRemoteShutdownPermissions -or $ExcessiveDCTimePermissions -or $ExcessiveDCBatchLogonPermissions -or $ExcessiveDCRDPLogonPermissions){
        Write-Both "    [!] Excessive permissions in Default Domain Controllers Policy detected!";
    }
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
if (Test-Path "$outputdir\adaudit.nessus") { Remove-Item -recurse "$outputdir\adaudit.nessus" | out-null }
Write-Nessus-Header
write-host "[+] Outputting to $outputdir"
if ($hostdetails -Or $all) { $running=$true; Write-Both "[*] Device Information" ; Get-HostDetails }
if ($domainaudit -Or $all) { $running=$true; Write-Both "[*] Domain Audit" ; Get-DCEval ; Get-PrivilegedGroupMembership ; Get-MachineAccountQuota; Get-DefaultDomainControllersPolicy ; Get-SMB1Support; Get-FunctionalLevel ; Get-DCsNotOwnedByDA }
if ($trusts -Or $all) { $running=$true; Write-Both "[*] Domain Trust Audit" ; Get-DomainTrusts }
if ($accounts -Or $all) { $running=$true; Write-Both "[*] Accounts Audit" ; Get-InactiveAccounts ; Get-DisabledAccounts ; Get-AdminAccountChecks ; Get-NULLSessions; Get-PrivilegedGroupAccounts; Get-ProtectedUsers }
if ($passwordpolicy -Or $all) { $running=$true; Write-Both "[*] Password Information Audit" ; Get-AccountPassDontExpire ; Get-UserPasswordNotChangedRecently; Get-PasswordPolicy }
if ($ntds -Or $all) { $running=$true; Write-Both "[*] Trying to save NTDS.dit, please wait..."; Get-NTDSdit }
if ($oldboxes -Or $all) { $running=$true; Write-Both "[*] Computer Objects Audit" ; Get-OldBoxes }
if ($gpo -Or $all) { $running=$true; Write-Both "[*] GPO audit (and checking SYSVOL for passwords)"  ; Get-GPOtoFile ; Get-GPOsPerOU ; Get-SYSVOLXMLS; Get-GPOEnum }
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
Write-Nessus-Footer

#Dirty fix for .nessus characters (will do this properly or as a function later. Will need more characters adding here...)
$originalnessusoutput = Get-Content $outputdir\adaudit.nessus
$nessusoutput = $originalnessusoutput -Replace "&", "&amp;"
$nessusoutput = $nessusoutput -Replace "`“", "&quot;"
$nessusoutput = $nessusoutput -Replace "`'", "&apos;"
$nessusoutput = $nessusoutput -Replace "ü", "u"
$nessusoutput | Out-File $outputdir\adaudit-replaced.nessus

$endtime = get-date
Write-Both "[*] Script end time $endtime"
