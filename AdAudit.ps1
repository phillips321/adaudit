<#
phillips321.co.uk ADAudit.ps1
Changlog:
    v1.1 - Fixed bug where SYSVOL research returns empty
    v1.0 - First release
ToDo:
  DCs not owned by Domain Admins: Get-ADComputer -server frunit.com -LDAPFilter "(&(objectCategory=computer)(|(primarygroupid=521)(primarygroupid=516)))" -properties name, ntsecuritydescriptor | select name,{$_.ntsecuritydescriptor.Owner}
#>
$versionnum = "v1.1"
$outputdir = (Get-Item -Path ".\").FullName + "\" + $env:computername
$starttime = get-date
if (!(Test-Path "$outputdir")) { New-Item -ItemType directory -Path $outputdir | out-null }

function Write-Both(){#writes to console screen and output file
    Write-Host "$args"; Add-Content -Path "$outputdir\consolelog.txt" -Value "$args"}

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
        if ($trust.TrustDirection -eq 2){Write-Both "    [!] The domain $($trust.Name) is trusted by us!" }
        if ($trust.TrustDirection -eq 3){Write-Both "    [!] Bidirectyional trust with domain $($trust.Name)!" }
    }
}

function Get-SMB1Support{#check if server supports SMBv1
    if (!(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters).SMB1 -eq 0){Write-Both "    [!] SMBv1 is not disabled"}
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
}

function Get-GPOtoHTML{#oututs complete GPO report
    if (Test-Path "$outputdir\GPOReport.html") { Remove-Item "$outputdir\GPOReport.html" -Recurse; }
    Get-GPOReport -All -ReportType HTML -Path "$outputdir\GPOReport.html"
    Write-Both "    [+] GPO Report saved to GPOReport.html"
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
function Get-InactiveAccounts{#lists accounts not used in past 180 days
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

function Get-DisabledAccounts{#lists disabled accounts
    $count = 0
    ForEach ($account in (Search-ADaccount -AccountInactive -Timespan 180 -UsersOnly)){
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
Write-Both "[*] Password Policy Findings" ; Get-PasswordPolicy ; Get-UserPasswordNotChangedRecently
Write-Both "[*] Looking for accounts that dont expire" ; Get-AccountPassDontExpire
Write-Both "[*] Looking for inactive/disabled accounts" ; Get-InactiveAccounts ; Get-DisabledAccounts
Write-Both "[*] Looking for server 2003/XP machines connected to domain" ; Get-OldBoxes
Write-Both "[*] AD Findings" ; Get-MachineAccountQuota ; Get-SMB1Support
Write-Both "[*] Domain Trust Findings" ; Get-DomainTrusts
Write-Both "[*] GPO Findings"  ; Get-GPOtoHTML ; Get-GPOsPerOU
Write-Both "[*] Trying to find SysVOL xml files containg cpassword..."; Get-SYSVOLXMLS
Write-Both "[*] Trying to save NTDS.dit, please wait..."; Get-NTDSdit
$endtime = get-date
Write-Both "[*] Script end time $endtime"
