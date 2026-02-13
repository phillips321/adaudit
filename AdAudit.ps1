<#
    .NOTES
        Author       : phillips321.co.uk
        Creation Date: 16/08/2018
        Script Name  : ADAudit.ps1
    .SYNOPSIS
        PowerShell Script to perform a quick AD audit
    .DESCRIPTION
        o Compatibility :
            * PowerShell v2.0 (PowerShell 5.0 needed if you intend to use DSInternals PowerShell module)
            * Tested on Windows Server 2008R2/2012/2012R2/2016/2019/2022
            * All languages (you may need to adjust $AdministratorTranslation variable)
        o Changelog :
            [x] Version 6.8 - 13/02/2026
                * Implemented proper XML special character escaping with dedicated Escape-XmlSpecialCharacters function
                * Updated Write-Nessus-Finding to escape all parameters (pluginname, pluginid, pluginexample) at source
                * Removed dirty post-processing code that created extra adaudit-replaced.nessus file
                * Nessus XML output now valid and properly formatted without post-processing
                * Handles all XML entities: &amp; &lt; &gt; &quot; &apos;
            [x] Version 6.7 - 13/02/2026
                * Added error handling to Get-GPOtoFile function for Get-GPOReport failures
                * Separated HTML and XML GPO report generation with independent try-catch blocks
                * Gracefully handles GPOReport ArgumentExceptions without blocking script execution
                * Improved error messaging for GPO report generation failures
            [x] Version 6.6 - 13/02/2026
                * Fixed Get-Variables() group retrieval with granular error handling per group
                * Schema Admins/Enterprise Admins now fail gracefully without blocking child domain groups
                * Domain Admins, Domain Users, and Domain Controllers now retrieved independently
                * Improved error messaging distinguishing forest root vs child domain scenarios
            [x] Version 6.5 - 13/02/2026
                * Fixed Schema Admins/Enterprise Admins lookup in child domains (they only exist in forest root)
                * Added defensive checks for null group variables in Get-PrivilegedGroupMembership
                * Added defensive checks for null group variables in Get-PrivilegedGroupAccounts
                * Fixed SPNs.txt file check to prevent error when no high-value kerberoastable accounts found
                * Improved error handling messages for child domain scenarios
            [x] Version 6.4 - 13/02/2026
                * Enhanced error handling throughout script with try-catch blocks
                * Improved Get-Variables() function with granular error handling for AD queries
                * Added error handling for module loading (ActiveDirectory, ServerManager, GroupPolicy)
                * Enhanced Install-Dependencies function with detailed error messages
                * Added error handling to Get-PasswordQuality and Get-ADCSVulns functions
                * Improved output directory creation with error messaging
                * Added validation check for script variable initialization
            [x] Version 6.3 - 07/11/2025
                * Force true anonymous bind: set AuthType=Anonymous and Credential=[NetworkCredential]::new($null,$null)
                * Use LdapDirectoryIdentifier($Server, $Port) instead of "$Server:$Port" string to avoid parsing quirks
                * Disable referral chasing to prevent OperationsError from referral handling (ReferralChasing=None)
                * Replace paged control with SizeLimit=1 and TimeLimit for a minimal, predictable read
                * Perform a real directory read under defaultNamingContext (not just RootDSE) to confirm effective anonymous access
                * Add precise result handling: Success vs InvalidCredentials (49) vs StrongerAuthRequired (8) vs OperationsError (1)
                * Coerce DC HostName to string using -ExpandProperty to fix ADPropertyValueCollection output
                * Minor robustness: ProtocolVersion=3, short timeouts, and safe Join-Path for output file
                * Fixed LDAPS certificate detection logic:
                   - Corrected EKU filtering to properly check for OID 1.3.6.1.5.5.7.3.1 (Server Authentication).
                   - Added validation for certificate expiry (NotAfter > current date).
                   - Added check to ensure certificate has a private key.
                * Added explicit success message for DSRM on DCs:
                   Prints "[+] Windows LAPS DSRM configuration on Domain Controllers looks OK..."
                   when DFL â‰¥ 2016 and all DCs have a DSRM secret backed up AND none are expired.
                * Introduced separate DC DSRM reports:
                   - winlaps_dcs_missing-dsrm.txt
                   - winlaps_dcs_expired-dsrm.txt
                  DC entries are also included in aggregate Windows LAPS files where appropriate.
                * DSRM checks gated by DFL â‰¥ 2016 per Microsoft guidance.
                * Fixed Windows LAPS rights export:
                   - Now binds -Identity explicitly for Find-LapsADExtendedRights.
                   - Prevents "Cannot bind argument to parameter 'Identity' ... empty array" errors.
                * Implemented DC-aware logic:
                   - Legacy LAPS checks (missing/expired) skip domain controllers (legacy LAPS doesn't apply to DCs).
                   - Windows LAPS distinguishes DC DSRM backups (msLAPS-EncryptedDSRMPassword) from non-DC backups
                    (msLAPS-Password / msLAPS-EncryptedPassword). Uses msLAPS-PasswordExpirationTime for expiry.
            [ ] Version 6.2 - 15/11/2024
                * Fixes for Get-Acl not working on Server 2016
                * Commented out section in Get-SPN that was taking forever to complete
            [ ] Version 6.1 - 26/02/2024
                * Added Server 2012 to End of Life list
            [ ] Version 6.0 - 22/12/2023
                * Fix "BUILTIN\$Administrators" quoting, in order to use $Administrators variable when script enumerates Default Domain Controllers Policy
                * Fix RDP logon policy check in the same function above
            [ ] Version 5.9 - 20/12/2023
                * Contempled all cases of DCs with weak Kerberos algorithm and saves finding according to them
                * Fix "Cannot get time source for DC" as a warning
            [ ] Version 5.8 - 27/03/2023
                * Updated switches, users can now select functions, or run -all with exclusions
                * Added LDAP security checks 
            [ ] Version 5.7 - 11/03/2023
                * Added ACL Checks
            [ ] Version 5.6 - 09/03/2023
                * Added kerberoasting checks
                * Added ASREProasting Checks
            [ ] Version 5.5 - 08/03/2023
                * ADCS vulnerabilities added, checks for ESC1,2,3,4 and 8.
            [ ] Version 5.4 - 16/08/2022
                * Added nessus output tags for LAPS
                * Added nessus output for GPO issues
            [ ] Version 5.3 - 07/03/2022
                * Added SamAccountName to Get-PrivilegedGroupMembership output
                * Swapped some write-host to write-both so it's captured in the consolelog.txt
            [ ] Version 5.2 - 28/01/2022
                * Enhanced Get-LAPSStatus
                * Added news checks (AD services + Windows Update + NTP source + Computer/User container + RODC + Locked accounts + Password Quality + SYSVOL & NETLOGON share presence)
                * Added support for WS 2022
                * Fix OS version difference check for WS 2008
                * Fix Write-Progress not disappearing when done
            [ ] Version 5.1
                * Added check for newly created users and groups
                * Added check for replication mechanism
                * Added check for Recycle Bin
                * Fix ProtectedUsers for WS 2008
            [ ] Version 5.0
                * Make the script compatible with other language than English
                * Fix the cpassword search in GPO
                * Fix Get-ACL bad syntax error
                * Fix Get-DNSZoneInsecure for WS 2008
            [ ] Version 4.9
                * Bug fix in checking password comlexity
            [ ] Version 4.8
                * Added checks for vista, win7 and 2008 old operating systems
                * Added insecure DNS zone checks
            [ ] Version 4.7
                * Added powershel-v2 suport and fixed array issue
            [ ] Version 4.6
                * Fixed potential division by zero
            [ ] Version 4.5
                * PR to resolve count issue when count = 1
            [ ] Version 4.4
                * Reinstated nessus fix and put output in a list for findings
                * Changed Get-AdminSDHolders with Get-PrivilegedGroupAccounts
            [ ] Version 4.3
                * Temp fix with nessus output
            [ ] Version 4.2
                * Bug fix on cpassword count
            [ ] Version 4.1
                * Loads of fixes
                * Works with Powershellv2 again now
                * Filtered out disabled accounts
                * Improved domain trusts checking
                * OUperms improvements and filtering
                * Check for w2k
                * Fixed typos/spelling and various other fixes
            [ ] Version 4.0
                * Added XML output for import to CheckSecCanopy
            [ ] Version 3.5
                * Added KB more references for internal use
            [ ] Version 3.4
                * Added KB references for internal use
            [ ] Version 3.3
                * Added a greater level of accuracy to Inactive Accounts (thanks exceedio)
            [ ] Version 3.2
                * Added search for DCs not owned by Domain Admins group
            [ ] Version 3.1
                * Added progress to functions that have count
                * Added check for transitive trusts
            [ ] Version 3.0
                * Added ability to choose functions before runtime
                * Cleaned up get-ouperms output
            [ ] Version 2.5
                * Bug fixes to version check for 2012R2 or greater specific checks
            [ ] Version 2.4
                * Forked project
                * Added Get-OUPerms, Get-LAPSStatus, Get-AdminSDHolders, Get-ProtectedUsers and Get-AuthenticationPoliciesAndSilos functions
                * Also added FineGrainedPasswordPolicies to Get-PasswordPolicy and changed order slightly
            [ ] Version 2.3
                * Added more useful user output to .txt files (Cheers DK)
            [ ] Version 2.2
                * Minor typo fix
            [ ] Version 2.1
                * Added check for null sessions
            [ ] Version 2.0
                * Multiple Additions and knocked off lots of the todo list
            [ ] Version 1.9
                * Fixed bug, that used Administrator account name instead of UID 500 and a bug with inactive accounts timespan
            [ ] Version 1.8
                * Added check for last time 'Administrator' account logged on
            [ ] Version 1.6
                * Added Get-FunctionalLevel and krbtgt password last changed check
            [ ] Version 1.5
                * Added Get-HostDetails to output simple info like username, hostname, etc...
            [ ] Version 1.4
                * Added Get-WinVersion version to assist with some checks (SMBv1 currently)
            [ ] Version 1.3
                * Added XML output for GPO (for offline processing using grouper https://github.com/l0ss/Grouper/blob/master/grouper.psm1)
            [ ] Version 1.2
                * Added check for modules
            [ ] Version 1.1
                * Fixed bug where SYSVOL research returns empty
            [ ] Version 1.0
                * First release
    .EXAMPLE
        PS> ADAudit.ps1 -installdeps -all
        Install external features and launch all checks
    .EXAMPLE
        PS> ADAudit.ps1 -all
        Launch all checks (but do not install external modules)
    .EXAMPLE
        PS> ADAudit.ps1 -installdeps
        Installs optionnal features (DSInternals)
    .EXAMPLE
        PS> ADAudit.ps1 -hostdetails -domainaudit
        Retrieves hostname and other useful audit info
        Retrieves information about the AD such as functional level
#>
[CmdletBinding()]
Param (
    [switch]$installdeps = $false,
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
    [switch]$insecurednszone = $false,
    [switch]$recentchanges = $false,
    [switch]$adcs = $false,
    [switch]$spn = $false,
    [switch]$asrep = $false,
    [switch]$acl = $false,
    [switch]$ldapsecurity = $false,
    [switch]$all = $false,
    [string[]]$exclude = @(),
    [string]$select
)

$selectedChecks = @()
if ($select) { $selectedChecks = $select.Split(',') }

$versionnum = "v6.8"
$AdministratorTranslation = @("Administrator", "Administrateur", "Administrador")#If missing put the default Administrator name for your own language here

Function Get-Variables() {
    #Retrieve group names and OS version
    try {
        $script:OSVersion = (Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName -ErrorAction Stop).ProductName
    } catch {
        Write-Both "    [!] Warning: Could not retrieve OS version from registry: $($_.Exception.Message)"
        $script:OSVersion = "Unknown"
    }

    try {
        $script:Administrators = (Get-ADGroup -Identity S-1-5-32-544 -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Administrators group: $($_.Exception.Message)"
        return
    }

    try {
        $script:Users = (Get-ADGroup -Identity S-1-5-32-545 -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Users group: $($_.Exception.Message)"
        return
    }

    try {
        $domainSID = (Get-ADDomain -Current LoggedOnUser -ErrorAction Stop).domainsid.value
        $script:DomainAdminsSID = $domainSID + "-512"
        $script:DomainUsersSID = $domainSID + "-513"
        $script:DomainControllersSID = $domainSID + "-516"
        $script:SchemaAdminsSID = $domainSID + "-518"
        $script:EnterpriseAdminsSID = $domainSID + "-519"
    } catch {
        Write-Both "    [!] Error: Failed to retrieve domain information: $($_.Exception.Message)"
        return
    }

    try {
        $script:EveryOneSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
        $script:EntrepriseDomainControllersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-9"
        $script:AuthenticatedUsersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-11"
        $script:SystemSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
        $script:LocalServiceSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-19"
    } catch {
        Write-Both "    [!] Error: Failed to create SID objects: $($_.Exception.Message)"
        return
    }

    try {
        $script:DomainAdmins = (Get-ADGroup -Identity $DomainAdminsSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Domain Admins group: $($_.Exception.Message)"
        return
    }

    try {
        $script:DomainUsers = (Get-ADGroup -Identity $DomainUsersSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Domain Users group: $($_.Exception.Message)"
        return
    }

    try {
        $script:DomainControllers = (Get-ADGroup -Identity $DomainControllersSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Domain Controllers group: $($_.Exception.Message)"
        return
    }

    # Schema Admins and Enterprise Admins only exist in forest root domain
    try {
        $script:SchemaAdmins = (Get-ADGroup -Identity $SchemaAdminsSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [i] Schema Admins not available in this domain (expected in child domains)"
        $script:SchemaAdmins = $null
    }

    try {
        $script:EnterpriseAdmins = (Get-ADGroup -Identity $EnterpriseAdminsSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [i] Enterprise Admins not available in this domain (expected in child domains)"
        $script:EnterpriseAdmins = $null
    }

    try {
        $script:EveryOne = $EveryOneSID.Translate([System.Security.Principal.NTAccount]).Value
        $script:EntrepriseDomainControllers = $EntrepriseDomainControllersSID.Translate([System.Security.Principal.NTAccount]).Value
        $script:AuthenticatedUsers = $AuthenticatedUsersSID.Translate([System.Security.Principal.NTAccount]).Value
        $script:System = $SystemSID.Translate([System.Security.Principal.NTAccount]).Value
        $script:LocalService = $LocalServiceSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        Write-Both "    [!] Error: Failed to translate SIDs to account names: $($_.Exception.Message)"
        return
    }
    Write-Both "    [+] Administrators               : $Administrators"
    Write-Both "    [+] Users                        : $Users"
    Write-Both "    [+] Domain Admins                : $DomainAdmins"
    Write-Both "    [+] Domain Users                 : $DomainUsers"
    Write-Both "    [+] Domain Controllers           : $DomainControllers"
    Write-Both "    [+] Schema Admins                : $SchemaAdmins"
    Write-Both "    [+] Enterprise Admins            : $EnterpriseAdmins"
    Write-Both "    [+] Everyone                     : $EveryOne"
    Write-Both "    [+] Entreprise Domain Controllers: $EntrepriseDomainControllers"
    Write-Both "    [+] Authenticated Users          : $AuthenticatedUsers"
    Write-Both "    [+] System                       : $System"
    Write-Both "    [+] Local Service                : $LocalService"
}
Function Write-Both() {
    #Writes to console screen and output file
    Write-Host "$args"
    Add-Content -Path "$outputdir\consolelog.txt" -Value "$args"
}
Function Write-Nessus-Header() {
    #Creates nessus XML file header
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<?xml version=`"1.0`" ?><AdAudit>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<Report name=`"$env:ComputerName`" xmlns:cm=`"http://www.nessus.org/cm`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportHost name=`"$env:ComputerName`"><HostProperties></HostProperties>"
}
Function Write-Nessus-Finding( [string]$pluginname, [string]$pluginid, [string]$pluginexample) {
    # Properly escape XML special characters in all parameters
    $escapedPluginName = Escape-XmlSpecialCharacters $pluginname
    $escapedPluginId = Escape-XmlSpecialCharacters $pluginid
    $escapedPluginExample = Escape-XmlSpecialCharacters $pluginexample

    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportItem port=`"0`" svc_name=`"`" protocol=`"`" severity=`"0`" pluginID=`"ADAudit_$escapedPluginId`" pluginName=`"$escapedPluginName`" pluginFamily=`"Windows`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<description>There's an issue with $escapedPluginName</description>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_type>remote</plugin_type><risk_factor>Low</risk_factor>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<solution>CCS Recommends fixing the issues with $escapedPluginName on the host</solution>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<synopsis>There's an issue with the $escapedPluginName settings on the host</synopsis>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_output>$escapedPluginExample</plugin_output></ReportItem>"
}
Function Write-Nessus-Footer() {
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "</ReportHost></Report></AdAudit>"
}
Function Escape-XmlSpecialCharacters {
    #Properly escapes XML special characters
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }

    $Value = $Value -replace '&', '&amp;'   # Must be FIRST to avoid double-escaping!
    $Value = $Value -replace '<', '&lt;'
    $Value = $Value -replace '>', '&gt;'
    $Value = $Value -replace '"', '&quot;'
    $Value = $Value -replace "'", '&apos;'

    return $Value
}
Function Get-DNSZoneInsecure {
    #Check DNS zones allowing insecure updates
    if ($OSVersion -notlike "Windows Server 2008*") {
        $count = 0
        $progresscount = 0
        $insecurezones = Get-DnsServerZone | Where-Object { $_.DynamicUpdate -like '*nonsecure*' }
        $totalcount = ($insecurezones | Measure-Object | Select-Object Count).count
        if ($totalcount -gt 0) {
            foreach ($insecurezone in $insecurezones ) {
                Add-Content -Path "$outputdir\insecure_dns_zones.txt" -Value "The DNS Zone $($insecurezone.ZoneName) allows insecure updates ($($insecurezone.DynamicUpdate))"
            }
            Write-Both "    [!] There were $totalcount DNS zones configured to allow insecure updates (KB842)"
            Write-Nessus-Finding "InsecureDNSZone" "KB842" ([System.IO.File]::ReadAllText("$outputdir\insecure_dns_zones.txt"))
        }
    }
    else {
        Write-Both "    [-] Not Windows 2012 or above, skipping Get-DNSZoneInsecure check."
    }
}
Function Get-OUPerms {
    #Check for non-standard perms for authenticated users, domain users, users and everyone groups
    $count = 0
    $progresscount = 0
    $objects = (Get-ADObject -Filter *)
    $totalcount = ($objects | Measure-Object | Select-Object Count).count
    foreach ($object in $objects) {
        if ($totalcount -eq 0) { break }
        $progresscount++
        Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
        if ($OSVersion -like "Windows Server 2019*" -or $OSVersion -like "Windows Server 2022*") {
            $output = (Get-Acl -Path "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$object").Access | Where-Object { ($_.IdentityReference -eq "$AuthenticatedUsers") -or ($_.IdentityReference -eq "$EveryOne") -or ($_.IdentityReference -like "*\$DomainUsers") -or ($_.IdentityReference -eq "BUILTIN\$Users") } | Where-Object { ($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny') }
        }
        else {
            $output = (Get-Acl AD:$object).Access                                                                    | Where-Object { ($_.IdentityReference -eq "$AuthenticatedUsers") -or ($_.IdentityReference -eq "$EveryOne") -or ($_.IdentityReference -like "*\$DomainUsers") -or ($_.IdentityReference -eq "BUILTIN\$Users") } | Where-Object { ($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny') }
        }
        if ($output -ne $null) {
            $count++
            Add-Content -Path "$outputdir\ou_permissions.txt" -Value "OU: $object"
            Add-Content -Path "$outputdir\ou_permissions.txt" -Value "[!] Rights: $($output.IdentityReference) $($output.ActiveDirectoryRights) $($output.AccessControlType)"
        }
    }
    Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] Issue identified, see $outputdir\ou_permissions.txt"
        Write-Nessus-Finding "OUPermissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\ou_permissions.txt"))
    }
}
function Get-LAPSStatus {

    # --- prerequisites & helpers -------------------------------------------------
    $ErrorActionPreference = 'Stop'

    try { Import-Module ActiveDirectory -ErrorAction Stop } catch {
        Write-Warning "ActiveDirectory module is required for LAPS checks."
        return
    }

    # Default $outputdir if not set by caller
    if (-not (Get-Variable -Name outputdir -ErrorAction SilentlyContinue)) {
        $script:outputdir = Join-Path $env:TEMP "laps-audit"
    }
    if (-not (Test-Path $outputdir)) { New-Item -ItemType Directory -Path $outputdir | Out-Null }

    # Helper: identify DCs using userAccountControl SERVER_TRUST_ACCOUNT (0x2000)
    function Test-IsDomainController {
        param(
            [Parameter(Mandatory)]
            [Microsoft.ActiveDirectory.Management.ADComputer]$Computer
        )
        $uac = 0
        if ($Computer.userAccountControl) { $uac = [int]$Computer.userAccountControl }
        if ( ($uac -band 0x2000) -ne 0 ) { return $true } else { return $false }
    }

    # Convenience
    $rootDse   = Get-ADRootDSE
    $dnConfig  = $rootDse.configurationNamingContext
    $schemaBase = "CN=Schema,$dnConfig"
    $forestDN  = (Get-ADDomain).DistinguishedName

    # Principals to ignore in rights exports
    $systemPrincipals = @('NT AUTHORITY\SYSTEM','SYSTEM','S-1-5-18')

    # --- schema detection ---------------------------------------------------------
    $legacyLapsSchemaPresent = $false
    $winLapsSchemaPresent    = $false

    try {
        # Legacy LAPS attributes exist?
        $legacyAttr = Get-ADObject -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)' -SearchBase $schemaBase -ErrorAction Stop
        $legacyExp  = Get-ADObject -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)' -SearchBase $schemaBase -ErrorAction Stop
        if ($legacyAttr -and $legacyExp) { $legacyLapsSchemaPresent = $true }
    } catch { }

    try {
        # Windows LAPS attributes exist?
        $winAttrPwd = Get-ADObject -LDAPFilter '(lDAPDisplayName=msLAPS-Password)' -SearchBase $schemaBase -ErrorAction Stop
        $winAttrExp = Get-ADObject -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' -SearchBase $schemaBase -ErrorAction Stop
        if ($winAttrPwd -and $winAttrExp) { $winLapsSchemaPresent = $true }
    } catch { }

    if ($legacyLapsSchemaPresent) { Write-Both "    [+] Legacy LAPS schema is present in the domain." }
    else {
        Write-Both "    [!] Legacy LAPS schema not found (AdmPwd)."
        Write-Nessus-Finding "LAPSMissing" "KB258" "Legacy LAPS schema not found in domain $forestDN"
    }

    if ($winLapsSchemaPresent) { Write-Both "    [+] Windows LAPS schema is present in the domain." }
    else {
        Write-Both "    [!] Windows LAPS schema not found."
        Write-Nessus-Finding "WindowsLAPSMissing" "KB258" "Windows LAPS schema not found in domain $forestDN"
    }

    if ($legacyLapsSchemaPresent -and -not $winLapsSchemaPresent) {
        Write-Both "    [>] Legacy LAPS is present but Windows LAPS is not. Recommendation: plan migration to Windows LAPS for encryption, DSRM support, and built-in management."
        Write-Nessus-Finding "LAPSUpgradeRecommended" "KB258" "Legacy LAPS present; Windows LAPS not detected. Recommend upgrading."
    }

    # --- determine if DSRM checks should be enforced on DCs ----------------------
    # DSRM password management requires DFL 2016+; otherwise skip DC DSRM 'missing' findings.
    $domainModeName = (Get-ADDomain).DomainMode.ToString()
    $dsrmSupported = $false
    if ($domainModeName -match '2016|2019|2022|2025') { $dsrmSupported = $true }  # coarse but effective

    if ($winLapsSchemaPresent -and -not $dsrmSupported) {
        Write-Both "    [i] Domain Functional Level is earlier than 2016; Windows LAPS DSRM management isn't supported. DCs will not be flagged for missing DSRM backup."
        Write-Nessus-Finding "WindowsLAPSDSRMNotSupported" "KB258" "DFL < 2016. DC DSRM backup via Windows LAPS isn't supported; skipping DC DSRM 'missing' findings."
    }

    # --- Legacy LAPS deep checks (if module available) ---------------------------
    if ($legacyLapsSchemaPresent) {
        if (Get-Module -ListAvailable -Name AdmPwd.PS) {
            Import-Module AdmPwd.PS -ErrorAction SilentlyContinue | Out-Null

            # Pull inventory with UAC to detect DCs
            $legacyAll = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime','userAccountControl'

            # Computers missing a legacy LAPS password (exclude DCs)
            $missingLegacyFile = Join-Path $outputdir 'legacy_laps_missing-computers.txt'
            Remove-Item $missingLegacyFile -ErrorAction SilentlyContinue
            $legacyMissing = $legacyAll |
                             Where-Object { -not (Test-IsDomainController -Computer $_) } |
                             Where-Object { -not $_.'ms-Mcs-AdmPwd' } |
                             Select-Object -ExpandProperty Name
            if ($legacyMissing) {
                $legacyMissing | Set-Content -Path $missingLegacyFile
                Write-Both  "    [!] Some computers/servers don't have a LEGACY LAPS password set, see $missingLegacyFile"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($missingLegacyFile))
            }

            # Expired legacy LAPS passwords (exclude DCs)
            $legacyExpiredFile = Join-Path $outputdir 'legacy_laps_expired-passwords.txt'
            Remove-Item $legacyExpiredFile -ErrorAction SilentlyContinue
            $now = Get-Date
            $legacyExpired = foreach ($c in $legacyAll) {
                if (Test-IsDomainController -Computer $c) { continue }
                $expRaw = $c.'ms-Mcs-AdmPwdExpirationTime'
                if ($expRaw) {
                    try {
                        $exp = [DateTime]::FromFileTime([Int64]$expRaw)
                        if ($exp -lt $now) { "{0} password expired since {1:u}" -f $c.Name, $exp }
                    } catch { }
                }
            }
            if ($legacyExpired) {
                $legacyExpired | Set-Content -Path $legacyExpiredFile
                Write-Both  "    [!] Some computers/servers have LEGACY LAPS password expired, see $legacyExpiredFile"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($legacyExpiredFile))
            }

            # Extended rights (legacy) - explicit -Identity
            $legacyRightsFile = Join-Path $outputdir 'legacy_laps_read-extendedrights.txt'
            Remove-Item $legacyRightsFile -ErrorAction SilentlyContinue
            $ous = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName |
                   Where-Object { $_.DistinguishedName -and $_.Name } |
                   Sort-Object DistinguishedName

            foreach ($ou in $ous) {
                try {
                    $res = Find-AdmPwdExtendedRights -Identity $ou.DistinguishedName -ErrorAction Stop
                    foreach ($holder in $res.ExtendedRightHolders) {
                        if ($systemPrincipals -notcontains $holder) {
                            "$holder can read LEGACY LAPS password attribute in $($ou.DistinguishedName)" |
                                Add-Content -Path $legacyRightsFile
                        }
                    }
                } catch { continue }
            }
            if (Test-Path $legacyRightsFile) {
                Write-Both  "    [!] LEGACY LAPS extended rights exported, see $legacyRightsFile"
                Write-Nessus-Finding "LAPSExtendedRights" "KB258" ([System.IO.File]::ReadAllText($legacyRightsFile))
            }

        } else {
            Write-Both "    [!] AdmPwd.PS module is not installed on this host; limited legacy LAPS checks only."
        }
    }

    # --- Windows LAPS deep checks (schema-based, module optional) ----------------
    if ($winLapsSchemaPresent) {
        $winMissingFile    = Join-Path $outputdir 'winlaps_missing-computers.txt'
        $winExpiredFile    = Join-Path $outputdir 'winlaps_expired-passwords.txt'
        $dcMissingDSRMFile = Join-Path $outputdir 'winlaps_dcs_missing-dsrm.txt'
        $dcExpiredDSRMFile = Join-Path $outputdir 'winlaps_dcs_expired-dsrm.txt'
        $winRightsFile     = Join-Path $outputdir 'winlaps_read-extendedrights.txt'
        Remove-Item $winMissingFile,$winExpiredFile,$winRightsFile,$dcMissingDSRMFile,$dcExpiredDSRMFile -ErrorAction SilentlyContinue

        # Pull all computers with Windows LAPS-related attributes (and UAC for DC detection)
        $props = @('msLAPS-Password','msLAPS-EncryptedPassword','msLAPS-PasswordExpirationTime','msLAPS-EncryptedDSRMPassword','userAccountControl')
        $allWin = Get-ADComputer -Filter * -Properties $props

        # Partition DCs vs non-DCs
        $dcComputers    = @()
        $nonDCComputers = @()
        foreach ($c in $allWin) {
            if (Test-IsDomainController -Computer $c) { $dcComputers += $c } else { $nonDCComputers += $c }
        }

        # ---- Non-DC missing Windows LAPS backup
        $nonDCMissing = $nonDCComputers | Where-Object {
            -not $_.'msLAPS-Password' -and -not $_.'msLAPS-EncryptedPassword'
        } | Select-Object -ExpandProperty Name

        # ---- DC missing DSRM backup (only when supported)
        $dcMissingDSRM = @()
        if ($dsrmSupported) {
            $dcMissingDSRM = $dcComputers | Where-Object {
                -not $_.'msLAPS-EncryptedDSRMPassword'
            } | Select-Object -ExpandProperty Name
        }

        # Combine for the aggregate "missing" file (non-DCs + DCs where supported)
        $aggregateMissing = @()
        if ($nonDCMissing) { $aggregateMissing += $nonDCMissing }
        if ($dcMissingDSRM) { $aggregateMissing += $dcMissingDSRM }

        if ($aggregateMissing) {
            $aggregateMissing | Set-Content -Path $winMissingFile
            Write-Both  "    [!] Some computers/servers don't have a WINDOWS LAPS password backed up (or DSRM on DCs where supported), see $winMissingFile"
            Write-Nessus-Finding "WindowsLAPSMissingOrNotBackedUp" "KB258" ([System.IO.File]::ReadAllText($winMissingFile))
        }

        # Write DC-specific missing file if applicable
        if ($dcMissingDSRM) {
            $dcMissingDSRM | Set-Content -Path $dcMissingDSRMFile
            Write-Both  "    [!] Domain Controllers missing DSRM backup via Windows LAPS: see $dcMissingDSRMFile"
            Write-Nessus-Finding "WindowsLAPSDSRMissing" "KB258" ([System.IO.File]::ReadAllText($dcMissingDSRMFile))
        }

        # ---- Expired (both DC and non-DC share the same expiration attribute)
        $now = Get-Date

        $nonDCExpiredLines = foreach ($c in $nonDCComputers) {
            $expRaw = $c.'msLAPS-PasswordExpirationTime'
            if ($expRaw) {
                try {
                    $exp = [DateTime]::FromFileTime([Int64]$expRaw)
                    if ($exp -lt $now) { "{0} password expired since {1:u}" -f $c.Name, $exp }
                } catch { }
            }
        }

        $dcExpiredDSRMLines = @()
        if ($dsrmSupported) {
            $dcExpiredDSRMLines = foreach ($c in $dcComputers) {
                $expRaw = $c.'msLAPS-PasswordExpirationTime'
                if ($expRaw) {
                    try {
                        $exp = [DateTime]::FromFileTime([Int64]$expRaw)
                        if ($exp -lt $now) { "{0} DSRM password expired since {1:u}" -f $c.Name, $exp }
                    } catch { }
                }
            }
        }

        # Aggregate expired
        $aggregateExpired = @()
        if ($nonDCExpiredLines) { $aggregateExpired += $nonDCExpiredLines }
        if ($dcExpiredDSRMLines) { $aggregateExpired += $dcExpiredDSRMLines }

        if ($aggregateExpired) {
            $aggregateExpired | Set-Content -Path $winExpiredFile
            Write-Both  "    [!] Some computers/servers have WINDOWS LAPS password expired (or DSRM on DCs), see $winExpiredFile"
            Write-Nessus-Finding "WindowsLAPSMissingOrExpired" "KB258" ([System.IO.File]::ReadAllText($winExpiredFile))
        }

        # DC-specific expired DSRM file
        if ($dcExpiredDSRMLines) {
            $dcExpiredDSRMLines | Set-Content -Path $dcExpiredDSRMFile
            Write-Both  "    [!] Domain Controllers with EXPIRED DSRM secret: see $dcExpiredDSRMFile"
            Write-Nessus-Finding "WindowsLAPSDSRMExpired" "KB258" ([System.IO.File]::ReadAllText($dcExpiredDSRMFile))
        }

        # --- NEW: Positive confirmation for DSRM status on DCs -------------------
        if ($dsrmSupported) {
            # If there were no DCs missing DSRM and none expired, report OK
            $allDCsHaveDSRM = ($dcComputers.Count -gt 0) -and (-not $dcMissingDSRM -or $dcMissingDSRM.Count -eq 0)
            $noDCExpired    = (-not $dcExpiredDSRMLines -or $dcExpiredDSRMLines.Count -eq 0)

            if ($allDCsHaveDSRM -and $noDCExpired) {
                Write-Both "    [+] Windows LAPS DSRM configuration on Domain Controllers looks OK (all DCs have DSRM secret backed up, none expired)."
            }
        } else {
            Write-Both "    [i] DSRM checks skipped (Domain Functional Level < 2016). See Microsoft guidance: DSRM management requires DFL 2016 or later."
        }

        # Extended rights (Windows LAPS) - explicit -Identity
        if (Get-Module -ListAvailable -Name LAPS) {
            Import-Module LAPS -ErrorAction SilentlyContinue | Out-Null

            $ous = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName |
                   Where-Object { $_.DistinguishedName -and $_.Name } |
                   Sort-Object DistinguishedName

            foreach ($ou in $ous) {
                try {
                    $result = Find-LapsADExtendedRights -Identity $ou.DistinguishedName -ErrorAction Stop
                    if ($result -and $result.ExtendedRightHolders) {
                        foreach ($holder in $result.ExtendedRightHolders) {
                            if ($systemPrincipals -notcontains $holder) {
                                "$holder can read WINDOWS LAPS password info in $($ou.DistinguishedName)" |
                                    Add-Content -Path $winRightsFile
                            }
                        }
                    }
                } catch { continue }
            }

            if (Test-Path $winRightsFile) {
                Write-Both  "    [!] WINDOWS LAPS extended rights exported, see $winRightsFile"
                Write-Nessus-Finding "WindowsLAPSExtendedRights" "KB258" ([System.IO.File]::ReadAllText($winRightsFile))
            } else {
                Write-Both "    [+] No non-system extended rights discovered for Windows LAPS password read on any OU."
            }
        } else {
            Write-Both "    [!] LAPS module not found; skipping Windows LAPS extended rights export. (Import the builtâ€‘in 'LAPS' module on this host to enable.)"
        }
    }

    Write-Both "    [+] LAPS checks complete."
}
Function Get-PrivilegedGroupAccounts {
    #Lists users in Admininstrators, DA and EA groups
    [array]$privilegedusers = @()

    try {
        $privilegedusers += Get-ADGroupMember $Administrators -Recursive -ErrorAction Stop
    } catch {
        Write-Both "    [!] Warning: Could not retrieve Administrators group members: $($_.Exception.Message)"
    }

    try {
        $privilegedusers += Get-ADGroupMember $DomainAdmins -Recursive -ErrorAction Stop
    } catch {
        Write-Both "    [!] Warning: Could not retrieve Domain Admins members: $($_.Exception.Message)"
    }

    # Enterprise Admins only exists in forest root domain
    if ($EnterpriseAdmins) {
        try {
            $privilegedusers += Get-ADGroupMember $EnterpriseAdmins -Recursive -ErrorAction Stop
        } catch {
            Write-Both "    [i] Enterprise Admins not available (child domain)"
        }
    }

    $privusersunique = $privilegedusers | Sort-Object -Unique
    $count = 0
    $totalcount = ($privilegedusers | Measure-Object | Select-Object Count).count
    foreach ($account in $privusersunique) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\accounts_userPrivileged.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts in privileged groups, see accounts_userPrivileged.txt (KB426)"
        Write-Nessus-Finding "AdminSDHolders" "KB426" ([System.IO.File]::ReadAllText("$outputdir\accounts_userPrivileged.txt"))
    }
}
Function Get-ProtectedUsers {
    #Lists users in "Protected Users" group (2012R2 and above)
    $DomainLevel = (Get-ADDomain).domainMode
    if ($DomainLevel -eq "Windows2012Domain" -or $DomainLevel -eq "Windows2012R2Domain" -or $DomainLevel -eq "Windows2016Domain") {
        #Checking for 2012 or above domain functional level
        $ProtectedUsersSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-525"
        $ProtectedUsers = (Get-ADGroup -Identity $ProtectedUsersSID).SamAccountName
        $count = 0
        $protectedaccounts = (Get-ADGroup $ProtectedUsers -Properties members).Members
        $totalcount = ($protectedaccounts | Measure-Object | Select-Object Count).count
        foreach ($members in $protectedaccounts) {
            if ($totalcount -eq 0) { break }
            Write-Progress -Activity "Searching for protected users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
            $account = Get-ADObject $members -Properties SamAccountName
            Add-Content -Path "$outputdir\accounts_protectedusers.txt" -Value "$($account.SamAccountName) ($($account.Name))"
            $count++
        }
        Write-Progress -Activity "Searching for protected users..." -Status "Ready" -Completed
        if ($count -gt 0) {
            Write-Both "    [!] There are $count accounts in the 'Protected Users' group, see accounts_protectedusers.txt"
            Write-Nessus-Finding "ProtectedUsers" "KB549" ([System.IO.File]::ReadAllText("$outputdir\accounts_protectedusers.txt"))
        }
    }
    else { Write-Both "    [-] Not Windows 2012 Domain Functional level or above, skipping Get-ProtectedUsers check." }
}
Function Get-AuthenticationPoliciesAndSilos {
    #Lists any authentication policies and silos (2012R2 and above)
    if ([single](Get-WinVersion) -ge [single]6.3) {
        #NT6.2 or greater detected so running this script
        $count = 0
        foreach ($policy in Get-ADAuthenticationPolicy -Filter *) {
            Write-Both "    [!] Found $policy Authentication Policy"
            $count++
        }
        if ($count -lt 1) {
            Write-Both "    [!] There were no AD Authentication Policies found in the domain"
        }
        $count = 0
        foreach ($policysilo in Get-ADAuthenticationPolicySilo -Filter *) {
            Write-Both "    [!] Found $policysilo Authentication Policy Silo"
            $count++
        }
        if ($count -lt 1) {
            Write-Both "    [!] There were no AD Authentication Policy Silos found in the domain"
        }
    }
}
Function Get-MachineAccountQuota {
    #Get number of machines a user can add to a domain
    $MachineAccountQuota = (Get-ADDomain | select -ExpandProperty DistinguishedName | Get-ADObject -Property 'ms-DS-MachineAccountQuota' | select -ExpandProperty ms-DS-MachineAccountQuota)
    if ($MachineAccountQuota -gt 0) {
        Write-Both "    [!] Domain users can add $MachineAccountQuota devices to the domain! (KB251)"
        Write-Nessus-Finding "DomainAccountQuota" "KB251" "Domain users can add $MachineAccountQuota devices to the domain"
    }
}
Function Get-PasswordPolicy {
    Write-Both "    [+] Checking default password policy"
    if (!(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled) {
        Write-Both "    [!] Password Complexity not enabled (KB262)"
        Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold -lt 5) {
        Write-Both "    [!] Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold) (KB263)"
        Write-Nessus-Finding "LockoutThreshold" "KB263" "Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold)"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength -lt 14) {
        Write-Both "    [!] Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength) (KB262)"
        Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled) {
        Write-Both "    [!] Reversible encryption is enabled"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge -eq "00:00:00") {
        Write-Both "    [!] Passwords do not expire (KB254)"
        Write-Nessus-Finding "PasswordsDoNotExpire" "KB254" "Passwords do not expire"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount -lt 12) {
        Write-Both "    [!] Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount) (KB262)"
        Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).NoLmHash -eq 0) {
        Write-Both "    [!] LM Hashes are stored! (KB510)"
        Write-Nessus-Finding "LMHashesAreStored" "KB510" "LM Hashes are stored"
    }
    Write-Both "    [-] Finished checking default password policy"
    Write-Both "    [+] Checking fine-grained password policies if they exist"
    foreach ($finegrainedpolicy in Get-ADFineGrainedPasswordPolicy -Filter *) {
        $finegrainedpolicyappliesto = $finegrainedpolicy.AppliesTo
        Write-Both "    [!] Policy: $finegrainedpolicy"
        Write-Both "    [!] AppliesTo: $($finegrainedpolicyappliesto)"
        if (!($finegrainedpolicy).PasswordComplexity) {
            Write-Both "    [!] Password Complexity not enabled (KB262)"
            Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled for $finegrainedpolicy"
        }
        if (($finegrainedpolicy).LockoutThreshold -lt 5) {
            Write-Both "    [!] Lockout threshold is less than 5, currently set to $($finegrainedpolicy).LockoutThreshold) (KB263)"
            Write-Nessus-Finding "LockoutThreshold" "KB263" " Lockout threshold for $finegrainedpolicy is less than 5, currently set to $(($finegrainedpolicy).LockoutThreshold)"
        }
        if (($finegrainedpolicy).MinPasswordLength -lt 14) {
            Write-Both "    [!] Minimum password length is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength) (KB262)"
            Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length for $finegrainedpolicy is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength)"
        }
        if (($finegrainedpolicy).ReversibleEncryptionEnabled) {
            Write-Both "    [!] Reversible encryption is enabled"
        }
        if (($finegrainedpolicy).MaxPasswordAge -eq "00:00:00") {
            Write-Both "    [!] Passwords do not expire (KB254)"
        }
        if (($finegrainedpolicy).PasswordHistoryCount -lt 12) {
            Write-Both "    [!] Passwords history is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount) (KB262)"
            Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history for $finegrainedpolicy is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount)"
        }
    }
    Write-Both "    [-] Finished checking fine-grained password policy"
}
Function Get-NULLSessions {
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymous -eq 0) {
        Write-Both "    [!] RestrictAnonymous is set to 0! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymousSam -eq 0) {
        Write-Both "    [!] RestrictAnonymousSam is set to 0! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).everyoneincludesanonymous -eq 1) {
        Write-Both "    [!] EveryoneIncludesAnonymous is set to 1! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" "EveryoneIncludesAnonymous is set to 1"
    }
}
Function Get-DomainTrusts {
    #Lists domain trusts if they are bad
    foreach ($trust in (Get-ADObject -Filter { objectClass -eq "trustedDomain" } -Properties TrustPartner, TrustDirection, trustType, trustAttributes)) {
        if ($trust.TrustDirection -eq 2) {
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4) {
                #1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."
            }
            else {
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"
            }
        }
        if ($trust.TrustDirection -eq 3) {
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4) {
                #1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."
            }
            else {
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"
            }
        }
    }
}
Function Get-WinVersion {
    $WinVersion = [single]([string][environment]::OSVersion.Version.Major + "." + [string][environment]::OSVersion.Version.Minor)
    return [single]$WinVersion
}
Function Get-SMB1Support {
    #Check if server supports SMBv1
    if ([single](Get-WinVersion) -le [single]6.1) {
        #NT6.1 or less detected so checking reg key
        if (!(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters).SMB1 -eq 0) {
            Write-Both "    [!] SMBv1 is not disabled (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
    elseif ([single](Get-WinVersion) -ge [single]6.2) {
        #NT6.2 or greater detected so using powershell function
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {
            Write-Both "    [!] SMBv1 is enabled! (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
}
Function Get-UserPasswordNotChangedRecently {
    #Reports users that haven't changed passwords in more than 90 days
    $count = 0
    $DaysAgo = (Get-Date).AddDays(-90)
    $accountsoldpasswords = Get-ADUser -Filter { PwdLastSet -lt $DaysAgo -and Enabled -eq "true" } -Properties PasswordLastSet
    $totalcount = ($accountsoldpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $accountsoldpasswords) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
        if ($account.PasswordLastSet) {
            $datelastchanged = $account.PasswordLastSet
        }
        else {
            $datelastchanged = "Never"
        }
        Add-Content -Path "$outputdir\accounts_with_old_passwords.txt" -Value "User $($account.SamAccountName) ($($account.Name)) has not changed their password since $datelastchanged"
        $count++
    }
    Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count accounts with passwords older than 90days, see accounts_with_old_passwords.txt (KB550)"
        Write-Nessus-Finding "AccountsWithOldPasswords" "KB550" ([System.IO.File]::ReadAllText("$outputdir\accounts_with_old_passwords.txt"))
    }
    $krbtgtPasswordDate = (Get-ADUser -Filter { SamAccountName -eq "krbtgt" } -Properties PasswordLastSet).PasswordLastSet
    if ($krbtgtPasswordDate -lt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] krbtgt password not changed since $krbtgtPasswordDate! (KB253)"
        Write-Nessus-Finding "krbtgtPasswordNotChanged" "KB253" "krbtgt password not changed since $krbtgtPasswordDate"
    }
}
Function Get-GPOtoFile {
    #Outputs complete GPO report
    try {
        if (Test-Path "$outputdir\GPOReport.html") { Remove-Item "$outputdir\GPOReport.html" -Recurse -ErrorAction Stop }
        Get-GPOReport -All -ReportType HTML -Path "$outputdir\GPOReport.html" -ErrorAction Stop
        Write-Both "    [+] GPO Report saved to GPOReport.html"
    } catch {
        Write-Both "    [!] Warning: Error generating GPO HTML report: $($_.Exception.Message)"
    }

    try {
        if (Test-Path "$outputdir\GPOReport.xml") { Remove-Item "$outputdir\GPOReport.xml" -Recurse -ErrorAction Stop }
        Get-GPOReport -All -ReportType XML -Path "$outputdir\GPOReport.xml" -ErrorAction Stop
        Write-Both "    [+] GPO Report saved to GPOReport.xml, now run Grouper offline using the following command (KB499)"
        Write-Both "    [+]     PS>Import-Module Grouper.psm1 ; Invoke-AuditGPOReport -Path C:\GPOReport.xml -Level 3"
    } catch {
        Write-Both "    [!] Warning: Error generating GPO XML report: $($_.Exception.Message)"
    }
}
Function Get-GPOsPerOU {
    #Lists all OUs and which GPOs apply to them
    $count = 0
    $ousgpos = @(Get-ADOrganizationalUnit -Filter *)
    $totalcount = ($ousgpos | Measure-Object | Select-Object Count).count
    foreach ($ouobject in $ousgpos) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Currently identifed $count OUs" -PercentComplete ($count / $totalcount * 100)
        $combinedgpos = ($(((Get-GPInheritance -Target $ouobject).InheritedGpoLinks) | select DisplayName) | ForEach-Object { $_.DisplayName }) -join ','
        Add-Content -Path "$outputdir\ous_inheritedGPOs.txt" -Value "$($ouobject.Name) Inherits these GPOs: $combinedgpos"
        $count++
    }
    Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Ready" -Completed
    Write-Both "    [+] Inherited GPOs saved to ous_inheritedGPOs.txt"
}
Function Get-NTDSdit {
    #Dumps NTDS.dit, SYSTEM and SAM for password cracking
    if (Test-Path "$outputdir\ntds.dit") { Remove-Item "$outputdir\ntds.dit" -Recurse }
    $outputdirntds = '\"' + $outputdir + '\ntds.dit\"'
    $command = "ntdsutil `"ac in ntds`" `"ifm`" `"cr fu $outputdirntds `" q q"
    $hide = cmd.exe /c "$command" 2>&1
    Write-Both "    [+] NTDS.dit, SYSTEM & SAM saved to output folder"
    Write-Both "    [+] Use secretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL -outputfile customer"
}
Function Get-SYSVOLXMLS {
    #Finds XML files in SYSVOL (thanks --> https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
    $XMLFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml'
    $count = 0
    if ($XMLFiles) {
        $progresscount = 0
        $totalcount = ($XMLFiles | Measure-Object | Select-Object Count).count
        foreach ($File in $XMLFiles) {
            if ($totalcount -eq 0) { break }
            $progresscount++
            Write-Progress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Currently searched through $count" -PercentComplete ($progresscount / $totalcount * 100)
            $Filename = Split-Path $File -Leaf
            $Distinguishedname = (Split-Path (Split-Path (Split-Path( Split-Path (Split-Path $File -Parent) -Parent ) -Parent ) -Parent) -Leaf).Substring(1).TrimEnd('}')
            [xml]$Xml = Get-Content ($File)
            if ($Xml.innerxml -like "*cpassword*" -and $Xml.innerxml -notlike '*cpassword=""*') {
                if (!(Test-Path "$outputdir\sysvol")) { New-Item -ItemType Directory -Path "$outputdir\sysvol" | Out-Null }
                Write-Both "    [!] cpassword found in file, copying to output folder (KB329)"
                Write-Both "        $File"
                Copy-Item -Path $File -Destination $outputdir\sysvol\$Distinguishedname.$Filename
                $count++
            }
        }
        Write-Progress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Ready" -Completed
    }
    if ($count -eq 0) {
        Write-Both "    ...cpassword not found in the $($XMLFiles.count) XML files found."
    }
    else {
        $GPOxml = (Get-Content "$outputdir\sysvol\*.xml" -ErrorAction SilentlyContinue)
        $GPOxml = $GPOxml -Replace "<", "&lt;"
        $GPOxml = $GPOxml -Replace ">", "&gt;"
        Write-Nessus-Finding "GPOPasswordStorage" "KB329" "$GPOxml"
    }
}
Function Get-InactiveAccounts {
    #Lists accounts not used in past 180 days plus some checks for admin accounts
    $count = 0
    $progresscount = 0
    $inactiveaccounts = Search-ADaccount -AccountInactive -Timespan (New-TimeSpan -Days 180) -UsersOnly | Where-Object { $_.Enabled -eq $true }
    $totalcount = ($inactiveaccounts | Measure-Object | Select-Object Count).count
    foreach ($account in $inactiveaccounts) {
        if ($totalcount -eq 0) { break }
        $progresscount++
        Write-Progress -Activity "Searching for inactive users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
        if ($account.Enabled) {
            if ($account.LastLogonDate) {
                $userlastused = $account.LastLogonDate
            }
            else {
                $userlastused = "Never"
            }
            Add-Content -Path "$outputdir\accounts_inactive.txt" -Value "User $($account.SamAccountName) ($($account.Name)) has not logged on since $userlastused"
            $count++
        }
    }
    Write-Progress -Activity "Searching for inactive users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count inactive user accounts(180days), see accounts_inactive.txt (KB500)"
        Write-Nessus-Finding "InactiveAccounts" "KB500" ([System.IO.File]::ReadAllText("$outputdir\accounts_inactive.txt"))
    }
}
Function Get-AdminAccountChecks {
    #Checks if Administrator account has been renamed, replaced and is no longer used.
    $AdministratorSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-500"
    $AdministratorSAMAccountName = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties SamAccountName).SamAccountName
    $AdministratorName = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties SamAccountName).Name
    if ($AdministratorTranslation -contains $AdministratorSAMAccountName) {
        Write-Both "    [!] Local Administrator account (UID500) has not been renamed (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Administrator account (UID500) has not been renamed"
    }
    else {
        $count = 0
        foreach ($AdminName in $AdministratorTranslation) {
            if ((Get-ADUser -Filter { SamAccountName -eq $AdminName })) { $count++ }
        }
        if ($count -eq 0) {
            Write-Both "    [!] Local Administrator account renamed to $AdministratorSAMAccountName ($($AdministratorName)), but a dummy account not made in it's place! (KB309)"
            Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Admin account renamed to $AdministratorSAMAccountName ($($AdministratorName)), but a dummy account not made in it's place"
        }
    }
    $AdministratorLastLogonDate = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties LastLogonDate).LastLogonDate
    if ($AdministratorLastLogonDate -gt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] UID500 (LocalAdministrator) account is still used, last used $AdministratorLastLogonDate! (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "UID500 (LocalAdmini) account is still used, last used $AdministratorLastLogonDate"
    }
}
Function Get-DisabledAccounts {
    #Lists disabled accounts
    $disabledaccounts = Search-ADaccount -AccountDisabled -UsersOnly
    $count = 0
    $totalcount = ($disabledaccounts | Measure-Object | Select-Object Count).count
    foreach ($account in $disabledaccounts) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for disabled users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\accounts_disabled.txt" -Value "Account $($account.SamAccountName) ($($account.Name)) is disabled"
        $count++
    }
    Write-Progress -Activity "Searching for disabled users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count disabled user accounts, see accounts_disabled.txt (KB501)"
        Write-Nessus-Finding "DisabledAccounts" "KB501" ([System.IO.File]::ReadAllText("$outputdir\accounts_disabled.txt"))
    }
}
Function Get-LockedAccounts {
    #Lists locked accounts
    $lockedAccounts = Get-ADUser -Filter * -Properties LockedOut | Where-Object { $_.LockedOut -eq $true }
    $count = 0
    $totalcount = ($lockedAccounts | Measure-Object | Select-Object Count).Count
    foreach ($account in $lockedAccounts) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for locked users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\accounts_locked.txt" -Value "Account $($account.SamAccountName) ($($account.Name)) is locked"
        $count++
    }
    Write-Progress -Activity "Searching for locked users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count locked user accounts, see accounts_locked.txt"
    }
}
Function Get-AccountPassDontExpire {
    #Lists accounts who's passwords dont expire
    $count = 0
    $nonexpiringpasswords = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object { $_.Enabled -eq $true }
    $totalcount = ($nonexpiringpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $nonexpiringpasswords) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\accounts_passdontexpire.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts that don't expire, see accounts_passdontexpire.txt (KB254)"
        Write-Nessus-Finding "AccountsThatDontExpire" "KB254" ([System.IO.File]::ReadAllText("$outputdir\accounts_passdontexpire.txt"))
    }
}
Function Get-OldBoxes {
    #Lists 2000/2003/XP/Vista/7/2008 machines
    $count = 0
    $oldboxes = Get-ADComputer -Filter { OperatingSystem -Like "*2003*" -and Enabled -eq "true" -or OperatingSystem -Like "*XP*" -and Enabled -eq "true" -or OperatingSystem -Like "*2000*" -and Enabled -eq "true" -or OperatingSystem -like '*Windows 7*' -and Enabled -eq "true" -or OperatingSystem -like '*vista*' -and Enabled -eq "true" -or OperatingSystem -like '*2008*' -and Enabled -eq "true" -or OperatingSystem -like '*2012*' -and Enabled -eq "true"} -Property OperatingSystem
    $totalcount = ($oldboxes | Measure-Object | Select-Object Count).count
    foreach ($machine in $oldboxes) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for 2000/2003/XP/Vista/7/2008 devices joined to the domain..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\machines_old.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address)"
        $count++
    }
    Write-Progress -Activity "Searching for 2000/2003/XP/Vista/7/2008 devices joined to the domain..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] We found $count machines running 2000/2003/XP/Vista/7/2008! see machines_old.txt (KB3/37/38/KB259)"
        Write-Nessus-Finding "OldBoxes" "KB259" ([System.IO.File]::ReadAllText("$outputdir\machines_old.txt"))
    }
}
Function Get-DCsNotOwnedByDA {
    #Searches for DC objects not owned by the Domain Admins group
    $count = 0
    $progresscount = 0
    $domaincontrollers = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } -Property *
    $totalcount = ($domaincontrollers | Measure-Object | Select-Object Count).count
    if ($totalcount -gt 0) {
        foreach ($machine in $domaincontrollers) {
            $progresscount++
            Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
            if ($machine.ntsecuritydescriptor.Owner -ne "$env:UserDomain\$DomainAdmins") {
                Add-Content -Path "$outputdir\dcs_not_owned_by_da.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address), owned by $($machine.ntsecuritydescriptor.Owner)"
                $count++
            }
        }
        Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Ready" -Completed
    }
    if ($count -gt 0) {
        Write-Both "    [!] We found $count DCs not owned by Domains Admins group! see dcs_not_owned_by_da.txt"
        Write-Nessus-Finding "DCsNotByDA" "KB547" ([System.IO.File]::ReadAllText("$outputdir\dcs_not_owned_by_da.txt"))
    }
}
Function Get-HostDetails {
    #Gets basic information about the host
    Write-Both "    [+] Device Name:  $env:ComputerName"
    Write-Both "    [+] Domain Name:  $env:UserDomain"
    Write-Both "    [+] User Name  :  $env:UserName"
    Write-Both "    [+] NT Version :  $(Get-WinVersion)"
    $IPAddresses = [net.dns]::GetHostAddresses("") | select -ExpandProperty IP*
    foreach ($ip in $IPAddresses) {
        if ($ip -ne "::1") {
            Write-Both "    [+] IP Address :  $ip"
        }
    }
}
Function Get-FunctionalLevel {
    #Gets the functional level for domain and forest
    $DomainLevel = (Get-ADDomain).domainMode
    if ($DomainLevel -eq "Windows2000Domain" -and [single](Get-WinVersion) -gt 5.0) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2003InterimDomain" -and [single](Get-WinVersion) -gt 5.1) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2003Domain" -and [single](Get-WinVersion) -gt 5.2) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2008Domain" -and [single](Get-WinVersion) -gt 6.0) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2008R2Domain" -and [single](Get-WinVersion) -gt 6.1) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2012Domain" -and [single](Get-WinVersion) -gt 6.2) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2012R2Domain" -and [single](Get-WinVersion) -gt 6.3) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2016Domain" -and [single](Get-WinVersion) -gt 10.0) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    $ForestLevel = (Get-ADForest).ForestMode
    if ($ForestLevel -eq "Windows2000Forest" -and [single](Get-WinVersion) -gt 5.0) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2003InterimForest" -and [single](Get-WinVersion) -gt 5.1) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2003Forest" -and [single](Get-WinVersion) -gt 5.2) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2008Forest" -and [single](Get-WinVersion) -gt 6.0) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2008R2Forest" -and [single](Get-WinVersion) -gt 6.1) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2012Forest" -and [single](Get-WinVersion) -gt 6.2) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2012R2Forest" -and [single](Get-WinVersion) -gt 6.3) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2016Forest" -and [single](Get-WinVersion) -gt 10.0) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
}
Function Get-GPOEnum {
    #Loops GPOs for some important domain-wide settings
    $AllowedJoin = @()
    $HardenNTLM = @()
    $DenyNTLM = @()
    $AuditNTLM = @()
    $NTLMAuthExceptions = @()
    $EncryptionTypesNotConfigured = $true
    $AdminLocalLogonAllowed = $true
    $AdminRPDLogonAllowed = $true
    $AdminNetworkLogonAllowed = $true
    $AllGPOs = Get-GPO -All | sort DisplayName
    foreach ($GPO in $AllGPOs) {
        $GPOreport = Get-GPOReport -Guid $GPO.Id -ReportType Xml
        #Look for GPO that allows join PC to domain
        $permissionindex = $GPOreport.IndexOf('<q1:Name>SeMachineAccountPrivilege</q1:Name>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeMachineAccountPrivilege' }).Member) ) {
                $obj = New-Object -TypeName PSObject
                $obj | Add-Member -MemberType NoteProperty -Name GPO  -Value $GPO.DisplayName
                $obj | Add-Member -MemberType NoteProperty -Name SID  -Value $member.Sid.'#text'
                $obj | Add-Member -MemberType NoteProperty -Name Name -Value $member.Name.'#text'
                $AllowedJoin += $obj
            }
        }
        #Look for GPO that hardens NTLM
        $permissionindex = $GPOreport.IndexOf('NoLMHash</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'NoLMHash' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "NoLMHash $($value.Display.DisplayBoolean)"
            $HardenNTLM += $obj
        }
        $permissionindex = $GPOreport.IndexOf('LmCompatibilityLevel</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'LmCompatibilityLevel' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "LmCompatibilityLevel $($value.Display.DisplayString)"
            $HardenNTLM += $obj
        }
        #Look for GPO that denies NTLM
        $permissionindex = $GPOreport.IndexOf('RestrictNTLMInDomain</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'RestrictNTLMInDomain' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "RestrictNTLMInDomain $($value.Display.DisplayString)"
            $DenyNTLM += $obj
        }
        #Look for GPO that audits NTLM
        $permissionindex = $GPOreport.IndexOf('AuditNTLMInDomain</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditNTLMInDomain' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditNTLMInDomain $($value.Display.DisplayString)"
            $AuditNTLM += $obj
        }
        $permissionindex = $GPOreport.IndexOf('AuditReceivingNTLMTraffic</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditReceivingNTLMTraffic' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditReceivingNTLMTraffic $($value.Display.DisplayString)"
            $AuditNTLM += $obj
        }
        #Look for GPO that allows NTLM exclusions
        $permissionindex = $GPOreport.IndexOf('DCAllowedNTLMServers</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'DCAllowedNTLMServers' }).SettingStrings.Value) ) {
                $NTLMAuthExceptions += $member
            }
        }
        #Validate Kerberos Encryption algorithm
        $permissionindex = $GPOreport.IndexOf('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes')
        if ($permissionindex -gt 0) {
            $EncryptionTypesNotConfigured = $false
            $xmlreport = [xml]$GPOreport
            $EncryptionTypes = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions.Display.DisplayFields.Field
            if (($EncryptionTypes     | Where-Object { $_.Name -eq 'DES_CBC_CRC' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_CRC for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'DES_CBC_MD5' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_MD5 for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'RC4_HMAC_MD5' }            | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled RC4_HMAC_MD5 for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'AES128_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] AES128_HMAC_SHA1 not enabled for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'AES256_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] AES256_HMAC_SHA1 not enabled for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'Future encryption types' } | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] Future encryption types not enabled for Kerberos!" }
        }
        #Validates Admins local logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyInteractiveLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyInteractiveLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminLocalLogonAllowed = $false
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyInteractiveLogonRight $($member.Name.'#text')"
                }
            }
        }
        #Validates Admins RDP logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyRemoteInteractiveLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyRemoteInteractiveLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminRPDLogonAllowed = $false
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyRemoteInteractiveLogonRight $($member.Name.'#text')"
                }
            }
        }
        #Validates Admins network logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyNetworkLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyNetworkLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminNetworkLogonAllowed = $false
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyNetworkLogonRight $($member.Name.'#text')"
                }
            }
        }
    }
    #Output for join PC to domain
    foreach ($record in $AllowedJoin) {
        Write-Both "    [+] GPO [$($record.GPO)] allows [$($record.Name)] to join computers to domain"
    }
    #Output for Admins local logon restrictions
    if ($AdminLocalLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise local logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise local logon across domain!"
    }
    #Output for Admins RDP logon restrictions
    if ($AdminRPDLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise RDP logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise RDP logon across domain!"
    }
    #Output for Admins network logon restrictions
    if ($AdminNetworkLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise network logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise network logon across domain!"
    }
    #Output for Validate Kerberos Encryption algorithm
    if ($EncryptionTypesNotConfigured) {
        Write-Both "    [!] RC4_HMAC_MD5 enabled for Kerberos across domain!!!"
    }
    #Output for deny NTLM
    if ($DenyNTLM.count -eq 0) {
        if ($HardenNTLM.count -eq 0) {
            Write-Both "    [!] No GPO denies NTLM authentication!"
            Write-Both "    [!] No GPO explicitely restricts LM or NTLMv1!"
        }
        else {
            Write-Both "    [+] NTLM authentication hardening implemented, but NTLM not denied"
            foreach ($record in $HardenNTLM) {
                Write-Both "        [-] $($record.value)"
                Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
            }
        }
    }
    else {
        foreach ($record in $DenyNTLM) {
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
        }
    }
    #Output for NTLM exceptions
    if ($NTLMAuthExceptions.count -ne 0) {
        foreach ($record in $NTLMAuthExceptions) {
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM auth exceptions $($record)"
        }
    }
    #Output for NTLM audit
    if ($AuditNTLM.count -eq 0) {
        Write-Both "    [!] No GPO enables NTLM audit authentication!"
    }
    else {
        foreach ($record in $DenyNTLM) {
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM audit GPO [$($record.gpo)] with value [$($record.value)]"
        }
    }
}
Function Get-PrivilegedGroupMembership {
    #List Domain Admins, Enterprise Admins and Schema Admins members
    # Note: Schema Admins and Enterprise Admins only exist in forest root domain
    if ($SchemaAdmins) {
        try {
            $SchemaMembers = Get-ADGroup $SchemaAdmins -ErrorAction Stop | Get-ADGroupMember -ErrorAction Stop
            if (($SchemaMembers | measure).count -ne 0) {
                Write-Both "    [!] Schema Admins not empty!!!"
                foreach ($member in $SchemaMembers) {
                    Add-Content -Path "$outputdir\schema_admins.txt" -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
                }
            }
        } catch {
            Write-Both "    [i] Schema Admins not available in this domain (expected in child domains)"
        }
    } else {
        Write-Both "    [i] Schema Admins not available (child domain)"
    }

    if ($EnterpriseAdmins) {
        try {
            $EnterpriseMembers = Get-ADGroup $EnterpriseAdmins -ErrorAction Stop | Get-ADGroupMember -ErrorAction Stop
            if (($EnterpriseMembers | measure).count -ne 0) {
                Write-Both "    [!] Enterprise Admins not empty!!!"
                foreach ($member in $EnterpriseMembers) {
                    Add-Content -Path "$outputdir\enterprise_admins.txt" -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
                }
            }
        } catch {
            Write-Both "    [i] Enterprise Admins not available in this domain (expected in child domains)"
        }
    } else {
        Write-Both "    [i] Enterprise Admins not available (child domain)"
    }

    try {
        $DomainAdminsMembers = Get-ADGroup $DomainAdmins -ErrorAction Stop | Get-ADGroupMember -ErrorAction Stop
        foreach ($member in $DomainAdminsMembers) {
            Add-Content -Path "$outputdir\domain_admins.txt" -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
        }
    } catch {
        Write-Both "    [!] Error retrieving Domain Admins members: $($_.Exception.Message)"
    }
}
Function Get-DCEval {
    #Basic validation of all DCs in forest
    #Collect all DCs in forest
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $ADs = Get-ADDomainController -Filter { Site -like "*" }
    #Validate OS version of DCs
    $osList = @()
    $ADs | ForEach-Object { $osList += $_.OperatingSystem }
    if (($osList | sort -Unique | measure).Count -eq 1) {
        Write-Both "    [+] All DCs are the same OS version of $($osList | sort -Unique)"
    }
    else {
        Write-Both "    [!] Operating system differs across DCs!!!"
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2003' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2003"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2003' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2008 !(R2)' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2008"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2008 !(R2)' } | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2008 R2' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2008 R2" ; $ADs | Where-Object { $_.OperatingSystem -Match '2008 R2' }    | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2012 !(R2)' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2012"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2012 !(R2)' } | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2012 R2' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2012 R2" ; $ADs | Where-Object { $_.OperatingSystem -Match '2012 R2' }    | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2016' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2016"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2016' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2019' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2019"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2019' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2022' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2022"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2022' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
    }
    #Validate DCs hotfix level
    if ( (( $ADs | Select-Object OperatingSystemHotfix -Unique ) | measure).count -eq 1 -or ( $ADs | Select-Object OperatingSystemHotfix -Unique ) -eq $null ) {
        Write-Both "    [+] All DCs have the same hotfix of [$($ADs | Select-Object OperatingSystemHotFix -Unique | ForEach-Object {$_.OperatingSystemHotfix})]"
    }
    else {
        Write-Both "    [!] Hotfix level differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) hotfix [$($_.OperatingSystemHotfix)]"
        }
    }
    #Validate DCs Service Pack level
    if ((($ADs | Select-Object OperatingSystemServicePack -Unique) | measure).count -eq 1 -or ($ADs | Select-Object OperatingSystemServicePack -Unique) -eq $null) {
        Write-Both "    [+] All DCs have the same Service Pack of [$($ADs | Select-Object OperatingSystemServicePack -Unique | ForEach-Object {$_.OperatingSystemServicePack})]"
    }
    else {
        Write-Both "    [!] Service Pack level differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) Service Pack [$($_.OperatingSystemServicePack)]"
        }
    }
    #Validate DCs OS Version
    if ((($ADs | Select-Object OperatingSystemVersion -Unique ) | measure).count -eq 1 -or ($ADs | Select-Object OperatingSystemVersion -Unique) -eq $null) {
        Write-Both "    [+] All DCs have the same OS Version of [$($ADs | Select-Object OperatingSystemVersion -Unique | ForEach-Object {$_.OperatingSystemVersion})]"
    }
    else {
        Write-Both "    [!] OS Version differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) OS Version [$($_.OperatingSystemVersion)]"
        }
    }
    #List sites without GC
    $SitesWithNoGC = $false
    foreach ($Site in $Forest.Sites) {
        if (($ADs | Where-Object { $_.Site -eq $Site.Name } | Where-Object { $_.IsGlobalCatalog -eq $true }) -eq $null) {
            $SitesWithNoGC = $true
            Add-Content -Path "$outputdir\sites_no_gc.txt" -Value "$($Site.Name)"
        }
    }
    if ($SitesWithNoGC -eq $true) {
        Write-Both "    [!] You have sites with no Global Catalog!"
    }
    #Does one DC holds all FSMO
    if (($ADs | Where-Object { $_.OperationMasterRoles -ne $null } | measure).count -eq 1) {
        Write-Both "    [!] DC $($ADs | Where-Object {$_.OperationMasterRoles -ne $null} | select -ExpandProperty Hostname) holds all FSMO roles!"
    }
    #DCs with weak Kerberos algorithm (*CH* Changed below to look for msDS-SupportedEncryptionTypes to work with 2008R2)
    $ADcomputers = $ADs | ForEach-Object { Get-ADComputer $_.Name -Properties msDS-SupportedEncryptionTypes }
    $WeakKerberos = $false
    foreach ($DC in $ADcomputers) {
        #Value 8 stands for AES-128, value 16 stands for AES-256 and value 24 stands for AES-128 & AES-256
        #Values 0 to 7, 9 to 15, 17 to 23 and 25 to 31 include RC4 and/or DES
        #See https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797
        if ($DC."msDS-SupportedEncryptionTypes" -ne 8 -and $DC."msDS-SupportedEncryptionTypes" -ne 16 -and $DC."msDS-SupportedEncryptionTypes" -ne 24) {
            $WeakKerberos = $true
            Add-Content -Path "$outputdir\dcs_weak_kerberos_ciphersuite.txt" -Value "$($DC.DNSHostName) $($dc."msDS-SupportedEncryptionTypes")"
        }
    }
    if ($WeakKerberos) {
        Write-Both "    [!] You have DCs with RC4 or DES allowed for Kerberos!!!"
        Write-Nessus-Finding "WeakKerberosEncryption" "KB995" ([System.IO.File]::ReadAllText("$outputdir\dcs_weak_kerberos_ciphersuite.txt"))
    }
    #Check where newly joined computers go
    $newComputers = (Get-ADDomain).ComputersContainer
    $newUsers = (Get-ADDomain).UsersContainer
    Write-Both "    [+] New joined computers are stored in $newComputers"
    Write-Both "    [+] New users are stored in $newUsers"
}
Function Get-DefaultDomainControllersPolicy {
    #Enumerates Default Domain Controllers Policy for default unsecure and excessive options
    $ExcessiveDCInteractiveLogon = $false
    $ExcessiveDCBackupPermissions = $false
    $ExcessiveDCRestorePermissions = $false
    $ExcessiveDCDriverPermissions = $false
    $ExcessiveDCLocalShutdownPermissions = $false
    $ExcessiveDCRemoteShutdownPermissions = $false
    $ExcessiveDCTimePermissions = $false
    $ExcessiveDCBatchLogonPermissions = $false
    $ExcessiveDCRDPLogonPermissions = $false
    $GPO = Get-GPO 'Default Domain Controllers Policy'
    $GPOreport = Get-GPOReport -Guid $GPO.Id -ReportType Xml
    #Interactive local logon
    $permissionindex = $GPOreport.IndexOf('SeInteractiveLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeInteractiveLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$EntrepriseDomainControllers") {
                $ExcessiveDCInteractiveLogon = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeInteractiveLogonRight $($member.Name.'#text')"
            }
        }
    }
    #Batch logon
    $permissionindex = $GPOreport.IndexOf('SeBatchLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeBatchLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCBatchLogonPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeBatchLogonRight $($member.Name.'#text')"
            }
        }
    }
    #RDP logon
    $permissionindex = $GPOreport.IndexOf('SeRemoteInteractiveLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRemoteInteractiveLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$EntrepriseDomainControllers") {
                $ExcessiveDCRDPLogonPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRemoteInteractiveLogonRight $($member.Name.'#text')"
            }
        }
    }
    #Backup
    $permissionindex = $GPOreport.IndexOf('SeBackupPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeBackupPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCBackupPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeBackupPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Restore
    $permissionindex = $GPOreport.IndexOf('SeRestorePrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRestorePrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCRestorePermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRestorePrivilege $($member.Name.'#text')"
            }
        }
    }
    #Load driver
    $permissionindex = $GPOreport.IndexOf('SeLoadDriverPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeLoadDriverPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCDriverPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeLoadDriverPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Local shutdown
    $permissionindex = $GPOreport.IndexOf('SeShutdownPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeShutdownPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCLocalShutdownPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeShutdownPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Remote shutdown
    $permissionindex = $GPOreport.IndexOf('SeRemoteShutdownPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRemoteShutdownPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCRemoteShutdownPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRemoteShutdownPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Change time
    $permissionindex = $GPOreport.IndexOf('SeSystemTimePrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeSystemTimePrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$LocalService") {
                $ExcessiveDCTimePermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeSystemTimePrivilege $($member.Name.'#text')"
            }
        }
    }
    #Output for Default Domain Controllers Policy
    if ($ExcessiveDCInteractiveLogon -or $ExcessiveDCBackupPermissions -or $ExcessiveDCRestorePermissions -or $ExcessiveDCDriverPermissions -or $ExcessiveDCLocalShutdownPermissions -or $ExcessiveDCRemoteShutdownPermissions -or $ExcessiveDCTimePermissions -or $ExcessiveDCBatchLogonPermissions -or $ExcessiveDCRDPLogonPermissions) {
        Write-Both "    [!] Excessive permissions in Default Domain Controllers Policy detected!"
    }
}
Function Get-RecentChanges() {
    #Retrieve users and groups that have been created during last 30 days
    $DateCutOff = ((Get-Date).AddDays(-30)).Date
    $newUsers = Get-ADUser  -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $newGroups = Get-ADGroup -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $countUsers = 0
    $countGroups = 0
    $progresscountUsers = 0
    $progresscountGroups = 0
    $totalcountUsers = ($newUsers  | Measure-Object | Select-Object Count).count
    $totalcountGroups = ($newGroups | Measure-Object | Select-Object Count).count
    if ($totalcountUsers -gt 0) {
        foreach ($newUser in $newUsers ) { Add-Content -Path "$outputdir\new_users.txt" -Value "Account $($newUser.SamAccountName) was created $($newUser.whenCreated)" }
        Write-Both "    [!] $totalcountUsers new users were created last 30 days, see $outputdir\new_users.txt"
    }
    if ($totalcountGroups -gt 0) {
        foreach ($newGroup in $newGroups ) { Add-Content -Path "$outputdir\new_groups.txt" -Value "Group $($newGroup.SamAccountName) was created $($newGroup.whenCreated)" }
        Write-Both "    [!] $totalcountGroups new groups were created last 30 days, see $outputdir\new_groups.txt"
    }
}
Function Get-ReplicationType {
    #Retrieve replication mechanism (FRS or DFSR)
    $objectName = "DFSR-GlobalSettings"
    $searcher = [ADSISearcher] "(objectClass=msDFSR-GlobalSettings)"
    $objectExists = $searcher.FindOne() -ne $null
    if ($objectExists) {
        $DFSRFlags = (Get-ADObject -Identity "CN=DFSR-GlobalSettings,$((Get-ADDomain).systemscontainer)" -Properties msDFSR-Flags).'msDFSR-Flags'
        switch ($DFSRFlags) {
            0 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: started!" }
            16 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: prepared!" }
            32 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: redirected!" }
            48 { Write-Both "    [+] DFSR mechanism is used to replicate across domain controllers." }
        }
    }
    else {
        Write-Both "    [!] FRS mechanism is still used to replicate across domain controllers, you should migrate to DFSR!"
    }
}
Function Get-RecycleBinState {
    #Check if recycle bin is enabled
    if ((Get-ADOptionalFeature -Filter 'Name -eq "Recycle Bin Feature"').EnabledScopes) {
        Write-Both "    [+] Recycle Bin is enabled in the domain"
    }
    else {
        Write-Both "    [!] Recycle Bin is disabled in the domain, you should consider enabling it!"
    }
}
Function Get-CriticalServicesStatus {
    #Check AD services status
    Write-Both "    [+] Checking services on all DCs"
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    $objectName = "DFSR-GlobalSettings"
    $searcher = [ADSISearcher] "(objectClass=msDFSR-GlobalSettings)"
    $objectExists = $searcher.FindOne() -ne $null
    if ($objectExists) {
        $services = @("dns", "netlogon", "kdc", "w32time", "ntds", "dfsr")
    }
    else {
        $services = @("dns", "netlogon", "kdc", "w32time", "ntds", "ntfrs")
    }
    foreach ($DC in $dcList) {
        foreach ($service in $services) {
            $checkService = Get-Service $service -ComputerName $DC -ErrorAction SilentlyContinue
            $serviceName = $checkService.Name
            $serviceStatus = $checkService.Status
            if (!($serviceStatus)) {
                Write-Both "        [!] Service $($service) cannot be checked on $DC!"
            }
            elseif ($serviceStatus -ne "Running") {
                Write-Both "        [!] Service $($service) is not running on $DC!"
            }
        }
    }
}
Function Get-LastWUDate {
    #Check Windows update status and last install date
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    $lastMonth = (Get-Date).AddDays(-30)
    Write-Both "    [+] Checking Windows Update"
    foreach ($DC in $dcList) {

        $startMode = (Get-WmiObject -ComputerName $DC -Class Win32_Service -Property StartMode -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue).StartMode
        if (!($startMode)) {
            Write-Both "        [!] Windows Update service cannot be checked on $DC!"
        }
        elseif ($startMode -eq "Disabled") {
            Write-Both "        [!] Windows Update service is disabled on $DC!"
        }
    }
    $progresscount = 0
    $totalcount = ($dcList | Measure-Object | Select-Object Count).count
    foreach ($DC in $dcList) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Currently searching on $DC" -PercentComplete ($progresscount / $totalcount * 100)
        try {
            $lastHotfix = (Get-HotFix -ComputerName $DC | Where-Object { $_.InstalledOn -ne $null } | Sort-Object -Descending InstalledOn  | Select-Object -First 1).InstalledOn
            if ($lastHotfix -lt $lastMonth) {
                Write-Both "        [!] Windows is not up to date on $DC, last install: $($lastHotfix)"
            }
            else {
                Write-Both "        [+] Windows is up to date on $DC, last install: $($lastHotfix)"
            }
        }
        catch {
            Write-Both "        [!] Cannot check last update date on $DC"
        }
        $progresscount++
    }
    Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Ready" -Completed
}
Function Get-TimeSource {
    #Get NTP sync source
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking NTP configuration"
    foreach ($DC in $dcList) {
        $ntpSource = w32tm /query /source /computer:$DC
        if ($ntpSource -like '*0x800706BA*') {
            Write-Both "        [!] Cannot get time source for $DC"
        }
        else {
            Write-Both "        [+] $DC is syncing time from $ntpSource"
        }
    }
}
Function Get-RODC {
    #Check for RODC
    Write-Both "    [+] Checking for Read Only DCs"
    $ADs = Get-ADDomainController -Filter { Site -like "*" }
    $ADs | ForEach-Object {
        if ($_.IsReadOnly) {
            Write-Both "        [+] DC $($_.Name) is a RODC server!"
        }
    }
}
Function Install-Dependencies {
    #Install DSInternals
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } catch {
            Write-Both "    [!] Warning: Could not set TLS 1.2 protocol: $($_.Exception.Message)"
        }

        $count = 0
        $totalcount = 3
        Write-Progress -Activity "Installing dependencies..." -Status "Currently installing NuGet Package Provider" -PercentComplete ($count / $totalcount * 100)
        try {
            if (!(Get-PackageProvider -ListAvailable -Name Nuget -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
            }
        } catch {
            Write-Both "    [!] Warning: Failed to install NuGet: $($_.Exception.Message)"
        }

        $count++
        Write-Progress -Activity "Installing dependencies..." -Status "Currently adding PSGallery to trusted Repositories" -PercentComplete ($count / $totalcount * 100)
        try {
            if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -eq "Untrusted") {
                Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction Stop
            }
        } catch {
            Write-Both "    [!] Warning: Failed to set PSGallery as trusted: $($_.Exception.Message)"
        }

        $count++
        Write-Progress -Activity "Installing dependencies..." -Status "Currently installing module DSInternals" -PercentComplete ($count / $totalcount * 100)
        try {
            if (!(Get-Module -ListAvailable -Name DSInternals -ErrorAction SilentlyContinue)) {
                Install-Module -Name DSInternals -Force -ErrorAction Stop
            }
            Import-Module DSInternals -ErrorAction Stop
            Write-Both "    [+] DSInternals module installed successfully"
        } catch {
            Write-Both "    [!] Warning: Failed to install DSInternals module: $($_.Exception.Message)"
        }

        Write-Progress -Activity "Installing dependencies..." -Status "Ready" -Completed
    }
    else {
        Write-Both "    [!] PowerShell 5 or greater is needed, see https://www.microsoft.com/en-us/download/details.aspx?id=54616"
    }
}
Function Remove-StringLatinCharacters {
    #Removes latin characters
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}
Function Get-PasswordQuality {
    #Use DSInternals to evaluate password quality
    if (Get-Module -ListAvailable -Name DSInternals) {
        try {
            $totalSite = (Get-ADObject -Filter { objectClass -like "site" } -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -ErrorAction Stop | measure).Count
            $count = 0
            Get-ADObject -Filter { objectClass -like "site" } -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -ErrorAction Stop | ForEach-Object {
                if ($_.Name -eq $(Remove-StringLatinCharacters $_.Name)) { $count++ }
            }
            if ($count -ne $totalSite) {
                Write-Both "    [!] One or more site have illegal characters in their name, can't get password quality!"
            }
            else {
                Get-ADReplAccount -All -Server $env:ComputerName -NamingContext $(Get-ADDomain | select -ExpandProperty DistinguishedName) -ErrorAction Stop | Test-PasswordQuality -IncludeDisabledAccounts | Out-File "$outputdir\password_quality.txt"
                Write-Both "    [!] Password quality test done, see $outputdir\password_quality.txt"
            }
        } catch {
            Write-Both "    [!] Error running password quality test: $($_.Exception.Message)"
        }
    }
}
Function Check-Shares {
    #Check SYSVOL and NETLOGON share exists
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking SYSVOL and NETLOGON shares on all DCs"
    foreach ($DC in $dcList) {
        $shareList = (Get-WmiObject -Class Win32_Share -ComputerName $DC -ErrorAction SilentlyContinue)
        if (!($shareList)) {
            Write-Both "        [!] Cannot test shares on $DC!"
        }
        else {
            $sysvolShare = ($shareList | ? { $_ -match 'SYSVOL' }   | measure).Count
            $netlogonShare = ($shareList | ? { $_ -match 'NETLOGON' } | measure).Count
            if ($sysvolShare -eq 0) { Write-Both "        [!] SYSVOL share is missing on $DC!" }
            if ($netlogonShare -eq 0) { Write-Both "        [!] NETLOGON share is missing on $DC!" }
        }
    }
}

Function Get-ADCSVulns {
    #Check for ADCS Vulnerabiltiies, ESC1,2,3,4 and 8. ESC8 will output to a different issues mapped to Nessus.
    try {
        $certutil_output = certutil -v -template -ErrorAction Stop
    } catch {
        Write-Both "    [!] Error: Unable to enumerate certificate templates: $($_.Exception.Message)"
        Write-Both "    [!] Make sure you have the appropriate permissions and certutil is available"
        return
    }

    try {
        $certutil_lines = $certutil_output.Trim().Split("`n")
    $templates = @()
    foreach ($line in $certutil_lines) {
        if ($line.StartsWith("Template[")) {
            $template_unparsed = $current_template.TrimEnd(",").Split(",")
            $SuppliesSubjectCheck = $false
            $ClientAuthCheck = $false
            $AllowEnrollCheck = $false
            $AnyPurposeCheck = $false
            $AllowWriteCheck = $false
            $AllowFullControl = $false
            $CertificateRequestAgentCheck = $false

            $TemplatePropCommonName = $null
            foreach ($detail in $template_unparsed) {
                if ($detail -like "*TemplatePropCommonName =*") {
                    $TemplatePropCommonName = $detail.Split("=")[1].Trim()
                }
                if ($detail -like "*CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1*") {
                    $SuppliesSubjectCheck = $true
                }
                if ($detail -like "*Client Authentication*") {
                    $ClientAuthCheck = $true
                }
                if ($detail -match "^\s*Allow Enroll\s+.*\\Authenticated Users\s*$|^\s*Allow Enroll\s+.*\\Domain Users\s*$") {
                    $AllowEnrollCheck = $true
                }
                if ($detail -like "2.5.29.37.0 Any Purpose") {
                    $AnyPurposeCheck = $true
                }
                if ($detail -match "^\s*Allow Write\s+.*\\Authenticated Users\s*$|^\s*Allow Write\s+.*\\Domain Users\s*$") {
                    $AllowWriteCheck = $true
                }
                # Check for Allow Full Control
                if ($detail -match "^\s*Allow Full Control\s+.*\\Authenticated Users\s*$|^\s*Allow Full Control\s+.*\\Domain Users\s*$") {
                    $AllowFullControl = $true
                }
                if ($detail -like "Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)") {
                    $CertificateRequestAgentCheck = $true
                }
                # Create object with details. Objectg name is TemplatePropCommonName
                $template = New-Object -TypeName PSObject -Property @{
                    "SuppliesSubjectCheck"         = $SuppliesSubjectCheck
                    "ClientAuthCheck"              = $ClientAuthCheck
                    "AllowEnrollCheck"             = $AllowEnrollCheck
                    "AnyPurposeCheck"              = $AnyPurposeCheck
                    "AllowWriteCheck"              = $AllowWriteCheck
                    "AllowFullControl"             = $AllowFullControl
                    "TemplatePropCommonName"       = $TemplatePropCommonName
                    "CertificateRequestAgentCheck" = $CertificateRequestAgentCheck
                }
            }
            $templates += $template
            $current_template = $line + ","
        }
        else {
            $current_template += $line + ","
        }
    }

    # Check for ESC1
    # ESC1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1 and  Client Authentication and ( enroll or full control )

    $ESC1 = @()
    $ESC1e = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowEnrollCheck }
    $ESC1f = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowFullControl }
    $ESC1w = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowWriteCheck }
    $ESC1 += $ESC1e
    $ESC1 += $ESC1f
    $ESC1 += $ESC1w
    # Remove duplicates
    $ESC1 = $ESC1 | Select-Object -Property TemplatePropCommonName -unique
    $ESC2 = $templates | Where-Object { $_.AnyPurposeCheck -and $_.AllowEnrollCheck }
    $ESC3 = $templates | Where-Object { $_.CertificateRequestAgentCheck -and $_.AllowEnrollCheck }
    $ESC4 = $templates | Where-Object { $_.AllowWriteCheck -or $_.AllowFullControl }

    $template_path = $outputdir + "\vulnerable_templates.txt"
    $web_enrollmeent_path = $outputdir + "\web_enrollment.txt"

    foreach ($template in $ESC1) {
        $ESC1line = "ESC1 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC1line
        Write-Both '    [!]'$ESC1line
    }
    foreach ($template in $ESC2) {
        $ESC2line = "ESC2 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC2line
        Write-Both '    [!]'$ESC2line
    }
    foreach ($template in $ESC3) {
        $ESC3line = "ESC3 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC3line
        Write-Both '    [!]'$ESC3line
    }
    foreach ($template in $ESC4) {
        $ESC4line = "ESC4 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC4line
        Write-Both '    [!]'$ESC4line
    }
    } catch {
        Write-Both "    [!] Error parsing certificate templates: $($_.Exception.Message)"
    }

    # ESC8 Check, If error 401 and response is unauthorized, then vulnerable
    try {
        $certInfo = & certutil
        $serverName = ($certInfo | Select-String 'Server:' | Select-Object -First 1).ToString().Split(':')[1].Trim().Replace('"', '')
        $response = Invoke-WebRequest -Uri ("http://$serverName/certsrv/") -ErrorAction Stop
        $response
    }
    catch {
        # If error and response is unauthorised, then vulnerable
        if ($_.Exception.Response.StatusCode -eq 401) {
            Add-Content -Path $web_enrollmeent_path -Value "ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
            Write-Both "    [!] ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
        }
        else {
            Write-Both "    [+] ESC8 not vulnerable"
        }
    }
    if (Test-Path "$outputdir\web_enrollment.txt") {
        Write-Nessus-Finding "Active Directory Certificate Service Web Enrollment Enabled in HTTP" "KB1095" ([System.IO.File]::ReadAllText("$outputdir\web_enrollment.txt"))
    }
    if (Test-Path "$outputdir\vulnerable_templates.txt") {
        Write-Nessus-Finding "Active Directory Certificate Service Vulnerable Templates" "KB1096" ([System.IO.File]::ReadAllText("$outputdir\vulnerable_templates.txt"))
    }
}

Function Get-SPNs {
    $default_groups = @("Domain Admins", "Domain Admins", "Enterprise Admins", "Schema Admins", "Domain Controllers", "Backup Operators", "Account Operators", "Server Operators", "Print Operators", "Remote Desktop Users", "Network Configuration Operators", "Exchange Organization Admins", "Exchange View-Only Admins", "Exchange Recipient Admins", "Exchange Servers", "Exchange Trusted Subsystem", "Exchange Public Folder Admins", "Exchange UM Management")
    $base_groups = @()
    foreach ($group in $default_groups) {
        try {
            $ADGrp = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
            $base_groups += $ADGrp.Name
        }
        catch {
            $base_groups = $base_groups | Where-Object { $_ -ne $group }
        }
    }

    $all_groups = $base_groups
    foreach ($group in $default_groups) {
        try {
            $ADGrp = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
            $QueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($ADGrp.DistinguishedName)))"
            foreach ($result in $QueryResult) {
                $all_groups += $result.Name
            }
        }
        catch {}
    }

#    while ($base_groups.count -gt 0) {
#        $new_groups = @()
#        foreach ($group in $base_groups) {
#            # I dont want to see errors if a group is not found
#            try {
#                $ADGrp = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
#                $QueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($ADGrp.DistinguishedName)))"
#                foreach ($result in $QueryResult) {
#                    $all_groups += $result.Name
#                    $new_groups += $result.Name
#                }
#            }
#            catch {
#                # Remove group from all_groups
#                $all_groups = $all_groups | Where-Object { $_ -ne $group }
#            }
#        }
#        $base_groups = $new_groups
#    }
#    
    $SPNs = Get-ADObject -Filter { serviceprincipalname -like "*" } -Properties MemberOf |
    Where-Object { $_.ObjectClass -eq "user" } |
    ForEach-Object {
        $groups = $_.MemberOf | Get-ADObject | Where-Object { $_.ObjectClass -eq "group" }
        $_ | Select-Object Name, @{ Name = "Groups"; Expression = { $groups.Name -join ',' } }
    }

    # for spn in spns check if a group in spn.groups is in all_groups
    $high_value_users = @()
    foreach ($spn in $SPNs) {
        $spn_groups = $spn.Groups.Split(',')
        $name = $spn.Name
        foreach ($spn_group in $spn_groups) {
            if ($all_groups -contains $spn_group) {
                # Create object with user and group
                # Add object to high_value_users if the user.name is not already in the list
                $user = New-Object -TypeName PSObject -Property @{
                    Name  = $name
                    Group = $spn_group
                }
                if ($high_value_users.Name -notcontains $name) {
                    $high_value_users += $user
                }
            }
        }
    }

    foreach ($user in $high_value_users) {
        $kerbuser = '    [!] High value kerberoastable user: ' + $user.Name + ' in groups: ' + $user.Group
        Write-both $kerbuser
        add-content -path $outputdir\SPNs.txt -value $user.Name
    }

    # Only write Nessus finding if SPNs were actually found
    if (Test-Path "$outputdir\SPNs.txt") {
        Write-Nessus-Finding  "Kerberoast Attack - Services Configured With a Weak Password" "KB611" ([System.IO.File]::ReadAllText("$outputdir\SPNs.txt"))
    } else {
        Write-Both "    [+] No high-value kerberoastable accounts found"
    }
}

function Get-ADUsersWithoutPreAuth {
    $ASREP = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth, Enabled | Where-Object { $_.DoesNotRequirePreAuth -eq "True" -and $_.Enabled -eq "True" } | Select-Object Name
    foreach ($user in $ASREP) {
        $asrepuser = '    [!] AS-REP Roastable user: ' + $user.Name
        Write-both $asrepuser
        add-content -path $outputdir\ASREP.txt -value $user.Name
    }
    if (-not (Test-Path "$outputdir\ASREP.txt") -or !(Get-Content "$outputdir\ASREP.txt")) {
        Write-Both "    [+] No ASREP Accounts"
    }
    else {
        Write-Nessus-Finding "AS-REP Roasting Attack" "KB720" ([System.IO.File]::ReadAllText("$outputdir\ASREP.txt"))
    }
}

function Get-LDAPSecurity {
    # Check if LDAP signing is enabled
    $computerName = $env:COMPUTERNAME
    
    # Check if LDAP signing is enabled
    try {
        $ldapSigning = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity

        if ($ldapSigning -eq 2) {
            Write-both "    [+] LDAP signing is enabled on $computerName"
        }
        else {
            Write-Both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry value is currently set to $ldapSigning."
            Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
        }
    }
    catch {
        Write-both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry key does not exist."
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
    }

    # Check if LDAPS is configured
    $serverAuthOid = '1.3.6.1.5.5.7.3.1'
    $ldapsCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date) -and
        (
            $_.Extensions |
            Where-Object {
                $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] -and
                ($_.EnhancedKeyUsages | Where-Object { $_.Value -eq $serverAuthOid })
            }
        )
    }

    if ($ldapsCert) {
        Write-Both "    [+] LDAPS is configured on $computerName"
    } else {
        Write-Both "    [!] Issue identified LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
    }


    # Check if LDAPS Channel binding is enabled
    try {
        $ldapsBinding = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction Stop).LdapEnforceChannelBinding

        if ($ldapsBinding -eq 2) {
            Write-both "    [+] LDAPS channel binding is enabled on $computerName"
        }
        else {
            Write-both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
        }
    }
    catch {
        Write-both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
    }


    # Check for LDAP null sessions (anonymous bind with effective read)
    $Server = Get-ADDomainController -Discover | Select-Object -ExpandProperty HostName -First 1
    $Port   = 389  # Use 636 + SSL if you want to test LDAPS

    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols

        # Create LDAP connection (explicit host/port)
        $id   = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port)
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id)

        # Force a true anonymous bind (no fallback to current logon)
        $conn.AuthType   = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $conn.Credential = [System.Net.NetworkCredential]::new($null, $null)
        $conn.Timeout    = [TimeSpan]::FromSeconds(5)
        $conn.SessionOptions.ProtocolVersion = 3
        $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        # For LDAPS testing, uncomment and set $Port=636:
        # $conn.SessionOptions.SecureSocketLayer = $true
        # (Lab-only) ignore cert trust:
        # $conn.SessionOptions.VerifyServerCertificate = { param($c,$cert) $true }

        # Anonymous bind
        $conn.Bind()

     # Discover default naming context from RootDSE (safe for discovery only)
        $rootReq = New-Object System.DirectoryServices.Protocols.SearchRequest("", "(objectClass=*)", "Base", "defaultNamingContext")
        $rootRes = $conn.SendRequest($rootReq)

        $defaultNC = $null
        if ($rootRes -and $rootRes.Entries.Count -gt 0) {
            $entry = $rootRes.Entries[0]
            if ($entry.Attributes -and $entry.Attributes.Contains("defaultNamingContext")) {
                $vals = $entry.Attributes["defaultNamingContext"].GetValues([string])
                if ($vals -and $vals.Count -gt 0) { $defaultNC = $vals[0] }
            }
        }

        if (-not $defaultNC) {
         Write-Both "    [+] LDAP null session not useful on $Server`:$Port (no naming context visible)"
         Add-Content -Path (Join-Path $outputdir 'LDAPSecurity.txt') -Value "Anonymous bind present but NC not visible on $Server`:$Port"
         return
        }

        # Attempt a real directory read under default NC (no paging; limit to 1 entry)
        $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $defaultNC,
            "(objectClass=*)",
            [System.DirectoryServices.Protocols.SearchScope]::Subtree,
            @("distinguishedName")
        )
        $req.SizeLimit = 1
        $req.TimeLimit = [TimeSpan]::FromSeconds(3)

        $res = $conn.SendRequest($req)

        if ($res.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success -and
            $res.Entries.Count -gt 0) {

            Write-Both "    [!] LDAP anonymous (null) bind allows directory READ on $Server`:$Port"
            Add-Content -Path (Join-Path $outputdir 'LDAPSecurity.txt') -Value "Anonymous bind allows directory read on $Server`:$Port"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "Anonymous LDAP bind allows directory read on $Server`:$Port"

        } else {
            Write-Both ("    [+] LDAP null session not allowed/useful on {0}:{1} - Result: {2} ({3}) Msg: {4}" -f `
             $Server, $Port, [int]$res.ResultCode, $res.ResultCode, $res.ErrorMessage)
        }
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        # Typically indicates anonymous bind succeeded, but search was blocked (your DSID-0C090D44 case)
        $resp = $_.Exception.Response
        if ($resp) {
         Write-Both ("    [+] LDAP null session not allowed/useful on {0}:{1} - Result: {2} ({3}) Msg: {4}" -f `
                $Server, $Port, [int]$resp.ResultCode, $resp.ResultCode, $resp.ErrorMessage)
            Add-Content -Path (Join-Path $outputdir 'LDAPSecurity.txt') -Value "Anonymous bind present but read blocked on $Server`:$Port"
        } else {
            Write-Both "    [+] LDAP null session not allowed/useful on $Server`:$Port (directory operation blocked)"
        }
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        switch ($_.Exception.ErrorCode) {
            49 {  # InvalidCredentials -> anonymous fully disabled
                Write-Both "    [+] LDAP anonymous bind NOT allowed on $Server`:$Port (InvalidCredentials)"
            }
            8 {   # StrongerAuthRequired -> signing/TLS required; try LDAPS if you want to check further
                Write-Both "    [+] LDAP anonymous bind refused on $Server`:$Port (StrongerAuthRequired - signing/LDAPS required)"
            }
            default {
                Write-Both ("    [i] LDAP error on {0}:{1} - {2} (code {3})" -f $Server, $Port, $_.Exception.Message, $_.Exception.ErrorCode)
            }
        }
    }
    finally {
        if ($conn) { $conn.Dispose() }
    }

}

function Find-DangerousACLPermissions {
    #Specify the ACLs and Groups to check against
    $dangerousAces = @('GenericAll', 'GenericWrite', 'ForceChangePassword', 'WriteDacl', 'WriteOwner', 'Delete')
    $groupsToCheck = @('NT AUTHORITY\Authenticated Users', 'DOMAIN\Domain Users', 'Everyone')

    # Find dangerous permissions on Computers
    $computers = Get-ADObject -Filter { objectClass -eq 'computer' -and objectCategory -eq 'computer' } -Properties *
    $computerResults = foreach ($computer in $computers) {
        if ($OSVersion -like "Windows Server 2019*" -or $OSVersion -like "Windows Server 2022*") {
	$acl = Get-Acl -Path "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$($computer.DistinguishedName)"} else {
	$acl = Get-Acl AD:\$computer}

        $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Computer'
                    ObjectName            = $computer
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                }
            }
        }
        Write-Progress -Activity "Searching for dangerous ACL permissions on computers" -Status "Computers searched: $($computers.IndexOf($computer) + 1)/$($computers.Count)" -PercentComplete (($computers.IndexOf($computer) + 1) / $computers.Count * 100)
    }

    # Find dangerous permissions on groups
    $groups = Get-ADObject -Filter { objectClass -eq 'group' -and objectCategory -eq 'group' } -Properties *
    $groupResults = foreach ($group in $groups) {
        if ($OSVersion -like "Windows Server 2019*" -or $OSVersion -like "Windows Server 2022*") {
	$acl = Get-Acl -Path "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$($group.DistinguishedName)"} else {
	$acl = Get-Acl AD:\$group}

        $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Group'
                    ObjectName            = $group
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                }
            }
        }
        Write-Progress -Activity "Searching for dangerous ACL permissions on groups" -Status "Groups searched: $($groups.IndexOf($group) + 1)/$($groups.Count)" -PercentComplete (($groups.IndexOf($group) + 1) / $groups.Count * 100)
    }
    # Find dangerous permissions on users
    $users = Get-ADObject -Filter { objectClass -eq 'user' -and objectCategory -eq 'person' } -Properties *

    $userResults = foreach ($user in $users) {
        $acl = $null

        if ($OSVersion -like "Windows Server 2019*" -or $OSVersion -like "Windows Server 2022*") {
	$acl = Get-Acl -Path "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$($user.DistinguishedName)"} else {
	$acl = Get-Acl AD:\$user}

        if ($acl) {
            $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }
            if ($dangerousRules) {
                foreach ($rule in $dangerousRules) {
                    [PSCustomObject]@{
                        ObjectType            = 'User'
                        ObjectName            = $user
                        IdentityReference     = $rule.IdentityReference
                        AccessControlType     = $rule.AccessControlType
                        ActiveDirectoryRights = $rule.ActiveDirectoryRights
                    }
                }
            }
            Write-Progress -Activity "Searching for dangerous ACL permissions on users" -Status "Users searched: $($users.IndexOf($user) + 1)/$($users.Count)" -PercentComplete (($users.IndexOf($user) + 1) / $users.Count * 100)
        }
    }

    # Output results
    if ($computerResults) {
        $computerResults | ConvertTo-Html -Property @{ Label = "Type"; Expression = { "Computer" } }, @{ Label = "Computer Name"; Expression = { $_.ObjectName } }, @{ Label = "Allowed Group"; Expression = { $_.IdentityReference } }, AccessControlType, ActiveDirectoryRights | Out-File -Encoding UTF8 $outputdir\dangerousACLs.html -Append
        $computerResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType | Out-File $outputdir\dangerousACL_Computer.txt -Encoding UTF8
        Write-Both "    [!] Issue identified, vulnerable ACL on Computer, see $outputdir\dangerousACL_Computer.txt"
        Write-Nessus-Finding "Weak Computer Permissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\dangerousACL_Computer.txt"))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any computer."
    }

    if ($groupResults) {
        $groupResults | ConvertTo-Html -Property @{ Label = "Type"; Expression = { "Group" } }, @{ Label = "Group Name"; Expression = { $_.ObjectName } }, @{ Label = "Allowed Group"; Expression = { $_.IdentityReference } }, AccessControlType, ActiveDirectoryRights | Out-File -Encoding UTF8 $outputdir\dangerousACLs.html -Append
        $groupResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File $outputdir\dangerousACL_Groups.txt
        Write-Both "    [!] Issue identified, vulnerable ACL on Group, see $outputdir\dangerousACL_Groups.txt"
        Write-Nessus-Finding "Weak Group Permissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\dangerousACL_Groups.txt"))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any group."
    }
    if ($userResults) {
        $userResults | ConvertTo-Html -Property @{ Label = "Type"; Expression = { "User" } }, @{ Label = "User"; Expression = { $_.ObjectName } }, @{ Label = "Allowed Group"; Expression = { $_.IdentityReference } }, AccessControlType, ActiveDirectoryRights | Out-File -Encoding UTF8 $outputdir\dangerousACLs.html -Append
        $userResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File $outputdir\dangerousACLUsers.txt
        Write-Both "    [!] Issue identified, vulnerable ACL on User, see $outputdir\dangerousACLUsers.txt"
        Write-Nessus-Finding "Weak User Permissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\dangerousACLUsers.txt"))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any user."
    }
}

$outputdir = (Get-Item -Path ".\").FullName + "\" + $env:computername
$starttime = Get-Date
$scriptname = $MyInvocation.MyCommand.Name
try {
    if (!(Test-Path "$outputdir")) { New-Item -ItemType Directory -Path $outputdir | Out-Null }
} catch {
    Write-Host "[!] Error: Cannot create output directory: $($_.Exception.Message)"
    exit
}

Write-Both " _____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
$versionnum                  by phillips321
"

$running = $false
Write-Both "[*] Script start time $starttime"

try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) { Import-Module ActiveDirectory -ErrorAction Stop }
    else { Write-Both "[!] ActiveDirectory module not installed, exiting..." ; exit }
} catch {
    Write-Both "[!] Error loading ActiveDirectory module: $($_.Exception.Message)"
    exit
}

try {
    if (Get-Module -ListAvailable -Name ServerManager) { Import-Module ServerManager -ErrorAction Stop }
    else { Write-Both "[!] ServerManager module not installed, exiting..." ; exit }
} catch {
    Write-Both "[!] Error loading ServerManager module: $($_.Exception.Message)"
    exit
}

try {
    if (Get-Module -ListAvailable -Name GroupPolicy) { Import-Module GroupPolicy -ErrorAction Stop }
    else { Write-Both "[!] GroupPolicy module not installed, exiting..." ; exit }
} catch {
    Write-Both "[!] Error loading GroupPolicy module: $($_.Exception.Message)"
    exit
}

if (Get-Module -ListAvailable -Name DSInternals) {
    Import-Module DSInternals -ErrorAction SilentlyContinue
} else {
    Write-Both "[!] DSInternals module not installed, use -installdeps to force install"
}

try {
    if (Test-Path "$outputdir\adaudit.nessus") { Remove-Item -recurse "$outputdir\adaudit.nessus" | Out-Null }
} catch {
    Write-Both "[!] Warning: Could not clean old nessus file: $($_.Exception.Message)"
}

Write-Nessus-Header
Write-Host "[+] Outputting to $outputdir"
Write-Both "[*] Lang specific variables"
Get-Variables

if (!$?) {
    Write-Both "[!] Error: Failed to initialize script variables. Exiting..."
    exit
}
if ($installdeps) { $running = $true ; Write-Both "[*] Installing optionnal features"                           ; Install-Dependencies }
if ($hostdetails -or ($all -and 'hostdetails' -notin $exclude) -or 'hostdetails' -in $selectedChecks) { $running = $true ; Write-Both "[*] Device Information" ; Get-HostDetails }
if ($domainaudit -or ($all -and 'domainaudit' -notin $exclude) -or 'domainaudit' -in $selectedChecks) { $running = $true ; Write-Both "[*] Domain Audit" ; Get-LastWUDate ; Get-DCEval ; Get-TimeSource ; Get-PrivilegedGroupMembership ; Get-MachineAccountQuota; Get-DefaultDomainControllersPolicy ; Get-SMB1Support ; Get-FunctionalLevel ; Get-DCsNotOwnedByDA ; Get-ReplicationType ; Check-Shares ; Get-RecycleBinState ; Get-CriticalServicesStatus ; Get-RODC }
if ($trusts -or ($all -and 'trusts' -notin $exclude) -or 'trusts' -in $selectedChecks) { $running = $true ; Write-Both "[*] Domain Trust Audit" ; Get-DomainTrusts }
if ($accounts -or ($all -and 'accounts' -notin $exclude) -or 'accounts' -in $selectedChecks) { $running = $true ; Write-Both "[*] Accounts Audit" ; Get-InactiveAccounts ; Get-DisabledAccounts ; Get-LockedAccounts ; Get-AdminAccountChecks ; Get-NULLSessions ; Get-PrivilegedGroupAccounts ; Get-ProtectedUsers }
if ($passwordpolicy -or ($all -and 'passwordpolicy' -notin $exclude) -or 'passwordpolicy' -in $selectedChecks) { $running = $true ; Write-Both "[*] Password Information Audit" ; Get-AccountPassDontExpire ; Get-UserPasswordNotChangedRecently ; Get-PasswordPolicy ; Get-PasswordQuality }
if ($ntds -or ($all -and 'ntds' -notin $exclude) -or 'ntds' -in $selectedChecks) { $running = $true ; Write-Both "[*] Trying to save NTDS.dit, please wait..." ; Get-NTDSdit }
if ($oldboxes -or ($all -and 'oldboxes' -notin $exclude) -or 'oldboxes' -in $selectedChecks) { $running = $true ; Write-Both "[*] Computer Objects Audit" ; Get-OldBoxes }
if ($gpo -or ($all -and 'gpo' -notin $exclude) -or 'gpo' -in $selectedChecks) { $running = $true ; Write-Both "[*] GPO audit (and checking SYSVOL for passwords)" ; Get-GPOtoFile ; Get-GPOsPerOU ; Get-SYSVOLXMLS; Get-GPOEnum }
if ($ouperms -or ($all -and 'ouperms' -notin $exclude) -or 'ouperms' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check Generic Group AD Permissions" ; Get-OUPerms }
if ($laps -or ($all -and 'laps' -notin $exclude) -or 'laps' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For Existence of LAPS in domain" ; Get-LAPSStatus }
if ($authpolsilos -or ($all -and 'authpolsilos' -notin $exclude) -or 'authpolsilos' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For Existence of Authentication Polices and Silos" ; Get-AuthenticationPoliciesAndSilos }
if ($insecurednszone -or ($all -and 'insecurednszone' -notin $exclude) -or 'insecurednszone' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For Existence DNS Zones allowing insecure updates" ; Get-DNSZoneInsecure }
if ($recentchanges -or ($all -and 'recentchanges' -notin $exclude) -or 'recentchanges' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For newly created users and groups"                ; Get-RecentChanges }
if ($spn -or ($all -and 'spn' -notin $exclude) -or 'spn' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check high value kerberoastable user accounts"           ; Get-SPNs }
if ($asrep -or ($all -and 'asrep' -notin $exclude) -or 'asrep' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for accounts with kerberos pre-auth"               ; Get-ADUsersWithoutPreAuth }
if ($acl -or ($all -and 'acl' -notin $exclude) -or 'acl' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for dangerous ACL permissions on Computers, Users and Groups"  ; Find-DangerousACLPermissions }
if ($adcs -or ($all -and 'adcs' -notin $exclude) -or 'adcs' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for ADCS Vulnerabilities"                          ; Get-ADCSVulns }
if ($ldapsecurity -or ($all -and 'ldapecurity' -notin $exclude) -or 'adcs' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for LDAP Security Issues"                          ; Get-LDAPSecurity }
if (!$running) {
    Write-Both "[!] No arguments selected"
    Write-Both "[!] Other options are as follows, they can be used in combination"
    Write-Both "    -installdeps installs optionnal features (DSInternals)"
    Write-Both "    -hostdetails retrieves hostname and other useful audit info"
    Write-Both "    -domainaudit retrieves information about the AD such as functional level"
    Write-Both "    -trusts retrieves information about any doman trusts"
    Write-Both "    -accounts identifies account issues such as expired, disabled, etc..."
    Write-Both "    -passwordpolicy retrieves password policy information"
    Write-Both "    -ntds dumps the NTDS.dit file using ntdsutil"
    Write-Both "    -oldboxes identifies outdated OSs like 2000/2003/XP/Vista/7/2008 joined to the domain"
    Write-Both "    -gpo dumps the GPOs in XML and HTML for later analysis"
    Write-Both "    -ouperms checks generic OU permission issues"
    Write-Both "    -laps checks if LAPS is installed"
    Write-Both "    -authpolsilos checks for existence of authentication policies and silos"
    Write-Both "    -insecurednszone checks for insecure DNS zones"
    Write-Both "    -recentchanges checks for newly created users and groups (last 30 days)"
    Write-Both "    -spn checks for kerberoastable high value accounts"
    Write-Both "    -asrep checks for accounts with kerberos pre-auth"
    Write-Both "    -acl checks for dangerous ACL permissions on Computers, Users and Groups"
    Write-Both "    -ADCS checks for ESC1,2,3,4 and 8"
    Write-Both "    -ldapsecurity checks for multiple LDAP issues"
    Write-Both "    -all runs all checks, e.g. $scriptname -all"
    Write-Both "    -exclude allows you to exclude specific checks when using -all, e.g. $scriptname -all -exclude hostdetails,ntds"
    Write-Both "    -select allows you to exclude specific checks when using -all, e.g. $scriptname -all `"-gpo,ntds,acl`""
}
Write-Nessus-Footer

$endtime = Get-Date
Write-Both "[*] Script end time $endtime"
