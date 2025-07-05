Overview

    This PowerShell script serves as a Proof-of-Concept (PoC) to demonstrate the AdminSDHolder persistence technique in Active Directory. It automates the process of adding a malicious Access Control Entry (ACE) to the `AdminSDHolder` object's Discretionary Access Control List (DACL). This grants an attacker-controlled user `Full Control` over all "protected" Active Directory accounts (e.g., Domain Admins, Enterprise Admins) once the SDProp process executes. The script leverages native PowerShell and .NET Framework methods (`System.DirectoryServices`) to interact with Active Directory, avoiding reliance on RSAT tools, which is typical for real-world attack scenarios.
    
How the Attack Works

    The AdminSDHolder object and the SDProp process are crucial security mechanisms in Active Directory designed to protect highly privileged accounts.

    1.  **AdminSDHolder:** A special object in Active Directory (`CN=AdminSDHolder,CN=System,DC=yourdomain,DC=com`) that holds the default security permissions (DACL) for sensitive groups (like Domain Admins) and their members.
    2.  **SDProp Process:** A background process (runs every ~60 minutes on the PDC Emulator) that ensures all protected accounts (those with `adminCount=1`) have their DACLs synchronized with the `AdminSDHolder` object's DACL. This prevents accidental or malicious permission changes on these critical accounts.

    An attacker who gains temporary administrative access can manipulate the system's defensive mechanism for persistence:
    - They add a malicious ACE to the `AdminSDHolder` object's DACL, giving their controlled user (or a newly created backdoor user) `GenericAll` (Full Control) rights.
    - When SDProp runs, it propagates this newly added malicious ACE to *all* protected accounts.
    - Even if the attacker's initial access is revoked (e.g., removed from Domain Admins), their backdoor user will still have `Full Control` over `Domain Admins`.

    -   A machine joined to the target Active Directory domain.
    -   The user running the script must have **Domain Administrator privileges** or equivalent permissions that allow modifying the DACL of the `AdminSDHolder` object.
    -   Network connectivity to a Domain Controller.

The script is structured into clear steps:

    -   **Domain Identification:** Dynamically discovers the current Active Directory domain's Distinguished Name using `System.DirectoryServices.ActiveDirectory.Domain`.
    -   **AdminSDHolder Location:** Constructs the LDAP path to the `AdminSDHolder` object.
    -   **Attacker User Resolution:** Finds the SID (Security Identifier) of the specified attacker username using `System.Security.Principal.NTAccount`.
    -   **DACL Retrieval:** Obtains the current Discretionary Access Control List (DACL) of the `AdminSDHolder` object.
    -   **ACE Construction:** Creates a new `Access Control Entry` (ACE) of type `Allow` for the attacker's SID, granting `GenericAll` rights (which equate to Full Control over Active Directory objects).
    -   **ACE Addition & Application:** Adds the newly created ACE to the retrieved DACL and then updates the `AdminSDHolder` object with the modified DACL.

Usage

    Clone it

    Edit : $AttackerUserName = "Your Target UserName" : Only Edit This 

    Run !


    
