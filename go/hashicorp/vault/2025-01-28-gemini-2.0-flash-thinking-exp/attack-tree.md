# Attack Tree Analysis for hashicorp/vault

Objective: Compromise Application by Stealing Secrets Managed by Vault and Using Them to Gain Unauthorized Access or Control.

## Attack Tree Visualization

```
Compromise Application via Vault Secrets
├── OR
│   ├── 1. Exploit Vault Vulnerabilities [HIGH-RISK PATH]
│   │   ├── OR
│   │   │   ├── 1.1. Exploit Known Vault Vulnerabilities (CVEs) [HIGH-RISK PATH]
│   │   │   │   └── AND
│   │   │   │       └── 1.1.3. Execute Exploit [CRITICAL NODE]
│   │   │   ├── 1.2. Exploit Unknown Vault Vulnerabilities (0-day)
│   │   │   │   └── AND
│   │   │   │       └── 1.2.2. Develop and Execute 0-day Exploit [CRITICAL NODE]
│   │   │   ├── 1.3. Exploit Logical Vulnerabilities in Vault API/Features
│   │   │   │   └── AND
│   │   │   │       └── 1.3.2. Craft API Requests to Exploit Flaw [CRITICAL NODE]
│   ├── 2. Exploit Vault Misconfiguration [HIGH-RISK PATH]
│   │   ├── OR
│   │   │   ├── 2.1. Weak Authentication Configuration [HIGH-RISK PATH]
│   │   │   │   ├── OR
│   │   │   │   │   ├── 2.1.1. Default or Weak Root Token [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   │   ├── 2.1.2. Weak or Compromised Authentication Methods [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   │   │   ├── OR
│   │   │   │   │   │   │   ├── 2.1.2.1. Weak Password Policy for Userpass Auth [HIGH-RISK PATH]
│   │   │   │   │   │   │   ├── 2.1.2.2. Compromised Authentication Credentials (e.g., leaked API keys, stolen tokens) [HIGH-RISK PATH]
│   │   │   │   │   │   │   ├── 2.1.2.3. Misconfigured Authentication Backends (e.g., LDAP/AD bypass) [HIGH-RISK PATH]
│   │   │   │   ├── 2.2. Authorization Bypass (Policy Misconfiguration) [HIGH-RISK PATH]
│   │   │   │   │   └── AND
│   │   │   │   │       └── 2.2.2. Exploit Policy Flaws to Access Secrets Unintended for Attacker [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   ├── 2.3. Insecure Secret Engines Configuration [HIGH-RISK PATH]
│   │   │   │   │   ├── OR
│   │   │   │   │   │   ├── 2.3.1. Default Secret Engine Configuration Vulnerabilities [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   │   │   │   └── AND
│   │   │   │   │   │   │       └── 2.3.1.2. Exploit Default Weaknesses to Access Secrets [CRITICAL NODE]
│   │   │   │   │   │   ├── 2.3.2. Misconfigured Secret Engine Policies (e.g., overly broad access) [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   │   │   │   └── AND
│   │   │   │   │   │   │       └── 2.3.2.2. Exploit Policy Misconfiguration to Access Secrets [CRITICAL NODE]
│   │   │   │   ├── 2.4. Inadequate Audit Logging and Monitoring [Important Node - Facilitates High-Risk Paths] [CRITICAL NODE - Configuration Weakness]
│   │   │   │   │   └── AND
│   │   │   │   │       └── 2.4.1. Disable or Weak Audit Logging [CRITICAL NODE - Configuration Weakness]
│   │   │   │   ├── 2.5. Network Exposure of Vault API [Important Node - Facilitates High-Risk Paths] [CRITICAL NODE - Configuration Weakness]
│   │   │   │   │   └── AND
│   │   │   │   │       └── 2.5.1. Vault API Exposed to Public Network [CRITICAL NODE - Configuration Weakness]
│   │   │   │   ├── 2.6. Insecure Storage Backend Configuration [HIGH-RISK PATH]
│   │   │   │   │   ├── OR
│   │   │   │   │   │   ├── 2.6.1. Weak Encryption of Storage Backend [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   │   │   │   └── AND
│   │   │   │   │   │   │       └── 2.6.1.2. Decrypt Storage Backend Data to Extract Secrets [CRITICAL NODE]
│   │   │   │   │   │   ├── 2.6.2. Unauthorized Access to Storage Backend [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   │   │   │   └── AND
│   │   │   │   │   │   │       └── 2.6.2.2. Extract Encrypted Vault Data from Storage [CRITICAL NODE]
│   │   │   │   │   │   ├── 2.6.3. Storage Backend Vulnerabilities (e.g., SQL Injection in database backend) [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   │   │   │   └── AND
│   │   │   │   │   │   │       └── 2.6.3.2. Exploit Storage Backend Vulnerability to Access Data [CRITICAL NODE]
│   ├── 3. Compromise Application's Vault Client/Integration [HIGH-RISK PATH]
│   │   ├── OR
│   │   │   ├── 3.1. Leaked Secrets in Application Code/Configuration [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   ├── OR
│   │   │   │   │   ├── 3.1.1. Hardcoded Vault Tokens or Credentials in Application [CRITICAL NODE]
│   │   │   │   │   ├── 3.1.2. Extract Hardcoded Credentials from Application (e.g., reverse engineering, code review) [CRITICAL NODE]
│   │   │   │   ├── 3.2. Insecure Storage of Vault Tokens by Application [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   │   └── AND
│   │   │   │   │       ├── 3.2.1. Application Stores Vault Tokens Insecurely (e.g., plaintext files, easily accessible locations) [CRITICAL NODE]
│   │   │   │   │       └── 3.2.2. Access Insecurely Stored Tokens [CRITICAL NODE]
│   │   │   │   ├── 3.3. Vulnerabilities in Vault Client Libraries/SDKs
│   │   │   │   │   └── AND
│   │   │   │   │       └── 3.3.2. Exploit Client Library Vulnerability to Intercept or Steal Secrets [CRITICAL NODE]
│   │   │   │   ├── 3.4. Man-in-the-Middle (MITM) Attack on Vault Communication [HIGH-RISK PATH]
│   │   │   │   │   └── AND
│   │   │   │   │       └── 3.4.2. Steal Vault Tokens or Secrets in Transit [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   ├── 3.5. Server-Side Request Forgery (SSRF) via Application to Vault [HIGH-RISK PATH]
│   │   │   │   │   └── AND
│   │   │   │   │       └── 3.5.2. Use SSRF to Access Vault API from Application's Context [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   ├── 3.6. Log Injection/Exposure of Secrets [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   │   │   └── AND
│   │   │   │   │       └── 3.6.2. Access Application Logs to Retrieve Exposed Secrets [CRITICAL NODE]
│   ├── 4. Compromise Vault Infrastructure [Lower Likelihood, High Impact Path]
│   │   ├── OR
│   │   │   ├── 4.1. Compromise Vault Server Operating System [Lower Likelihood, High Impact Path]
│   │   │   │   └── AND
│   │   │   │       └── 4.1.2. Gain Root/Administrator Access to Vault Server [CRITICAL NODE]
│   │   │   │   ├── 4.2. Compromise Underlying Infrastructure (Cloud Provider, Network) [Lower Likelihood, High Impact Path]
│   │   │   │   │   └── AND
│   │   │   │   │       └── 4.2.2. Gain Access to Vault Server's Network or Infrastructure [CRITICAL NODE]
│   │   │   │   ├── 4.3. Physical Access to Vault Server (Less likely in cloud environments) [Very Low Likelihood Path]
│   │   │   │   │   └── AND
│   │   │   │   │       └── 4.3.2. Extract Secrets or Vault Data from Physical Server [CRITICAL NODE]
```

## Attack Tree Path: [1. Exploit Vault Vulnerabilities [HIGH-RISK PATH]:](./attack_tree_paths/1__exploit_vault_vulnerabilities__high-risk_path_.md)

*   **1.1. Exploit Known Vault Vulnerabilities (CVEs) [HIGH-RISK PATH]:**
    *   **1.1.3. Execute Exploit [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Exploiting publicly available exploits for known CVEs in the running Vault version.
            *   Adapting existing exploits to the specific Vault environment.
            *   Using vulnerability scanning tools to identify exploitable CVEs and potentially automate exploitation.

*   **1.2. Exploit Unknown Vault Vulnerabilities (0-day):**
    *   **1.2.2. Develop and Execute 0-day Exploit [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Reverse engineering Vault code to identify previously unknown vulnerabilities.
            *   Fuzzing Vault API and components to discover new vulnerabilities.
            *   Developing custom exploits for discovered 0-day vulnerabilities.

*   **1.3. Exploit Logical Vulnerabilities in Vault API/Features:**
    *   **1.3.2. Craft API Requests to Exploit Flaw [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Identifying logical flaws in Vault's API design or feature implementation.
            *   Crafting specific API requests that leverage these flaws to bypass intended security controls or gain unauthorized access.
            *   Exploiting race conditions or unexpected interactions between different Vault features.

## Attack Tree Path: [2. Exploit Vault Misconfiguration [HIGH-RISK PATH]:](./attack_tree_paths/2__exploit_vault_misconfiguration__high-risk_path_.md)

*   **2.1. Weak Authentication Configuration [HIGH-RISK PATH]:**
    *   **2.1.1. Default or Weak Root Token [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Attempting to guess default root tokens (if applicable and not changed).
            *   Brute-forcing weak root tokens if a weak password policy was used during initial setup.

    *   **2.1.2. Weak or Compromised Authentication Methods [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **2.1.2.1. Weak Password Policy for Userpass Auth [HIGH-RISK PATH]:**
            *   **Attack Vectors:**
                *   Password guessing attacks against user accounts.
                *   Brute-force attacks against user accounts with weak passwords.
                *   Credential stuffing using leaked password databases.

        *   **2.1.2.2. Compromised Authentication Credentials (e.g., leaked API keys, stolen tokens) [HIGH-RISK PATH]:**
            *   **Attack Vectors:**
                *   Searching for leaked Vault tokens or API keys on public repositories (e.g., GitHub), paste sites, or dark web forums.
                *   Phishing attacks or social engineering to steal Vault tokens or credentials from legitimate users.
                *   Compromising developer workstations or CI/CD systems to steal stored Vault credentials.

        *   **2.1.2.3. Misconfigured Authentication Backends (e.g., LDAP/AD bypass) [HIGH-RISK PATH]:**
            *   **Attack Vectors:**
                *   Exploiting misconfigurations in LDAP/AD integration to bypass authentication checks.
                *   Leveraging vulnerabilities in the authentication backend itself to gain unauthorized access to Vault.
                *   Exploiting overly permissive or default configurations in authentication backends.

*   **2.2. Authorization Bypass (Policy Misconfiguration) [HIGH-RISK PATH]:**
    *   **2.2.2. Exploit Policy Flaws to Access Secrets Unintended for Attacker [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Identifying overly permissive or poorly designed Vault policies that grant unintended access.
            *   Crafting API requests that exploit policy flaws to access secrets that should be restricted.
            *   Leveraging policy precedence or complex policy logic to bypass intended access controls.

*   **2.3. Insecure Secret Engines Configuration [HIGH-RISK PATH]:**
    *   **2.3.1. Default Secret Engine Configuration Vulnerabilities [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **2.3.1.2. Exploit Default Weaknesses to Access Secrets [CRITICAL NODE]:**
            *   **Attack Vectors:**
                *   Exploiting known vulnerabilities or weaknesses in default configurations of specific secret engines.
                *   Leveraging default credentials or overly permissive default access settings in secret engines.

    *   **2.3.2. Misconfigured Secret Engine Policies (e.g., overly broad access) [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **2.3.2.2. Exploit Policy Misconfiguration to Access Secrets [CRITICAL NODE]:**
            *   **Attack Vectors:**
                *   Identifying misconfigured secret engine policies that grant overly broad access to secrets within that engine.
                *   Exploiting these misconfigurations to access secrets that should be restricted based on the principle of least privilege.

*   **2.4. Inadequate Audit Logging and Monitoring [Important Node - Facilitates High-Risk Paths] [CRITICAL NODE - Configuration Weakness]:**
    *   **2.4.1. Disable or Weak Audit Logging [CRITICAL NODE - Configuration Weakness]:**
        *   **Attack Vectors:**
            *   Disabling audit logging entirely, leaving no record of malicious activity.
            *   Configuring weak audit logging that does not capture sufficient detail for effective detection and investigation.
            *   Storing audit logs insecurely, making them vulnerable to tampering or deletion by attackers.

*   **2.5. Network Exposure of Vault API [Important Node - Facilitates High-Risk Paths] [CRITICAL NODE - Configuration Weakness]:**
    *   **2.5.1. Vault API Exposed to Public Network [CRITICAL NODE - Configuration Weakness]:**
        *   **Attack Vectors:**
            *   Directly accessing the Vault API from the public internet, increasing the attack surface.
            *   Exposing Vault to a wider range of potential attackers and automated scanning tools.
            *   Making Vault vulnerable to brute-force attacks, vulnerability exploitation attempts, and other external threats.

*   **2.6. Insecure Storage Backend Configuration [HIGH-RISK PATH]:**
    *   **2.6.1. Weak Encryption of Storage Backend [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **2.6.1.2. Decrypt Storage Backend Data to Extract Secrets [CRITICAL NODE]:**
            *   **Attack Vectors:**
                *   Identifying weak encryption algorithms or key management practices used for the storage backend.
                *   Attempting to decrypt the storage backend data if weak encryption is used and the encryption key is compromised or discoverable.

    *   **2.6.2. Unauthorized Access to Storage Backend [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **2.6.2.2. Extract Encrypted Vault Data from Storage [CRITICAL NODE]:**
            *   **Attack Vectors:**
                *   Gaining unauthorized access to the underlying storage backend (e.g., filesystem, cloud storage service) through misconfigurations or vulnerabilities.
                *   Extracting the encrypted Vault data from the storage backend once access is gained.

    *   **2.6.3. Storage Backend Vulnerabilities (e.g., SQL Injection in database backend) [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **2.6.3.2. Exploit Storage Backend Vulnerability to Access Data [CRITICAL NODE]:**
            *   **Attack Vectors:**
                *   Identifying and exploiting vulnerabilities in the chosen storage backend (e.g., SQL injection in a database backend).
                *   Using these vulnerabilities to directly access and extract Vault data from the storage backend, bypassing Vault's API and security controls.

## Attack Tree Path: [3. Compromise Application's Vault Client/Integration [HIGH-RISK PATH]:](./attack_tree_paths/3__compromise_application's_vault_clientintegration__high-risk_path_.md)

*   **3.1. Leaked Secrets in Application Code/Configuration [HIGH-RISK PATH] [CRITICAL NODE]:**
    *   **3.1.1. Hardcoded Vault Tokens or Credentials in Application [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Developers accidentally or intentionally hardcoding Vault tokens or credentials directly into application source code.
            *   Storing Vault credentials in application configuration files that are not properly secured.

    *   **3.1.2. Extract Hardcoded Credentials from Application (e.g., reverse engineering, code review) [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Performing code review of application source code to find hardcoded credentials.
            *   Reverse engineering compiled application binaries to extract embedded credentials.
            *   Analyzing application configuration files to locate stored Vault credentials.

*   **3.2. Insecure Storage of Vault Tokens by Application [HIGH-RISK PATH] [CRITICAL NODE]:**
    *   **3.2.1. Application Stores Vault Tokens Insecurely (e.g., plaintext files, easily accessible locations) [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Applications storing Vault tokens in plaintext files on the server filesystem.
            *   Storing tokens in easily accessible locations within the application's deployment directory.
            *   Using insecure storage mechanisms that are vulnerable to unauthorized access.

    *   **3.2.2. Access Insecurely Stored Tokens [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Gaining access to the application server filesystem through vulnerabilities or misconfigurations.
            *   Reading insecurely stored token files directly from the filesystem.
            *   Exploiting application vulnerabilities to access token storage locations.

*   **3.3. Vulnerabilities in Vault Client Libraries/SDKs:**
    *   **3.3.2. Exploit Client Library Vulnerability to Intercept or Steal Secrets [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Exploiting known vulnerabilities in the Vault client library or SDK used by the application.
            *   Developing custom exploits that target client-side vulnerabilities to intercept or steal secrets during communication with Vault.

*   **3.4. Man-in-the-Middle (MITM) Attack on Vault Communication [HIGH-RISK PATH]:**
    *   **3.4.2. Steal Vault Tokens or Secrets in Transit [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Performing a Man-in-the-Middle attack to intercept network traffic between the application and Vault API.
            *   Exploiting TLS misconfigurations or lack of TLS enforcement to decrypt communication and steal Vault tokens or secrets in transit.

*   **3.5. Server-Side Request Forgery (SSRF) via Application to Vault [HIGH-RISK PATH]:**
    *   **3.5.2. Use SSRF to Access Vault API from Application's Context [HIGH-RISK PATH] [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Identifying and exploiting Server-Side Request Forgery (SSRF) vulnerabilities in the application.
            *   Crafting SSRF requests that target the Vault API endpoint, leveraging the application's network context and potentially its Vault authentication credentials.
            *   Using SSRF to read secrets from Vault that the application is authorized to access.

*   **3.6. Log Injection/Exposure of Secrets [HIGH-RISK PATH] [CRITICAL NODE]:**
    *   **3.6.2. Access Application Logs to Retrieve Exposed Secrets [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Developers accidentally logging secrets or Vault tokens in application logs, especially during debugging or error handling.
            *   Gaining unauthorized access to application logs through vulnerabilities or misconfigurations.
            *   Searching application logs for exposed secrets or tokens.

## Attack Tree Path: [4. Compromise Vault Infrastructure [Lower Likelihood, High Impact Path]:](./attack_tree_paths/4__compromise_vault_infrastructure__lower_likelihood__high_impact_path_.md)

*   **4.1. Compromise Vault Server Operating System [Lower Likelihood, High Impact Path]:**
    *   **4.1.2. Gain Root/Administrator Access to Vault Server [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Exploiting operating system vulnerabilities on the Vault server to gain root or administrator level access.
            *   Using weak or default credentials for OS accounts on the Vault server.
            *   Leveraging misconfigurations in the OS to escalate privileges.

*   **4.2. Compromise Underlying Infrastructure (Cloud Provider, Network) [Lower Likelihood, High Impact Path]:**
    *   **4.2.2. Gain Access to Vault Server's Network or Infrastructure [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Exploiting vulnerabilities or misconfigurations in the cloud provider's infrastructure or the network where Vault is deployed.
            *   Gaining unauthorized access to the network segment where the Vault server resides through lateral movement or network penetration techniques.

*   **4.3. Physical Access to Vault Server (Less likely in cloud environments) [Very Low Likelihood Path]:**
    *   **4.3.2. Extract Secrets or Vault Data from Physical Server [CRITICAL NODE]:**
        *   **Attack Vectors:**
            *   Gaining physical access to the Vault server hardware.
            *   Booting from alternative media to bypass OS security controls.
            *   Directly accessing storage devices to extract encrypted Vault data.
            *   Using memory dumping techniques to extract secrets from running Vault processes.

