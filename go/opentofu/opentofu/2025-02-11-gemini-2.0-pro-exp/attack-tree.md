# Attack Tree Analysis for opentofu/opentofu

Objective: Gain Unauthorized Access/Control of Resources Managed by OpenTofu

## Attack Tree Visualization

Goal: Gain Unauthorized Access/Control of Resources Managed by OpenTofu
├── 1. Compromise OpenTofu State [CRITICAL]
│   ├── 1.1.  Tamper with State File (Remote Backend) [HIGH-RISK]
│   │   └── 1.1.1.  Exploit Backend Vulnerabilities (e.g., S3, Azure Blob Storage, GCS)
│   │       └── 1.1.1.1.  Misconfigured Permissions (Read/Write access too broad) [HIGH-RISK]
│   │       └── 1.1.1.3.  Compromised Backend Credentials (e.g., leaked access keys) [CRITICAL]
│   ├── 1.2.  Tamper with State File (Local Backend)
│   │   └── 1.2.1.  Unauthorized File System Access
│   │       └── 1.2.1.1.  Compromised User Account on Host Machine [CRITICAL]
│   │       └── 1.2.1.2.  Insecure File Permissions [HIGH-RISK]
│   └── 1.3.  State Poisoning via Malicious Modules/Providers
│       └── 1.3.1.  Supply Chain Attack on Provider/Module
│           └── 1.3.1.2. Typosquatting/Dependency Confusion [HIGH-RISK]
│       └── 1.3.2.  Malicious Code within Provider/Module
│           └── 1.3.2.2.  Unintentional Vulnerabilities Introduced by Provider/Module [HIGH-RISK]
├── 2. Exploit OpenTofu Core Vulnerabilities
│   └── 2.1.  Remote Code Execution (RCE) [CRITICAL]
├── 3. Misuse OpenTofu Features [HIGH-RISK]
    ├── 3.1.  Insecure Configuration [HIGH-RISK]
    │   ├── 3.1.1.  Hardcoded Credentials in Configuration Files [HIGH-RISK]
    │   ├── 3.1.2.  Overly Permissive Resource Configurations (e.g., open security groups) [HIGH-RISK]
    │   └── 3.1.4.  Using Outdated/Vulnerable Providers/Modules (without updates) [HIGH-RISK]
    ├── 3.2.  Abuse of `local-exec` or `remote-exec` Provisioners [CRITICAL]
    │   └── 3.2.1.  Executing Arbitrary Commands on Target Machines [CRITICAL]
    └── 3.3.  Data Destruction via `terraform destroy` (or OpenTofu equivalent) [CRITICAL]
        └── 3.3.2.  Malicious Destruction (e.g., compromised credentials used to run destroy) [CRITICAL]
├── 4.  Exploit OpenTofu Plugins
    ├── 4.1. Vulnerabilities in custom plugins [HIGH-RISK]
        ├── 4.1.1.  Poorly written plugin code [HIGH-RISK]
        ├── 4.1.2.  Lack of input validation in plugin [HIGH-RISK]
        └── 4.1.3.  Plugin dependencies with known vulnerabilities [HIGH-RISK]
    └── 4.2.  Plugin impersonation
        └── 4.2.1.  Replacing a legitimate plugin with a malicious one [CRITICAL]

## Attack Tree Path: [1. Compromise OpenTofu State [CRITICAL]](./attack_tree_paths/1__compromise_opentofu_state__critical_.md)

*   **Description:** This is the most critical node.  Gaining control of the state file allows an attacker to manipulate the infrastructure managed by OpenTofu.
*   **Sub-Vectors:**
    *   **1.1. Tamper with State File (Remote Backend) [HIGH-RISK]**
        *   **1.1.1.1. Misconfigured Permissions (Read/Write access too broad) [HIGH-RISK]:**
            *   *How:* The attacker exploits overly permissive access controls on the remote backend (e.g., S3 bucket, Azure Blob Storage container) to read, write, or delete the state file.
            *   *Example:* An S3 bucket policy allows any authenticated AWS user to write to the bucket containing the state file.
        *   **1.1.1.3. Compromised Backend Credentials (e.g., leaked access keys) [CRITICAL]:**
            *   *How:* The attacker obtains valid credentials for the remote backend (e.g., through phishing, credential stuffing, or finding them in exposed code repositories).
            *   *Example:* An AWS access key and secret key are accidentally committed to a public GitHub repository.
    *   **1.2. Tamper with State File (Local Backend)**
        *   **1.2.1.1. Compromised User Account on Host Machine [CRITICAL]:**
            *   *How:* The attacker gains access to the user account on the machine where the OpenTofu state file is stored locally.
            *   *Example:* An attacker uses a stolen password or exploits a vulnerability to gain shell access to the machine.
        *   **1.2.1.2. Insecure File Permissions [HIGH-RISK]:**
            *   *How:* The state file has overly permissive file system permissions, allowing unauthorized users on the local machine to read or modify it.
            *   *Example:* The state file has world-readable permissions (e.g., `chmod 666`).
    *   **1.3. State Poisoning via Malicious Modules/Providers**
        *   **1.3.1.2. Typosquatting/Dependency Confusion [HIGH-RISK]:**
            *   *How:* The attacker publishes a malicious module or provider with a name similar to a legitimate one, tricking users into installing it.
            *   *Example:* An attacker publishes a module named `aws-vpc-modu1e` (note the `1` instead of `l`) that contains malicious code.
        *   **1.3.2.2. Unintentional Vulnerabilities Introduced by Provider/Module [HIGH-RISK]:**
            *   *How:* A legitimate provider or module contains a vulnerability that can be exploited to modify the state or gain control of resources.
            *   *Example:* A provider has a bug that allows an attacker to inject arbitrary commands into a resource configuration.

## Attack Tree Path: [2. Exploit OpenTofu Core Vulnerabilities](./attack_tree_paths/2__exploit_opentofu_core_vulnerabilities.md)

*   **2.1. Remote Code Execution (RCE) [CRITICAL]:**
    *   *How:* The attacker exploits a vulnerability in OpenTofu's core code (e.g., in HCL parsing, provider interaction, or internal logic) to execute arbitrary code on the machine running OpenTofu.
    *   *Example:* A buffer overflow vulnerability in the HCL parser allows an attacker to inject and execute malicious code.

## Attack Tree Path: [3. Misuse OpenTofu Features [HIGH-RISK]](./attack_tree_paths/3__misuse_opentofu_features__high-risk_.md)

*   **Description:** This path involves exploiting insecure configurations or misusing OpenTofu's features.
*   **Sub-Vectors:**
    *   **3.1. Insecure Configuration [HIGH-RISK]**
        *   **3.1.1. Hardcoded Credentials in Configuration Files [HIGH-RISK]:**
            *   *How:* The attacker gains access to OpenTofu configuration files that contain hardcoded credentials (e.g., API keys, passwords).
            *   *Example:* An OpenTofu configuration file contains an AWS access key and secret key directly embedded in the code.
        *   **3.1.2. Overly Permissive Resource Configurations (e.g., open security groups) [HIGH-RISK]:**
            *   *How:* The OpenTofu configuration creates resources with overly permissive security settings, allowing unauthorized access.
            *   *Example:* An OpenTofu configuration creates an AWS security group that allows inbound traffic from any IP address on port 22 (SSH).
        *   **3.1.4. Using Outdated/Vulnerable Providers/Modules (without updates) [HIGH-RISK]:**
            *   *How:* The OpenTofu configuration uses providers or modules with known vulnerabilities that have not been patched.
            *   *Example:* Using an outdated version of the AWS provider that has a known vulnerability allowing privilege escalation.
    *   **3.2. Abuse of `local-exec` or `remote-exec` Provisioners [CRITICAL]**
        *   **3.2.1. Executing Arbitrary Commands on Target Machines [CRITICAL]:**
            *   *How:* The attacker uses `local-exec` or `remote-exec` provisioners to execute arbitrary commands on the machines managed by OpenTofu.
            *   *Example:* An OpenTofu configuration uses `remote-exec` to run a malicious script on a newly provisioned EC2 instance.
    *   **3.3. Data Destruction via `terraform destroy` (or OpenTofu equivalent) [CRITICAL]**
        *   **3.3.2. Malicious Destruction (e.g., compromised credentials used to run destroy) [CRITICAL]:**
            *   *How:* The attacker gains access to credentials with sufficient permissions and uses them to run `tofu destroy`, deleting resources.
            *   *Example:* An attacker uses stolen AWS credentials to run `tofu destroy` on a production environment.

## Attack Tree Path: [4. Exploit OpenTofu Plugins](./attack_tree_paths/4__exploit_opentofu_plugins.md)

*   **Sub-Vectors:**
    *   **4.1. Vulnerabilities in custom plugins [HIGH-RISK]**
        *   **4.1.1. Poorly written plugin code [HIGH-RISK]:**
            * *How:* Custom-developed plugins contain vulnerabilities due to coding errors.
            * *Example:* A plugin doesn't properly sanitize user input, leading to a command injection vulnerability.
        *   **4.1.2. Lack of input validation in plugin [HIGH-RISK]:**
            * *How:* The plugin fails to validate input, making it susceptible to injection attacks.
            * *Example:* A plugin accepts arbitrary strings for a resource name without sanitization.
        *   **4.1.3. Plugin dependencies with known vulnerabilities [HIGH-RISK]:**
            * *How:* The plugin relies on third-party libraries with known vulnerabilities.
            * *Example:* A plugin uses an outdated version of a logging library with a known RCE vulnerability.
    *   **4.2. Plugin impersonation**
        *   **4.2.1. Replacing a legitimate plugin with a malicious one [CRITICAL]:**
            *   *How:* The attacker replaces a legitimate OpenTofu plugin with a malicious one, either on the local filesystem or by compromising the plugin distribution mechanism.
            *   *Example:* An attacker replaces the `aws` provider plugin with a modified version that steals credentials.

