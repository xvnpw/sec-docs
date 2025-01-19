# Attack Tree Analysis for openfaas/faas

Objective: Compromise application using OpenFaaS by executing arbitrary code within the OpenFaaS environment.

## Attack Tree Visualization

```
*   [CN] **Exploit Gateway Vulnerabilities**
    *   [HR] Bypass Authentication/Authorization
        *   [HR] Exploit Authentication Weakness (e.g., default credentials, weak hashing)
        *   [HR] Exploit Authorization Bypass (e.g., path traversal, missing checks)
    *   [HR] Exploit Gateway Software Vulnerabilities
        *   [HR] Exploit Known CVEs in Gateway Components (e.g., Go libraries)
    *   [HR] Abuse Gateway Functionality
        *   [HR] Function Path Injection: Manipulate function path to access unintended functions
*   Compromise Function Execution Environment
    *   [HR] Exploit Function Code Vulnerabilities
        *   [HR] Code Injection (e.g., command injection, SQL injection if interacting with DB)
        *   [HR] Path Traversal within Function Context
        *   [HR] Exploiting Dependencies with Known Vulnerabilities
    *   [HR] Exploit Function Configuration Issues
        *   [HR] Insecure Environment Variables: Access or modify sensitive environment variables
        *   [HR] Overly Permissive File System Access: Read or write sensitive files on the container
*   [CN] **Compromise Function Store/Registry**
    *   [HR] Exploit Registry Authentication/Authorization
        *   [HR] Access Registry with Stolen Credentials
    *   [HR] Inject Malicious Function Image
        *   [HR] Push Backdoored Image with Same Name/Tag
*   [CN] **Exploit Secrets Management Vulnerabilities**
    *   [HR] Access Secrets in Transit
        *   [HR] Intercept Communication between Gateway and Secrets Store (if not properly secured)
    *   [HR] Access Secrets at Rest
        *   [HR] Access Secrets due to Misconfiguration (e.g., overly permissive access controls)
    *   [HR] Exploit Secrets Handling in Functions
        *   [HR] Secrets Logged or Exposed in Error Messages
        *   [HR] Secrets Stored Insecurely within Function Code or Configuration
```


## Attack Tree Path: [[CN] **Exploit Gateway Vulnerabilities**](./attack_tree_paths/_cn__exploit_gateway_vulnerabilities.md)

**High-Risk Path: Bypass Authentication/Authorization:**
    *   **Exploit Authentication Weakness:** Attackers attempt to gain unauthorized access by exploiting weak or default credentials configured on the OpenFaaS Gateway. This could involve using common default passwords, brute-forcing weak passwords, or exploiting vulnerabilities in the authentication mechanism itself (e.g., weak hashing algorithms).
    *   **Exploit Authorization Bypass:** Even if authenticated, attackers try to circumvent authorization controls to access functions or resources they are not permitted to access. This can involve techniques like path traversal in function names, exploiting missing authorization checks for specific actions, or manipulating request parameters to bypass access controls.
**High-Risk Path: Exploit Gateway Software Vulnerabilities:**
    *   **Exploit Known CVEs in Gateway Components:** Attackers leverage publicly known vulnerabilities (Common Vulnerabilities and Exposures) in the software components and libraries used by the OpenFaaS Gateway (primarily Go libraries). They use existing exploits or develop their own to compromise the gateway.
**High-Risk Path: Abuse Gateway Functionality:**
    *   **Function Path Injection:** Attackers manipulate the function path in the request URL to target unintended functions or internal endpoints within the OpenFaaS system. By injecting special characters or relative paths, they might be able to access administrative functions or other sensitive resources.

## Attack Tree Path: [Compromise Function Execution Environment](./attack_tree_paths/compromise_function_execution_environment.md)

**High-Risk Path: Exploit Function Code Vulnerabilities**
    *   **Code Injection:** Attackers inject malicious code into the function's input, which is then executed by the function's interpreter or runtime. This can include:
        *   **Command Injection:** Injecting shell commands that are executed on the underlying operating system of the function's container.
        *   **SQL Injection:** Injecting malicious SQL queries that are executed against a database the function interacts with.
    *   **Path Traversal within Function Context:** Attackers exploit vulnerabilities in the function code to access files or directories outside the intended scope within the function's container. This could allow them to read sensitive configuration files, access secrets, or even overwrite critical files.
    *   **Exploiting Dependencies with Known Vulnerabilities:** Functions often rely on external libraries and packages. Attackers target known vulnerabilities in these dependencies to compromise the function's execution.
**High-Risk Path: Exploit Function Configuration Issues**
    *   **Insecure Environment Variables:** Attackers gain access to sensitive information (like API keys, database credentials, or other secrets) that are stored as environment variables within the function's container without proper protection or encryption.
    *   **Overly Permissive File System Access:** The function's container is configured with overly broad file system permissions, allowing attackers to read or write sensitive files that they should not have access to.

## Attack Tree Path: [[CN] **Compromise Function Store/Registry**](./attack_tree_paths/_cn__compromise_function_storeregistry.md)

**High-Risk Path: Exploit Registry Authentication/Authorization:**
    *   **Access Registry with Stolen Credentials:** Attackers obtain valid credentials (usernames and passwords or API keys) for the function store/registry (e.g., Docker Hub, a private registry). This allows them to perform actions like pulling, pushing, or deleting images.
**High-Risk Path: Inject Malicious Function Image:**
    *   **Push Backdoored Image with Same Name/Tag:** Attackers, having gained access to the registry, push a malicious function image with the same name and tag as a legitimate function. When OpenFaaS attempts to deploy or update this function, the backdoored image is used instead, leading to code execution within the OpenFaaS environment.

## Attack Tree Path: [[CN] **Exploit Secrets Management Vulnerabilities**](./attack_tree_paths/_cn__exploit_secrets_management_vulnerabilities.md)

**High-Risk Path: Access Secrets in Transit:**
    *   **Intercept Communication between Gateway and Secrets Store:** Attackers intercept the communication channel between the OpenFaaS Gateway and the secrets management system (e.g., HashiCorp Vault, Kubernetes Secrets). If this communication is not properly encrypted (e.g., using TLS), they can eavesdrop and extract sensitive secrets.
**High-Risk Path: Access Secrets at Rest:**
    *   **Access Secrets due to Misconfiguration:** Attackers exploit misconfigurations in the secrets management system, such as overly permissive access controls, to directly access and retrieve stored secrets.
**High-Risk Path: Exploit Secrets Handling in Functions:**
    *   **Secrets Logged or Exposed in Error Messages:** Developers inadvertently log secrets or expose them in error messages generated by the function. Attackers can then access these logs or error messages to retrieve the secrets.
    *   **Secrets Stored Insecurely within Function Code or Configuration:** Developers directly embed secrets within the function's source code or configuration files, making them easily accessible to anyone who can access the function's code or configuration.

