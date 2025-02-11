# Attack Tree Analysis for openfaas/faas

Objective: Gain Unauthorized Code Execution and/or Exfiltrate Sensitive Data on OpenFaaS

## Attack Tree Visualization

```
                                     +-----------------------------------------------------+                                     |  Attacker Goal: Gain Unauthorized Code Execution   |                                     |  and/or Exfiltrate Sensitive Data on OpenFaaS      |                                     +-----------------------------------------------------+                                                        |
          +---------------------------------------------------------------------------------+          |                                                                                 |          |
+---------+---------+                                      +------------------------+------------------------+        +----------------+ |  Exploit Function  |                                      |   Compromise Gateway   | [CRITICAL NODE]       |        |  Abuse Cluster  | |     Deployment     |                                      |                        |                        |        |   Configuration  | +---------+---------+                                      +------------------------+------------------------+        +----------------+          |                                                              |                                                | +---------+---------+  +----------------+----------------+   +---------+---------+                                  +---------+---------+  +----------------+ | Malicious Function|  |  Function Input|  |  Gateway API  |  |  Gateway Auth  |                                  |  Provider   |   |  Secrets   | |     Code          |  |   Poisoning    |  |   Exposure   |  |   Bypass     |                                  |   API Abuse  |   |  Mismanagement| +---------+---------+  +----------------+----------------+   +---------+---------+                                  +---------+---------+  +----------------+          |                      |                                 |                      |                                                |                      | +---------+---------+  +---------+---------+  +---------+---------+  +---------+---------+                                  +---------+---------+  +---------+---------+ |  Known   |  |  Untrusted|  |  Missing |  |  Weak    |  |  Lack of |                                  |  AWS API |  |  Leaked   | |  Vuln.   |  |  Input    |  |  Input   |  |  Auth    |  |  RBAC    |                                  |  Exposure |  |  Secrets  | |  in Lib. |  |  Data     |  |  Validation|  |  /Token  |  |          |                                  | [CRITICAL |  |  (e.g.,    | | [HIGH RISK]|  | [HIGH RISK]|  | [HIGH RISK]|  |  Leak    |  |          |                                  |   NODE]   |  |  in Env)  | |          |  |          |  |          |  | [HIGH RISK]|  |          |                                  |          |  | [HIGH RISK]| +---------+---------+  +---------+---------+  +---------+---------+  +---------+---------+                                  +---------+---------+  +---------+---------+                                                                                                                                                  |                                                                                                                                        +---------+---------+                                                                                                                                        |  Read    |                                                                                                                                        |  Env.    |                                                                                                                                        |  Vars    |                                                                                                                                        | [HIGH RISK]|                                                                                                                                        +---------+---------+ ```

## Attack Tree Path: [1. Exploit Function Deployment (High Risk):](./attack_tree_paths/1__exploit_function_deployment__high_risk_.md)

*   **Malicious Function Code (Known Vulnerability in Library):**
    *   **Description:** An attacker deploys a function that intentionally includes a library with a known, exploitable vulnerability (e.g., a vulnerable version of a Node.js package, a Python library with a known CVE).
    *   **How it works:** The attacker crafts input to the function that triggers the vulnerability in the library, leading to arbitrary code execution within the function's container.
    *   **Mitigations:**
        *   **Vulnerability Scanning:** Implement rigorous dependency scanning during the build and deployment process. Use tools like `npm audit`, `snyk`, OWASP Dependency-Check, or similar tools for other languages.
        *   **Software Bill of Materials (SBOM):** Maintain an SBOM to track all dependencies and their versions.
        *   **Policy Enforcement:** Enforce policies that prevent deployment of functions with known high-severity vulnerabilities.
        *   **Runtime Protection:** Consider using runtime application self-protection (RASP) tools to detect and block exploitation attempts.

## Attack Tree Path: [2. Function Input Poisoning (High Risk):](./attack_tree_paths/2__function_input_poisoning__high_risk_.md)

*   **Untrusted Input Data:**
    *   **Description:** The function processes input from external sources (e.g., HTTP requests, message queues) without proper sanitization or validation. This can lead to various injection attacks.
    *   **How it works:**
        *   **Command Injection:** The attacker injects operating system commands into the input, which are then executed by the function.
        *   **SQL Injection:** If the function interacts with a database, the attacker injects SQL code to manipulate or exfiltrate data.
        *   **Cross-Site Scripting (XSS):** If the function's output is displayed in a web interface, the attacker injects malicious JavaScript code.
    *   **Mitigations:**
        *   **Input Validation:** Implement strict input validation using a whitelist approach (allow only known-good input patterns).
        *   **Input Sanitization:** Sanitize input by removing or escaping potentially dangerous characters.
        *   **Output Encoding:** Use appropriate output encoding to prevent XSS attacks.
        *   **Parameterized Queries:** Use parameterized queries or prepared statements to prevent SQL injection.
        *   **Web Application Firewall (WAF):** Deploy a WAF to filter malicious traffic.

*   **Missing Input Validation:**
    *   **Description:** The OpenFaaS gateway or the function itself lacks any input validation, allowing arbitrary data to be passed to the function.
    *   **How it works:** Similar to "Untrusted Input Data," but the vulnerability exists due to a complete absence of validation, rather than insufficient validation.
    *   **Mitigations:**
        *   **Gateway-Level Validation:** Implement input validation at the OpenFaaS gateway level using API schemas (e.g., OpenAPI/Swagger) to define expected input formats.
        *   **Function-Level Validation:** Implement input validation within the function code itself (as described above).  This provides defense-in-depth.

## Attack Tree Path: [3. Compromise Gateway (Critical Node, High Risk):](./attack_tree_paths/3__compromise_gateway__critical_node__high_risk_.md)

*   **Gateway API Exposure (Weak Auth/Token Leak):**
    *   **Description:** The OpenFaaS gateway API is exposed with weak authentication mechanisms (e.g., easily guessable passwords, default credentials) or an API key/token is accidentally leaked (e.g., committed to a public code repository, exposed in logs).
    *   **How it works:** The attacker uses the weak credentials or leaked token to gain unauthorized access to the gateway API, allowing them to deploy malicious functions, modify existing functions, or access sensitive data.
    *   **Mitigations:**
        *   **Strong Authentication:** Use strong authentication mechanisms like OAuth 2.0, mTLS, or JWT with robust key management.
        *   **API Key Rotation:** Regularly rotate API keys and tokens.
        *   **Secrets Management:** Store API keys securely using a secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets).  *Never* store secrets in code or environment variables directly.
        *   **Access Control:** Implement strict access control policies (RBAC) on the gateway API.
        *   **Monitoring:** Monitor API access logs for suspicious activity (e.g., failed login attempts, unusual API calls).

* **Gateway Auth Bypass (Lack of RBAC):**
    * **Description:** While authentication might be present, authorization is missing or improperly configured, allowing any authenticated user to perform any action.
    * **How it works:** An attacker, even with low-privileged credentials, can perform actions they shouldn't be able to, like deleting or modifying functions.
    * **Mitigations:**
        * **Implement RBAC:** Use OpenFaaS's built-in RBAC features or integrate with an external identity provider that supports RBAC.
        * **Principle of Least Privilege:** Grant users only the minimum necessary permissions.

## Attack Tree Path: [4. Abuse Cluster Configuration (Critical Node - Provider API, High Risk):](./attack_tree_paths/4__abuse_cluster_configuration__critical_node_-_provider_api__high_risk_.md)

*   **AWS API Exposure:**
    *   **Description:** If OpenFaaS is deployed on AWS, the AWS API is exposed with overly permissive IAM credentials (e.g., an IAM role with full access to all AWS services).
    *   **How it works:** The attacker obtains the AWS credentials (e.g., through a compromised function, a leaked access key) and uses them to access other AWS resources, potentially escalating privileges and causing significant damage.
    *   **Mitigations:**
        *   **IAM Roles:** Use IAM roles with the principle of least privilege.  Grant only the specific permissions required by OpenFaaS and the functions.
        *   **Temporary Credentials:** Use temporary credentials (e.g., STS) instead of long-lived access keys.
        *   **Credential Rotation:** Regularly rotate IAM credentials.
        *   **Monitoring:** Monitor AWS CloudTrail logs for suspicious activity.
        *   **Network Segmentation:** Use VPCs and security groups to restrict network access to AWS resources.

## Attack Tree Path: [5. Secrets Mismanagement (High Risk):](./attack_tree_paths/5__secrets_mismanagement__high_risk_.md)

*   **Leaked Secrets (e.g., in Env):**
    *   **Description:** Sensitive data, such as database credentials, API keys, or other secrets, are stored insecurely (e.g., in environment variables that are exposed to the function, hardcoded in the function code, or logged).
    *   **How it works:** The attacker gains access to the secrets through various means (e.g., exploiting a vulnerability in the function, accessing logs, compromising the gateway) and uses them to access other systems or data.
    *   **Mitigations:**
        *   **Secrets Management Solution:** Use a dedicated secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets).
        *   **Secure Injection:** Inject secrets into functions securely at runtime, *not* at build time.
        *   **Avoid Hardcoding:** *Never* hardcode secrets in the function code.
        *   **Environment Variable Security:** If environment variables *must* be used, encrypt them and ensure they are not exposed to unauthorized processes.

* **Read Env. Vars (High Risk):**
    * **Description:** An attacker gains the ability to read the environment variables of a running function container.
    * **How it works:** This could be through a vulnerability in the function runtime, a compromised container, or a misconfiguration that allows access to the container's environment.
    * **Mitigations:**
        * **Minimize Environment Variable Use:** Avoid storing sensitive data in environment variables whenever possible.
        * **Encryption:** If environment variables must be used for sensitive data, encrypt them.
        * **Secrets Management:** Prefer using a secrets management solution to inject secrets directly into the function's runtime.
        * **Container Security:** Implement strong container security practices, including using minimal base images, regularly scanning for vulnerabilities, and limiting container privileges.

