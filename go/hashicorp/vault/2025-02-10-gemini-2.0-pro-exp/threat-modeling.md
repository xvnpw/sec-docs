# Threat Model Analysis for hashicorp/vault

## Threat: [Compromised Vault Token (Stolen or Leaked)](./threats/compromised_vault_token__stolen_or_leaked_.md)

*   **Threat:** Compromised Vault Token (Stolen or Leaked)

    *   **Description:** An attacker obtains a valid Vault token through various means, such as:
        *   Phishing a developer or operator.
        *   Exploiting a vulnerability in a CI/CD pipeline that exposes the token.
        *   Finding the token in a compromised system's logs or environment variables.
        *   Gaining access to a compromised machine where the token is stored insecurely.
        *   Exploiting a vulnerability in the application that leaks the token.

    *   **Impact:** The attacker can use the stolen token to authenticate to Vault and access secrets according to the token's associated policies. This can lead to:
        *   Data breaches (reading sensitive data).
        *   System compromise (using secrets to access other systems).
        *   Denial of service (revoking other tokens or leases).
        *   Privilege escalation (if the token has excessive permissions).

    *   **Vault Component Affected:**
        *   `auth/*` methods (all authentication methods are potential entry points).
        *   Token store.
        *   Any secret engine the token has access to.

    *   **Risk Severity:** Critical

    *   **Mitigation Strategies:**
        *   **Short-Lived Tokens:** Use tokens with short Time-To-Live (TTL) values.
        *   **Least Privilege:** Enforce strict, granular policies that limit token access to only necessary secrets.
        *   **Response Wrapping:** Use response wrapping to securely deliver initial tokens.
        *   **Token Revocation:** Implement procedures for immediate token revocation upon suspicion of compromise.
        *   **Secure Token Storage:**  Store tokens securely on the client-side (e.g., using secure environment variables, encrypted configuration files, or dedicated secret management tools).  Avoid hardcoding tokens.
        *   **Audit Logging:** Enable and monitor audit logs for token usage and suspicious activity.
        *   **Multi-Factor Authentication (MFA):**  If using auth methods that support it, enable MFA for an additional layer of security.
        *   **Token Usage Limits:**  Consider using token usage limits to restrict the number of times a token can be used.
        *   **CIDR Restrictions:** If applicable, restrict token usage to specific IP address ranges.

## Threat: [Weak Authentication Method Exploitation](./threats/weak_authentication_method_exploitation.md)

*   **Threat:** Weak Authentication Method Exploitation

    *   **Description:** An attacker exploits a weak authentication method configured in Vault, such as:
        *   Brute-forcing a weak username/password combination.
        *   Guessing or obtaining a static AppRole SecretID.
        *   Exploiting a misconfigured Kubernetes Service Account Token integration.
        *   Using a compromised TLS certificate.

    *   **Impact:** The attacker gains unauthorized access to Vault, potentially obtaining a token with privileges defined by the compromised authentication method.  This leads to similar consequences as a compromised token (data breach, system compromise, etc.).

    *   **Vault Component Affected:**
        *   Specific `auth/*` method being exploited (e.g., `auth/userpass`, `auth/approle`, `auth/kubernetes`, `auth/cert`).

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Strong Authentication:**  Use strong authentication methods.  Prefer AppRole with dynamic SecretID generation and CIDR restrictions, Kubernetes Service Account Tokens with proper RBAC configuration, or TLS certificates with strong key management.
        *   **Avoid Weak Methods:**  Avoid username/password authentication unless absolutely necessary and enforce strong password policies and MFA.
        *   **Regular Rotation:**  Rotate authentication credentials regularly (e.g., AppRole SecretIDs, TLS certificates).
        *   **Rate Limiting:** Implement rate limiting on authentication attempts to prevent brute-force attacks.
        *   **Monitoring:** Monitor authentication logs for failed attempts and suspicious activity.

## Threat: [Policy Misconfiguration (Overly Permissive Policies)](./threats/policy_misconfiguration__overly_permissive_policies_.md)

*   **Threat:** Policy Misconfiguration (Overly Permissive Policies)

    *   **Description:** Vault policies are configured too broadly, granting excessive permissions to users or applications.  This might involve:
        *   Using wildcard characters (`*`) excessively in paths.
        *   Granting unnecessary capabilities (e.g., `sudo`, `root`).
        *   Failing to restrict access to specific secret engines or paths.

    *   **Impact:**  A compromised token or a malicious insider with limited privileges can access a wider range of secrets than intended, significantly increasing the impact of a breach.

    *   **Vault Component Affected:**
        *   Policy engine (`sys/policy`).
        *   All secret engines and auth methods governed by the misconfigured policies.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Principle of Least Privilege:**  Create granular policies that grant only the *minimum* necessary access to specific secrets and paths.
        *   **Avoid Wildcards:**  Minimize the use of wildcard characters in paths.  Be specific.
        *   **Regular Audits:**  Regularly review and audit Vault policies to identify and correct overly permissive configurations.
        *   **Policy Version Control:**  Use version control (e.g., Git) to track policy changes and facilitate rollbacks.
        *   **Policy Testing:**  Thoroughly test policies before deploying them to production.
        *   **Policy Review Process:** Implement a formal review and approval process for all policy changes.

## Threat: [Vault Server Compromise (OS or Application Vulnerability)](./threats/vault_server_compromise__os_or_application_vulnerability_.md)

*   **Threat:** Vault Server Compromise (OS or Application Vulnerability)

    *   **Description:** An attacker exploits a vulnerability in the operating system or the Vault application itself to gain access to the Vault server. This could involve:
        *   Exploiting an unpatched OS vulnerability.
        *   Exploiting a vulnerability in a Vault plugin.
        *   Gaining SSH access through compromised credentials.

    *   **Impact:**  Potentially complete compromise of Vault, including access to the master key (if unsealed), all stored secrets, and the ability to modify Vault's configuration. This is a catastrophic scenario.

    *   **Vault Component Affected:**
        *   Entire Vault server.
        *   All secret engines and auth methods.
        *   Storage backend.

    *   **Risk Severity:** Critical

    *   **Mitigation Strategies:**
        *   **OS Hardening:**  Harden the operating system of the Vault servers according to security best practices.
        *   **Regular Patching:**  Apply security patches to the operating system and Vault software promptly.
        *   **Vulnerability Scanning:**  Regularly scan the Vault servers for vulnerabilities.
        *   **Intrusion Detection/Prevention:**  Implement intrusion detection and prevention systems (IDS/IPS).
        *   **Limited Access:**  Restrict access to the Vault servers to only authorized personnel and systems.
        *   **Network Segmentation:**  Isolate Vault servers in a dedicated, secure network segment.
        *   **Minimal Software:**  Install only the necessary software on the Vault servers to reduce the attack surface.
        *   **Secure Configuration:**  Follow Vault's security hardening guidelines.

## Threat: [Storage Backend Compromise](./threats/storage_backend_compromise.md)

*   **Threat:** Storage Backend Compromise

    *   **Description:** An attacker gains access to the storage backend used by Vault (e.g., Consul, etcd, a database) and either:
        *   Directly reads the (encrypted) data.
        *   Modifies the data, potentially corrupting Vault's state.
        *   Deletes the data, causing data loss.

    *   **Impact:**  While the data is encrypted at rest by Vault, a compromised backend could allow an attacker to:
        *   Attempt to decrypt the data offline (if they obtain the master key through other means).
        *   Cause denial of service by corrupting or deleting data.
        *   Potentially bypass Vault's access controls if they can modify the backend data directly.

    *   **Vault Component Affected:**
        *   Storage backend (e.g., `storage/consul`, `storage/etcd`, `storage/mysql`, etc.).

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Secure Backend:**  Secure the storage backend according to its own security best practices (e.g., authentication, authorization, encryption at rest, network security).
        *   **Regular Backups:**  Implement regular, secure backups of the storage backend.
        *   **Monitoring:**  Monitor the storage backend for suspicious activity and performance issues.
        *   **Access Control:**  Restrict access to the storage backend to only the Vault servers.
        *   **Encryption at Rest (Backend):** Ensure the storage backend itself also encrypts data at rest, providing an additional layer of defense.

## Threat: [Denial of Service (DoS) against Vault](./threats/denial_of_service__dos__against_vault.md)

*   **Threat:** Denial of Service (DoS) against Vault

    *   **Description:** An attacker floods Vault with requests, overwhelming its resources and making it unavailable to legitimate applications. This could be done by:
        *   Sending a large number of authentication requests.
        *   Making excessive requests to read or write secrets.
        *   Exploiting a vulnerability that causes Vault to consume excessive resources.

    *   **Impact:** Applications that rely on Vault for secrets are unable to function, leading to service disruption.

    *   **Vault Component Affected:**
        *   `api` (Vault's API endpoint).
        *   Potentially all secret engines and auth methods.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Rate Limiting:** Implement rate limiting on Vault API requests to prevent abuse.
        *   **High Availability:** Deploy Vault in a highly available cluster to distribute the load and provide redundancy.
        *   **Resource Limits:** Configure resource limits (e.g., memory, CPU) on the Vault servers to prevent resource exhaustion.
        *   **Network Security:** Implement network security controls (e.g., firewalls, DDoS protection) to mitigate network-based DoS attacks.
        *   **Monitoring:** Monitor Vault's performance and resource utilization to detect and respond to DoS attacks.
        * **Request Size Limits:** Limit the size of requests to the Vault API.

## Threat: [Audit Log Tampering or Deletion](./threats/audit_log_tampering_or_deletion.md)

* **Threat:** Audit Log Tampering or Deletion

    * **Description:** An attacker, having gained sufficient privileges within Vault or on the system hosting the audit logs, modifies or deletes the audit logs to conceal their malicious activities.

    * **Impact:** Loss of crucial forensic information, hindering incident response and making it difficult or impossible to determine the scope of a breach and the actions taken by the attacker.

    * **Vault Component Affected:**
        * `audit/*` (audit devices).
        * The system or service where audit logs are stored.

    * **Risk Severity:** High

    * **Mitigation Strategies:**
        * **Multiple Audit Destinations:** Configure Vault to send audit logs to multiple destinations (e.g., syslog, a SIEM system, a dedicated logging server).
        * **WORM Storage:** Use a write-once, read-many (WORM) storage solution for audit logs to prevent modification or deletion.
        * **Access Control:** Implement strict access controls to the audit logs, limiting access to authorized personnel only.
        * **Integrity Monitoring:** Implement file integrity monitoring (FIM) on the audit log files to detect unauthorized changes.
        * **Regular Review:** Regularly review audit logs for suspicious activity.
        * **Alerting:** Configure alerts for any attempts to modify or delete audit logs.

## Threat: [Unsealed Vault (After Restart or Failure)](./threats/unsealed_vault__after_restart_or_failure_.md)

* **Threat:** Unsealed Vault (After Restart or Failure)

    * **Description:** After a restart or a failure, Vault is in an unsealed state, meaning the master key is in memory and the data is accessible. An attacker with access to the server during this window could access all secrets.

    * **Impact:** Complete exposure of all secrets stored in Vault.

    * **Vault Component Affected:**
        * `core` (Vault's core functionality).
        * All secret engines.

    * **Risk Severity:** Critical

    * **Mitigation Strategies:**
        * **Auto-Unseal:** Use auto-unseal with a trusted KMS (Key Management Service) like AWS KMS, Azure Key Vault, or GCP Cloud KMS. This automates the unsealing process.
        * **Shamir's Secret Sharing:** Distribute unseal keys among multiple trusted individuals using Shamir's Secret Sharing.
        * **Minimize Unseal Window:** Minimize the time Vault remains in an unsealed state.
        * **Monitoring:** Implement monitoring and alerting for Vault's seal status.
        * **Physical Security:** Ensure physical security of the Vault servers.

## Threat: [Improper Secret Rotation](./threats/improper_secret_rotation.md)

* **Threat:** Improper Secret Rotation

    * **Description:** Secrets are not rotated regularly, or the rotation process is flawed, leading to:
        *   Long-lived secrets that are more vulnerable to compromise.
        *   Failed rotation attempts that leave old secrets valid.
        *   Lack of a consistent rotation schedule.

    * **Impact:** Increased risk of secret compromise. If a secret is compromised, the attacker has long-term access.

    * **Vault Component Affected:**
        * Secret engines that support rotation (e.g., `database`, `aws`, `pki`).
        * `sys/leases` (for lease-based secrets).

    * **Risk Severity:** High

    * **Mitigation Strategies:**
        * **Automated Rotation:** Implement automated secret rotation using Vault's dynamic secrets or other mechanisms.
        * **Rotation Schedule:** Establish a regular rotation schedule for all secrets, based on their sensitivity and risk.
        * **Rotation Testing:** Thoroughly test secret rotation procedures to ensure they work correctly.
        * **Monitoring:** Monitor secret rotation events and ensure they are successful.
        * **Rollback Plan:** Have a rollback plan in case secret rotation fails.

## Threat: [Improper Secret Revocation](./threats/improper_secret_revocation.md)

* **Threat:** Improper Secret Revocation

    * **Description:** Secrets are not revoked properly when they are no longer needed, or when a security incident occurs. This includes:
        *   Failing to revoke tokens associated with terminated employees or compromised systems.
        *   Not revoking leases when they expire.
        *   Leaving old secrets valid after a rotation.

    * **Impact:** Leaked or compromised secrets remain valid, allowing continued unauthorized access.

    * **Vault Component Affected:**
        * `sys/leases` (for lease-based secrets).
        * `auth/*` (for tokens).
        * Secret engines that support revocation.

    * **Risk Severity:** High

    * **Mitigation Strategies:**
        * **Revocation Procedures:** Implement a clear process for revoking secrets.
        * **Lease Management:** Use Vault's lease mechanism and revoke secrets when leases expire.
        * **Immediate Revocation:** Immediately revoke secrets associated with compromised tokens, systems, or users.
        * **Automation:** Automate secret revocation where possible.
        * **Auditing:** Audit secret revocation events to ensure they are performed correctly.

