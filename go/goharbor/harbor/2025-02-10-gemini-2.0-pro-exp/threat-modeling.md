# Threat Model Analysis for goharbor/harbor

## Threat: [Unauthorized Registry Access via Default/Weak Admin Credentials](./threats/unauthorized_registry_access_via_defaultweak_admin_credentials.md)

*   **Threat:** Unauthorized Registry Access via Default/Weak Admin Credentials

    *   **Description:** An attacker gains administrative access to Harbor using the default `admin` credentials or by guessing a weak password. The attacker uses the Harbor UI or API for login attempts.
    *   **Impact:** Complete control over the Harbor registry. The attacker can delete, modify, or push images, change configurations, and potentially compromise connected systems.
    *   **Affected Component:** Harbor Core (Authentication module, user database, login logic).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Immediately change the default administrator password after installation.
        *   Enforce strong password policies (length, complexity).
        *   Implement multi-factor authentication (MFA) for administrative accounts.
        *   Integrate with an external identity provider (LDAP, OIDC).

## Threat: [Privilege Escalation via RBAC Misconfiguration](./threats/privilege_escalation_via_rbac_misconfiguration.md)

*   **Threat:** Privilege Escalation via RBAC Misconfiguration

    *   **Description:** An attacker, initially with limited access, exploits misconfigured Role-Based Access Control (RBAC) settings to gain higher privileges within Harbor. This might involve finding a project where they have unintended "Project Admin" or "Maintainer" rights.
    *   **Impact:** Unauthorized access to projects and images, allowing the attacker to push malicious images or delete critical ones.
    *   **Affected Component:** Harbor Core (RBAC module, project and user role assignments).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Strictly adhere to the principle of least privilege.
        *   Regularly audit user roles and permissions.
        *   Clearly define roles and responsibilities, mapping them to Harbor's RBAC.
        *   Use project-level RBAC for isolation.

## Threat: [Robot Account Credential Leakage](./threats/robot_account_credential_leakage.md)

*   **Threat:** Robot Account Credential Leakage

    *   **Description:** An attacker obtains credentials for a Harbor robot account. Credentials might be leaked through insecure CI/CD configurations, exposed environment variables, or accidental commits. The attacker uses these credentials via the Harbor API.
    *   **Impact:** The attacker gains registry access with the robot account's privileges, potentially pushing or pulling images.
    *   **Affected Component:** Harbor Core (Robot account management, API authentication).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Store credentials securely using a secrets management solution.
        *   Never hardcode credentials.
        *   Rotate credentials regularly.
        *   Limit robot account permissions.
        *   Monitor robot account activity.

## Threat: [Image Tampering (Malicious Image Injection)](./threats/image_tampering__malicious_image_injection_.md)

*   **Threat:** Image Tampering (Malicious Image Injection)

    *   **Description:** An attacker with write access (compromised credentials or RBAC exploitation) modifies an existing image or pushes a new, malicious image disguised as legitimate. They use the Harbor API or UI for the push.
    *   **Impact:** Deployment of compromised applications with backdoors, malware, or data exfiltration.
    *   **Affected Component:** Harbor Core (Registry, image storage).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Enable and enforce image signing (Notary/Cosign).
        *   Implement strict RBAC to limit write access.
        *   Use immutable tags.

## Threat: [Exposure of Internal Harbor Components](./threats/exposure_of_internal_harbor_components.md)

*   **Threat:** Exposure of Internal Harbor Components

    *   **Description:** An attacker directly accesses Harbor's internal components (database, job service, registry backend) due to exposure to the public internet or an untrusted network (misconfigured network/firewall).
    *   **Impact:** Complete compromise of the Harbor instance, data loss, potential lateral movement.
    *   **Affected Component:** All Harbor components (Core, Database, Job Service, Registry).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Deploy Harbor in a secure, isolated network.
        *   Use firewalls and network segmentation.
        *   Never expose internal components directly to the internet.
        *   Use a reverse proxy.

## Threat: [Exploitation of Unpatched Harbor Vulnerabilities](./threats/exploitation_of_unpatched_harbor_vulnerabilities.md)

*   **Threat:** Exploitation of Unpatched Harbor Vulnerabilities

    *   **Description:** An attacker exploits a known vulnerability in an outdated Harbor version. The attacker likely uses a public exploit or develops one based on disclosed information.
    *   **Impact:** Varies, but could range from information disclosure to complete system compromise.
    *   **Affected Component:** Potentially any Harbor component.
    *   **Risk Severity:** High (or Critical, depending on the vulnerability)
    *   **Mitigation Strategies:**
        *   Regularly update Harbor.
        *   Subscribe to security advisories.
        *   Implement a vulnerability management process.

## Threat: [Running Harbor with Excessive Privileges](./threats/running_harbor_with_excessive_privileges.md)

* **Threat:** Running Harbor with Excessive Privileges

    * **Description:** Harbor components (e.g., the registry container) run with root privileges or unnecessary container capabilities.  An attacker compromising a container could escalate to the host.
    * **Impact:** Increased blast radius; potential for host system takeover.
    * **Affected Component:** Harbor Core (Registry container, potentially other containers).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Run containers with non-root users.
        * Restrict container capabilities.
        * Use security contexts (e.g., `securityContext` in Kubernetes).

