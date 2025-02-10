# Attack Surface Analysis for goharbor/harbor

## Attack Surface: [Authentication and Authorization (Harbor-Specific Aspects)](./attack_surfaces/authentication_and_authorization__harbor-specific_aspects_.md)

*   **Description:** Attacks targeting Harbor's user accounts, robot accounts, and *misconfigured* integrated authentication systems (LDAP, OIDC).  Focus is on Harbor's implementation and configuration.
*   **Harbor Contribution:** Harbor provides and manages these authentication mechanisms, making misconfiguration or exploitation directly related to Harbor's security.
*   **Example:**
    *   An attacker exploits a *misconfigured* LDAP integration within Harbor to gain elevated privileges.  This is distinct from a general LDAP vulnerability; it's about how Harbor *uses* LDAP.
    *   A compromised robot account token *created within Harbor* is used to push malicious images.
    *   The *default Harbor admin password* is not changed, allowing immediate compromise.
*   **Impact:** Unauthorized access to images, projects, and administrative functions; potential for complete system compromise.
*   **Risk Severity:** Critical (for default admin password issues, compromised admin accounts, severely misconfigured integrations), High (for compromised robot accounts, moderately misconfigured integrations).
*   **Mitigation Strategies:**
    *   **Developers:** Provide secure-by-default configurations.  Implement robust validation of LDAP/OIDC settings *within Harbor*.  Enforce immediate change of default admin password.  Design robot accounts with least privilege and clear scoping *within Harbor's context*.
    *   **Users:** *Immediately* change the default admin password.  Carefully configure and *thoroughly test* LDAP/OIDC integrations *using Harbor's interface and documentation*.  Regularly review and rotate robot account tokens *managed within Harbor*.  Use strong, unique passwords for all Harbor accounts.

## Attack Surface: [Image Signing and Trust (Notary Integration)](./attack_surfaces/image_signing_and_trust__notary_integration_.md)

*   **Description:** Attacks targeting Harbor's integration with Notary, specifically focusing on the compromise of the Notary server or signing keys *used by Harbor*, or exploitation of trust in unsigned/improperly signed images *within the Harbor context*.
*   **Harbor Contribution:** Harbor's security relies heavily on the proper functioning and secure configuration of its Notary integration.
*   **Example:**
    *   An attacker compromises the Notary server *that Harbor is configured to use*, allowing them to sign malicious images that Harbor will then trust.
    *   An attacker pushes an unsigned image, and a user, *due to misconfigured policies within Harbor*, pulls it, assuming it is trusted.
    *   Weak key management practices *for keys used by Harbor's Notary integration* lead to compromise.
*   **Impact:** Deployment of malicious or tampered images, leading to potential compromise of the entire system.
*   **Risk Severity:** Critical (for compromised Notary server or signing keys *used by Harbor*), High (for pulling unsigned images in a trust-required environment *due to Harbor policy misconfiguration*).
*   **Mitigation Strategies:**
    *   **Developers:** Securely implement and *validate* the Notary integration *within Harbor*.  Provide clear guidance and secure defaults for configuring signing policies *within Harbor*.  Promote secure key management practices *specifically for Harbor's Notary keys*.
    *   **Users:** Enforce strict image signing policies *within Harbor*, requiring valid signatures for all image pulls.  Securely manage signing keys *used by Harbor's Notary integration*.  Regularly rotate these keys.  Verify that Harbor is configured to use a trusted and secure Notary server.

## Attack Surface: [API Security (Harbor-Specific Endpoints)](./attack_surfaces/api_security__harbor-specific_endpoints_.md)

* **Description:** Attacks targeting vulnerabilities *specific to Harbor's API implementation*, such as injection flaws or authorization bypasses in Harbor's custom API endpoints.
    * **Harbor Contribution:** Harbor exposes a REST API with custom endpoints for its functionality. Vulnerabilities in *these specific endpoints* are directly attributable to Harbor.
    * **Example:**
        * An attacker uses a SQL injection vulnerability in a *Harbor-specific API endpoint* (e.g., `/api/v2.0/projects/{project_name}/repositories`) to extract sensitive data. This is distinct from a general database vulnerability; it's about a flaw in Harbor's API code.
        * An unauthenticated *Harbor API endpoint* allows an attacker to delete images or modify project settings.
    * **Impact:** Data breaches, unauthorized access, system compromise, denial of service.
    * **Risk Severity:** High (for critical vulnerabilities like SQL injection in Harbor's API, unauthorized admin access via the API).
    * **Mitigation Strategies:**
        * **Developers:** Implement robust input validation and output encoding for *all Harbor-specific API endpoints*. Use parameterized queries to prevent SQL injection *within Harbor's API code*. Require authentication and authorization for *all sensitive Harbor API endpoints*. Follow secure coding practices *specifically when developing Harbor's API*.
        * **Users:** Keep Harbor updated to the latest version to receive API security patches. Use a web application firewall (WAF) configured to protect *Harbor's API endpoints*. Monitor Harbor's API usage and logs for suspicious activity.

## Attack Surface: [Image Replication and Storage (Harbor Configuration)](./attack_surfaces/image_replication_and_storage__harbor_configuration_.md)

*   **Description:** Attacks targeting the image replication process *as configured within Harbor* or the underlying storage backend *due to Harbor's configuration*.
*   **Harbor Contribution:** Harbor's configuration dictates how replication occurs and how the storage backend is accessed. Misconfigurations *within Harbor* are the primary concern.
*   **Example:**
    *   A man-in-the-middle attack intercepts image replication traffic *because Harbor is configured to use HTTP instead of HTTPS*.
    *   Unauthorized access to the S3 bucket used by Harbor *because Harbor's configuration grants overly permissive access*.
*   **Impact:** Data loss, data corruption, deployment of malicious images, denial of service.
*   **Risk Severity:** High (for compromised storage backend due to Harbor misconfiguration, successful MitM attacks due to insecure Harbor replication settings).
*   **Mitigation Strategies:**
    *   **Developers:** Provide secure-by-default configuration options for replication and storage *within Harbor*. Enforce HTTPS for replication by default. Guide users towards secure storage backend configurations *through Harbor's interface*.
    *   **Users:** Securely configure the storage backend *using Harbor's configuration options* (e.g., use IAM roles with least privilege, enable encryption). *Always* use HTTPS for all replication *configured within Harbor*. Regularly audit storage permissions *as they relate to Harbor's access*.

