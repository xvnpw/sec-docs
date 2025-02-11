# Attack Tree Analysis for netflix/asgard

Objective: [G] Gain Unauthorized Control over AWS Resources via Asgard [!]

## Attack Tree Visualization

[G] Gain Unauthorized Control over AWS Resources via Asgard [!]
    |
    [B] Leverage Misconfigured Asgard Permissions/Settings [!]
        |
        -----------------------------------------------------------------
        |                               |                               |
[B1] Overly Permissive IAM Roles [!]--->   [B2] Weak/Default Credentials   [B3] Exposed Asgard API Endpoints
        |                                                               |
        -----------------------                                         -----------------------
        |                     |                                         |                     |
[B1a] Broad AWS  [B1b] Lack of Least  [B2b] Default Asgard          [B3a] Unprotected
    Permissions---> Privilege in Asgard   Credentials                    API Endpoints--->
                    Configuration

## Attack Tree Path: [[G] Gain Unauthorized Control over AWS Resources via Asgard [!]](./attack_tree_paths/_g__gain_unauthorized_control_over_aws_resources_via_asgard__!_.md)

*   **Description:** The ultimate objective of the attacker.  This involves gaining the ability to manipulate AWS resources (EC2 instances, S3 buckets, security groups, etc.) that are managed by the Asgard application. The attacker achieves this by exploiting vulnerabilities *within Asgard* or its configuration, not by directly attacking AWS.
*   **Criticality:** This is the root node and represents the complete success of the attack.

## Attack Tree Path: [[B] Leverage Misconfigured Asgard Permissions/Settings [!]](./attack_tree_paths/_b__leverage_misconfigured_asgard_permissionssettings__!_.md)

*   **Description:** This branch represents the most likely and impactful attack vector.  It focuses on exploiting errors in how Asgard is configured, particularly regarding permissions and access controls.
    *   **Criticality:** This is a critical branch because misconfigurations are common and often provide a direct path to compromising AWS resources.
    *   **High-Risk:** Due to the ease of making configuration mistakes and the significant impact they can have.

## Attack Tree Path: [[B1] Overly Permissive IAM Roles [!]--->](./attack_tree_paths/_b1__overly_permissive_iam_roles__!_---.md)

*   **Description:** This is the *most critical* vulnerability. Asgard operates within AWS using an IAM role. If this role grants excessive permissions (e.g., `AdministratorAccess` or overly broad access to services), an attacker who gains any level of control over Asgard immediately inherits those permissions.
    *   **Criticality:** This is a critical node because it directly leads to the attacker achieving their goal.  It's a single point of failure that can negate other security measures.
    *   **High-Risk:** Because it's a common mistake to assign overly permissive roles for convenience.

## Attack Tree Path: [[B1a] Broad AWS Permissions --->](./attack_tree_paths/_b1a__broad_aws_permissions_---.md)

*   **Description:**  The IAM role grants access to AWS services and actions that Asgard *doesn't need* for its intended functionality.  For example, if Asgard only needs to manage EC2 instances, but the role grants access to S3, an attacker could exploit this to access or modify S3 data.
        *   **High-Risk:**  This is a specific instance of overly permissive IAM roles, making it a high-risk vulnerability.

## Attack Tree Path: [[B1b] Lack of Least Privilege in Asgard Configuration --->](./attack_tree_paths/_b1b__lack_of_least_privilege_in_asgard_configuration_---.md)

*   **Description:** Even if the IAM role is *somewhat* restricted, Asgard's *internal* configuration might not enforce the principle of least privilege.  For example, all Asgard users might have permission to launch new instances, even if only a few should have that capability. This means that even with a less permissive IAM role, an attacker with limited access *within Asgard* could still perform actions they shouldn't.
        *   **High-Risk:**  This highlights the importance of enforcing least privilege at *all* levels, not just at the IAM role level.

## Attack Tree Path: [[B2] Weak/Default Credentials](./attack_tree_paths/_b2__weakdefault_credentials.md)

*   **Description:** This attack vector focuses on using weak or default credentials to gain access to Asgard.
    *   **High-Risk:** Although not marked as critical, it is still a high-risk path due to the prevalence of default credential usage.

## Attack Tree Path: [[B2b] Default Asgard Credentials](./attack_tree_paths/_b2b__default_asgard_credentials.md)

* **Description:** If Asgard has default administrative credentials that haven't been changed after installation, an attacker could easily gain access by simply trying these known credentials.
        * **High-Risk:** Because it's a common oversight to leave default credentials unchanged.

## Attack Tree Path: [[B3] Exposed Asgard API Endpoints](./attack_tree_paths/_b3__exposed_asgard_api_endpoints.md)

*   **Description:** This attack vector involves exploiting Asgard's API endpoints, particularly if they are not properly secured.
    *   **High-Risk:** Due to the potential for direct access to Asgard's functionality.

## Attack Tree Path: [[B3a] Unprotected API Endpoints --->](./attack_tree_paths/_b3a__unprotected_api_endpoints_---.md)

*   **Description:** Asgard exposes API endpoints for various operations. If these endpoints are not properly authenticated and authorized, an attacker could directly interact with Asgard's functionality, potentially launching instances, modifying security groups, or performing other actions without needing to go through the web interface.
        *   **High-Risk:**  Because unprotected API endpoints are relatively easy to discover and exploit.

