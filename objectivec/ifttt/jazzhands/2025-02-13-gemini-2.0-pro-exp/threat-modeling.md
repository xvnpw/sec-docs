# Threat Model Analysis for ifttt/jazzhands

## Threat: [Overly Permissive Role Assignment](./threats/overly_permissive_role_assignment.md)

*   **Description:** An attacker, either a malicious insider or someone who has compromised a `jazzhands` user account, requests and receives temporary AWS credentials for a role that grants excessive permissions. The attacker leverages these overly permissive credentials to access resources they should not have access to. This is a direct result of misconfigured `permissions` or `constraints` within the `jazzhands` `config.yml`.
*   **Impact:** Data breaches, unauthorized data modification, deletion of resources, disruption of services, lateral movement within the AWS environment, potential complete compromise of the AWS account.
*   **Affected Component:** `config.yml` (specifically the `permissions` and `constraints` sections within role definitions), `jazzhands.aws.assume_role_with_saml` and `jazzhands.aws.assume_role` functions (which enforce these configurations).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Implement the principle of least privilege when defining roles in `config.yml`.  Grant only the absolute minimum necessary permissions.
    *   Thoroughly review and test all role definitions, paying close attention to `permissions` and `constraints`. Use Infrastructure as Code (IaC) to manage and version control these configurations.
    *   Regularly audit AWS IAM policies and roles to identify and remediate overly permissive configurations.
    *   Implement a robust approval workflow for changes to `jazzhands` configuration, especially role definitions.

## Threat: [Authentication Bypass in Jazzhands API](./threats/authentication_bypass_in_jazzhands_api.md)

*   **Description:** An external attacker exploits a vulnerability in the `jazzhands` API authentication logic to bypass the authentication process entirely. This could be due to a flaw in how `jazzhands` handles authentication tokens, session management, or integration with Okta/Duo.  This is a direct vulnerability *within* the `jazzhands` code.
*   **Impact:** The attacker gains unauthorized access to the `jazzhands` API, allowing them to request temporary AWS credentials for *any* configured role, potentially leading to complete compromise of the AWS environment.
*   **Affected Component:** `jazzhands` API endpoints (e.g., `/auth`, `/request_aws_creds`), authentication-related functions within `jazzhands.auth` and potentially integration modules with Okta (`jazzhands.auth.okta`) or Duo (`jazzhands.auth.duo`).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Conduct thorough security code reviews of the authentication logic within `jazzhands`.
    *   Perform penetration testing specifically targeting the authentication mechanisms of the `jazzhands` API.
    *   Implement robust input validation and sanitization on all API endpoints.
    *   Ensure secure session management practices are followed.
    *   Keep `jazzhands` and its dependencies (especially authentication-related libraries) up-to-date with the latest security patches.

## Threat: [Missing or Incorrect `constraints`](./threats/missing_or_incorrect__constraints_.md)

*   **Description:** The `constraints` feature in `jazzhands` is either not used or is misconfigured, allowing users to obtain temporary credentials that are broader in scope than intended.  This is a direct failure to properly utilize a core security feature of `jazzhands`. For example, a user might be able to access resources in a different AWS region or use services that they should not have access to.
*   **Impact:** Increased blast radius of a compromised user account; users can access more resources than they should, potentially leading to data breaches or unauthorized actions.
*   **Affected Component:** `config.yml` (specifically the `constraints` section within role definitions), `jazzhands.aws.assume_role_with_saml` and `jazzhands.aws.assume_role` functions.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Mandatory use of `constraints` for all role definitions.
    *   Define specific and granular constraints to limit the scope of temporary credentials, including restrictions on regions, services, resource ARNs, and condition keys.
    *   Regularly review and audit `constraints` configurations to ensure they are effective and up-to-date.
    *   Provide training to administrators on the proper use of `constraints`.

## Threat: [Compromised Jazzhands Server (Directly impacting Jazzhands functionality)](./threats/compromised_jazzhands_server__directly_impacting_jazzhands_functionality_.md)

*   **Description:** While server compromise is often a general threat, in the context of Jazzhands, it *directly* impacts the security of the AWS environment. An attacker with access to the Jazzhands server can directly access the `jazzhands` configuration, including potentially sensitive information used to generate AWS credentials, and the long-lived AWS credentials themselves if not properly secured using a secrets manager. This is distinct from general server compromise, as it *specifically* targets the core function of Jazzhands.
*   **Impact:** Complete compromise of `jazzhands`, allowing the attacker to generate arbitrary AWS credentials, modify the configuration, access the database, and potentially pivot to other systems. The attacker gains the ability to impersonate *any* role managed by Jazzhands.
*   **Affected Component:** Entire `jazzhands` deployment, including the server operating system, web server, `jazzhands` application code, database, and configuration files. The critical aspect is the attacker's ability to directly manipulate Jazzhands' credential generation.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Implement strong server hardening practices, including regular patching, disabling unnecessary services, and configuring a firewall.
    *   Use a secure secret management solution (e.g., AWS Secrets Manager, HashiCorp Vault) to store sensitive information like AWS access keys and database credentials, *not* in plain text on the server. This is crucial.
    *   Implement intrusion detection and prevention systems (IDS/IPS) to monitor for and block malicious activity.
    *   Regularly perform vulnerability scans of the server and its software.
    *   Use strong SSH key-based authentication and disable password-based SSH access.

## Threat: [Direct Database Access and Modification (Impacting Jazzhands Logic)](./threats/direct_database_access_and_modification__impacting_jazzhands_logic_.md)

*   **Description:** An attacker gains direct access to the `jazzhands` database. While database access is a general concern, here it *directly* impacts Jazzhands' authorization. The attacker modifies user data or group memberships *within the Jazzhands database* to grant themselves unauthorized access to AWS roles *managed by Jazzhands*. This bypasses the intended Jazzhands workflow.
*   **Impact:** The attacker can manipulate user accounts and permissions *within jazzhands*, potentially granting themselves access to any AWS role. They can also delete or modify audit logs, hindering incident response. This directly undermines the security controls of Jazzhands.
*   **Affected Component:** The `jazzhands` database (MySQL or PostgreSQL), database connection logic within `jazzhands.db`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement strong database security practices, including strong passwords, encryption at rest and in transit, and access controls.
    *   Regularly back up the database.
    *   Use a dedicated database user for `jazzhands` with the minimum necessary privileges.
    *   Monitor database logs for suspicious activity.
    *   Ensure the database server is not directly accessible from the public internet.
    *   Implement database firewall rules to restrict access to authorized hosts only.

## Threat: [Compromised Okta API Token (if Okta is used, and directly used by Jazzhands)](./threats/compromised_okta_api_token__if_okta_is_used__and_directly_used_by_jazzhands_.md)

*   **Description:** An attacker gains access to the Okta API token *used by jazzhands* to communicate with Okta.  The attacker uses this token to impersonate `jazzhands` and potentially manipulate user accounts or group memberships within Okta, *directly affecting which AWS roles Jazzhands can grant*.
*   **Impact:** The attacker can potentially bypass `jazzhands` controls by directly manipulating Okta, granting themselves access to AWS resources (via Jazzhands' role assignments) or disrupting Okta-based authentication used by Jazzhands.
*   **Affected Component:** `jazzhands.auth.okta` module, Okta API token storage location.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Store the Okta API token securely using a secret management solution.
    *   Rotate the Okta API token regularly.
    *   Monitor Okta API usage for suspicious activity.
    *   Implement least privilege for the Okta service account used by `jazzhands`.

