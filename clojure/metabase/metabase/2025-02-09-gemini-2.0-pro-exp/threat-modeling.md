# Threat Model Analysis for metabase/metabase

## Threat: [Exploitation of Metabase Deserialization Vulnerability (e.g., CVE-2023-38646)](./threats/exploitation_of_metabase_deserialization_vulnerability__e_g___cve-2023-38646_.md)

*   **Description:** An attacker sends a crafted request to the Metabase setup endpoint, exploiting a deserialization vulnerability. This allows the attacker to execute arbitrary code on the Metabase server *without authentication*.
    *   **Impact:** Complete compromise of the Metabase instance, including access to all connected databases and data. Potential for lateral movement within the network.
    *   **Affected Metabase Component:**  `metabase.server.middleware.exceptions` (and related setup/initialization code). The vulnerability lies in how Metabase handles certain setup parameters.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Immediate:** Upgrade to a patched version of Metabase (0.46.6.1, 1.46.6.1, or later). This is the *primary* mitigation.
        *   **Defense in Depth:** Implement a Web Application Firewall (WAF) with rules to detect and block malicious requests targeting the setup endpoint. Specifically, look for patterns associated with known exploits.
        *   **Network Segmentation:** Isolate the Metabase server from other critical systems to limit the impact of a compromise.
        *   **Monitoring:** Monitor server logs for unusual activity, particularly around the setup endpoint.

## Threat: [Abuse of Metabase "Public Sharing" Feature (Leading to Sensitive Data Exposure)](./threats/abuse_of_metabase_public_sharing_feature__leading_to_sensitive_data_exposure_.md)

*   **Description:** An attacker discovers a publicly shared dashboard or question that exposes *sensitive* data. This is due to an oversight by a Metabase user who unintentionally shared sensitive information publicly, or a misconfiguration.
    *   **Impact:**  Unauthorized disclosure of *sensitive* data to anyone with the public link. Potential for data breaches, regulatory violations, and significant reputational damage.
    *   **Affected Metabase Component:**  `metabase.public` (and related sharing/embedding functionality). This involves the mechanisms for generating and managing public links.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Disable Public Sharing:** Disable the "Public Sharing" feature entirely if it's not absolutely essential.
        *   **Strict Review Process:** Implement a mandatory, multi-stage review process for *any* requests to share dashboards or questions publicly. This review must include a data sensitivity assessment.
        *   **Tokenized Embedding (Alternative):** If embedding is required, *exclusively* use embedding with strong, unpredictable, and frequently rotated tokens. Limit the data exposed to the absolute minimum. Avoid "Public Links" for embedding.
        *   **Regular Audits:** Conduct frequent, automated audits of all publicly shared dashboards and questions to ensure they remain necessary and do *not* expose sensitive data.
        *   **User Training:** Provide comprehensive training to Metabase users on the severe risks of public sharing and the importance of data privacy and classification.

## Threat: [Compromise of a Metabase User Account with Elevated Privileges](./threats/compromise_of_a_metabase_user_account_with_elevated_privileges.md)

*   **Description:** An attacker gains access to a Metabase user account with administrative or broad data access privileges. This could be through phishing, password guessing, credential stuffing, or exploiting a vulnerability in the user's system.
    *   **Impact:** The attacker gains access to all data and functionality accessible to the compromised user. This could include the ability to modify Metabase settings, create new users, exfiltrate sensitive data, and potentially use Metabase as a pivot point for further attacks.
    *   **Affected Metabase Component:** `metabase.models.user`, `metabase.api.user` (and related authentication and authorization mechanisms). This affects the core user management and access control system.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Mandatory Strong MFA:** Enforce strong, phishing-resistant multi-factor authentication (MFA) for *all* Metabase users, *especially* those with elevated privileges. This should be non-optional.
        *   **Strict Least Privilege:** Rigorously enforce the principle of least privilege within Metabase. Grant users *only* the absolute minimum necessary permissions. Avoid granting administrative privileges unless demonstrably required.
        *   **Regular Account Reviews:** Conduct frequent, automated reviews of Metabase user accounts and permissions. Revoke unnecessary access promptly.
        *   **Robust Session Management:** Implement short session timeouts and require users to re-authenticate frequently, especially after periods of inactivity.
        *   **Aggressive Account Lockout:** Implement aggressive account lockout policies to deter and prevent brute-force password attacks.

## Threat: [Exploitation of SQL Injection Vulnerability in a Custom SQL Question (Metabase-Specific Context)](./threats/exploitation_of_sql_injection_vulnerability_in_a_custom_sql_question__metabase-specific_context_.md)

*   **Description:** A Metabase user with permission to create custom SQL questions writes a query that is vulnerable to SQL injection. An attacker (who may or may not be the same user) then provides malicious input to the question's parameters, exploiting the vulnerability. *This is distinct from SQLi in the underlying database; it's about SQLi within a Metabase question itself, leveraging Metabase's query handling.*
    *   **Impact:** The attacker can execute arbitrary SQL commands on the connected database, potentially gaining access to all data, modifying data, or even gaining control of the database server. The impact is amplified because it bypasses Metabase's intended access controls.
    *   **Affected Metabase Component:** `metabase.query_processor`, `metabase.driver` (and related SQL query execution mechanisms). This affects how Metabase handles and executes custom SQL queries *before* they reach the database.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Mandatory Parameterized Queries:** Enforce the *exclusive* use of parameterized queries (prepared statements) in *all* custom SQL questions. Prohibit any form of string concatenation with user input. Metabase provides the necessary tools; their use must be mandatory and enforced.
        *   **Strict Input Validation:** Implement rigorous input validation for *all* user-supplied parameters to custom SQL questions. Validate data types, lengths, and formats *before* they are used in the query.
        *   **Mandatory Code Review:** Implement a mandatory code review process for *all* custom SQL questions, with a specific focus on identifying and eliminating potential SQL injection vulnerabilities. This review should be performed by someone other than the question author.
        *   **Least Privilege (Database):** Ensure that the database user accounts used by Metabase have *only* the absolute minimum necessary permissions on the connected databases. This limits the damage from a successful SQLi, even if it occurs.
        *   **Comprehensive Training:** Provide in-depth training to all users who are authorized to create custom SQL questions. This training must cover secure coding practices, the dangers of SQL injection, and the proper use of Metabase's parameterized query features.

