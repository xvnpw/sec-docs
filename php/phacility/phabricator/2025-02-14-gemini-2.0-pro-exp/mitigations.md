# Mitigation Strategies Analysis for phacility/phabricator

## Mitigation Strategy: [Strict Reviewer Assignment and Permissions (Differential)](./mitigation_strategies/strict_reviewer_assignment_and_permissions__differential_.md)

*   **Description:**
    1.  **Herald Rule Configuration:**
        *   Access the Herald application within Phabricator.
        *   Create rules that trigger based on:
            *   File paths (e.g., `/src/auth/*` requires review by `auth-team`).  This leverages Phabricator's understanding of the codebase.
            *   Project tags (e.g., projects tagged `security` require a blocking reviewer from the security team). This uses Phabricator's project organization.
            *   Author (e.g., new hires require more thorough review). This uses Phabricator's user management.
        *   Set the actions for these rules to:
            *   Add specific reviewers or reviewer groups (using Phabricator's user/group system).
            *   Add blocking reviewers (a Phabricator-specific feature).
            *   Prevent merge if conditions are not met (Differential's core functionality).
    2.  **Permission Management (Policies):**
        *   Use Phabricator's built-in "Policies" system to restrict who can:
            *   Approve revisions (within Differential).
            *   Bypass review requirements (a Differential-specific setting).
            *   Modify Herald rules (controlling the review process itself).
    3.  **Audit Log Review (Differential):**
        *   Regularly review the audit logs *within Differential* to look for:
            *   Changes approved quickly or with minimal discussion.
            *   Changes approved by users who may not have the appropriate expertise (based on Phabricator's user profiles).
            *   Changes that bypass established review processes (detectable through Differential's logs).
            *   Changes to Herald rules themselves (to prevent malicious rule modifications).

*   **Threats Mitigated:**
    *   **Malicious Code Injection (High Severity):**  Phabricator's Differential and Herald are used to enforce review processes, making it harder to inject malicious code.
    *   **Accidental Introduction of Vulnerabilities (Medium Severity):** Phabricator's review tools and policies help catch errors.
    *   **Insider Threats (Medium Severity):** Phabricator's permission system and audit logs limit the impact of malicious insiders.
    *   **Compliance Violations (Medium Severity):** Phabricator's workflow can be configured to enforce compliance requirements.

*   **Impact:** (Same as before, but now focused on Phabricator's role)
    *   **Malicious Code Injection:** Risk significantly reduced.
    *   **Accidental Vulnerabilities:** Risk moderately reduced.
    *   **Insider Threats:** Risk moderately reduced.
    *   **Compliance Violations:** Risk significantly reduced.

*   **Currently Implemented:** (Example - adjust to your situation)
    *   Basic Herald rules for reviewer assignment based on project tags.
    *   Reviewer permissions are generally restricted, but some senior developers have broad approval rights.

*   **Missing Implementation:** (Example - adjust to your situation)
    *   No blocking reviewer functionality is used.
    *   No Herald rules based on file paths.
    *   No automated enforcement of the "no self-approval" policy (within Phabricator).
    *   No regular audits of Herald rules or permissions *within the Phabricator interface*.

## Mitigation Strategy: [Automated Code Analysis Integration (via Herald)](./mitigation_strategies/automated_code_analysis_integration__via_herald_.md)

*   **Description:**
    1.  **Herald Rule Configuration:**
        *   Create Herald rules that trigger when a new Differential revision is created or updated.  This is entirely within Phabricator.
        *   Set the action to run a specific task in an *external* CI/CD pipeline (e.g., trigger a SonarQube scan).  This is the *interface* between Phabricator and the external tool.
        *   Configure the rule to check the results of the analysis (e.g., block merge if SonarQube reports critical vulnerabilities).  This uses Herald's conditional logic.  The *results* are reported back to Phabricator.
    2.  **Threshold Definition (within Herald):** Define clear thresholds for acceptable code quality and security *within the Herald rule conditions*.  For example:
        *   Block merges if a custom field (populated by the CI/CD system) indicates critical vulnerabilities.
    3. **Result Display (Differential):** The results of the analysis, and the reason for blocking a merge (if applicable), are displayed directly within the Differential revision interface.

*   **Threats Mitigated:** (Same threats, but Phabricator's role is in *enforcing* the analysis)
    *   **Code Injection Vulnerabilities (High Severity)**
    *   **Logic Errors (Medium Severity)**
    *   **Use of Insecure Libraries/Functions (Medium Severity)**
    *   **Data Exposure (Medium Severity)**

*   **Impact:** (Same as before)

*   **Currently Implemented:** (Example)
    *   A basic linter is run externally, but there's no integration with Differential or Herald.

*   **Missing Implementation:** (Example)
    *   No Herald rules to trigger or check the results of code analysis.
    *   No display of analysis results within Differential.

## Mitigation Strategy: [Controlled Task Visibility and Permissions (Maniphest)](./mitigation_strategies/controlled_task_visibility_and_permissions__maniphest_.md)

*   **Description:**
    1.  **Project-Level Permissions (Maniphest & Policies):**
        *   Define distinct projects *within Maniphest*.
        *   Set project visibility to "Members Only" using Phabricator's project settings.
        *   Use Phabricator's "Policies" to control who can:
            *   View projects (within Maniphest).
            *   Create tasks within projects (Maniphest functionality).
            *   Edit project settings (Maniphest functionality).
    2.  **Task-Level Permissions (Maniphest):**
        *   For individual tasks, use the "Visible To" setting (a Maniphest feature) to restrict visibility.
        *   Use the "Editable By" setting (a Maniphest feature) to control who can modify task details.
    3.  **Audit Logs (Maniphest):** Regularly review Maniphest's audit logs to check for inappropriate access or modifications.

*   **Threats Mitigated:** (Phabricator's role is in providing the access control mechanisms)
    *   **Unauthorized Data Access (Medium Severity)**
    *   **Data Leakage (Medium Severity)**
    *   **Insider Threats (Low Severity)**

*   **Impact:** (Same as before)

*   **Currently Implemented:** (Example)
    *   Most projects are set to "Members Only."
    *   Basic task-level permissions are used, but not consistently.

*   **Missing Implementation:** (Example)
    *   No regular audits of project and task permissions *within Maniphest*.
    *   Inconsistent use of "Editable By" settings.

## Mitigation Strategy: [Content Moderation and Revision History (Phriction)](./mitigation_strategies/content_moderation_and_revision_history__phriction_.md)

*   **Description:**
    1.  **Revision History (Phriction):** Ensure that revision history is enabled for all Phriction documents (a Phriction feature, usually on by default).
    2.  **Moderation Workflow (Phriction & Policies & Herald):**
        *   Identify critical documents.
        *   Use Phabricator's "Policies" to restrict editing permissions for these documents.
        *   Configure a workflow using Herald rules that trigger on edits to specific Phriction documents (identified by path or other criteria) and add a blocking reviewer (using Phabricator's user management).  This leverages Herald's integration with Phriction.
    3. **Audit Logs (Phriction):** Periodically review Phriction's own audit logs to look for suspicious activity.

*   **Threats Mitigated:** (Phabricator provides the revision tracking and moderation tools)
    *   **Data Vandalism (Medium Severity)**
    *   **Unauthorized Content Modification (Medium Severity)**
    *   **Data Loss (Low Severity)**

*   **Impact:** (Same as before)

*   **Currently Implemented:** (Example)
    *   Revision history is enabled.

*   **Missing Implementation:** (Example)
    *   No moderation workflow using Herald and Policies.
    *   No regular audits of Phriction's audit logs.

## Mitigation Strategy: [API Key Management and Rate Limiting (Conduit)](./mitigation_strategies/api_key_management_and_rate_limiting__conduit_.md)

*   **Description:**
    1.  **Strong API Keys (Conduit):** Ensure that all Conduit tokens are generated using Phabricator's built-in token generation mechanism.
    2.  **Regular Key Rotation (Conduit):** Use Phabricator's Conduit administration interface to revoke old tokens and generate new ones.
    3.  **Rate Limiting (Conduit):** Configure Phabricator's built-in rate limiting features (within Conduit's settings) to restrict API calls.
    4.  **API Key Permissions (Conduit & Policies):** When creating a Conduit token, grant only the minimum necessary permissions using Phabricator's interface. Use "Policies" to control which API methods a token can access.
    5.  **Monitoring (Conduit):** Monitor API usage logs *within Phabricator's Conduit interface* for suspicious activity.

*   **Threats Mitigated:** (Phabricator provides the API management and security features)
    *   **API Abuse (Medium Severity)**
    *   **Unauthorized Access (High Severity)**
    *   **Brute-Force Attacks (Medium Severity)**
    *   **Data Exfiltration (High Severity)**

*   **Impact:** (Same as before)

*   **Currently Implemented:** (Example)
    *   Basic rate limiting is enabled.
    *   API keys are generated using Phabricator's built-in mechanism.

*   **Missing Implementation:** (Example)
    *   No regular API key rotation.
    *   No granular API key permissions.
    *   No monitoring of API usage logs *within Conduit*.

## Mitigation Strategy: [Diffusion Access Control](./mitigation_strategies/diffusion_access_control.md)

* **Description:**
    1. **Repository Permissions (Diffusion & Policies):** Use Phabricator's Diffusion application and its integration with "Policies" to define granular access control for each repository.  Restrict read, write, and administrative access to specific users or groups.
    2. **Audit Logs (Diffusion):** Regularly review Diffusion's audit logs to identify any unauthorized access attempts or changes to repository settings.

* **Threats Mitigated:**
    * **Unauthorized Code Access (High Severity):** Prevents unauthorized users from viewing or modifying source code.
    * **Data Breach (High Severity):** Limits the potential for sensitive code or data to be leaked.
    * **Insider Threats (Medium Severity):** Restricts the actions that malicious insiders can perform within repositories.

* **Impact:**
    * **Unauthorized Code Access:** Risk significantly reduced.
    * **Data Breach:** Risk significantly reduced.
    * **Insider Threats:** Risk moderately reduced.

* **Currently Implemented:** (Example)
    * Basic repository permissions are in place, but some repositories have overly broad access.

* **Missing Implementation:** (Example)
    * No regular audits of Diffusion's audit logs.
    * Inconsistent application of granular permissions across all repositories.

