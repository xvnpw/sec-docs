# Threat Model Analysis for phacility/phabricator

## Threat: [Unintentional Data Disclosure via Misconfigured Policies](./threats/unintentional_data_disclosure_via_misconfigured_policies.md)

*   **Description:** An attacker gains access to sensitive information (code, internal discussions, user details, infrastructure configurations) due to incorrectly configured visibility settings on Phabricator objects (projects, repositories, tasks, etc.). The attacker might browse the interface, use search, or the Conduit API.
*   **Impact:** Loss of confidentiality, reputational damage, legal consequences, exposure of intellectual property, compromise of accounts or infrastructure.
*   **Affected Phabricator Component:**
    *   `policy` system (core)
    *   `PhabricatorProjectProjectPHIDType` (Project visibility)
    *   `PhabricatorRepositoryPHIDType` (Repository visibility)
    *   `ManiphestTask` (Task visibility)
    *   `DifferentialRevision` (Revision visibility)
    *   `PhabricatorFile` (File visibility)
    *   `PhabricatorPaste` (Paste visibility)
    *   `PhabricatorUser` (User profile visibility)
    *   Spaces (`PhabricatorSpacesNamespace`)
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Consistent policy checks, helper functions, documentation, unit/integration tests for policy enforcement.
    *   **User/Admin:** Understand Phabricator's policy system, "least privilege" principle, regular audits, Spaces for segmentation, user training.

## Threat: [Malicious Herald Rule Abuse](./threats/malicious_herald_rule_abuse.md)

*   **Description:** An attacker crafts a Herald rule to trigger on events (commit, task creation, comment) and perform malicious actions: sending data externally, deleting objects, modifying data, sending spam, or causing DoS.
*   **Impact:** Data exfiltration, data modification/deletion, denial of service, spamming, reputational damage.
*   **Affected Phabricator Component:**
    *   `Herald` application
    *   `HeraldRule` model
    *   `HeraldAction` (various actions)
    *   `HeraldCondition` (various conditions)
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Input validation/sanitization for rules, limit action scope, rate limiting/resource quotas, quarantine suspicious rules.
    *   **User/Admin:** Restrict Herald access, audit rules, review process for new rules.

## Threat: [Conduit API Abuse](./threats/conduit_api_abuse.md)

*   **Description:** An attacker uses the Conduit API (with obtained credentials or a compromised account) to perform unauthorized actions: deleting objects, modifying data, exfiltrating information, or causing DoS.
*   **Impact:** Data exfiltration, data modification/deletion, denial of service, reputational damage, account compromise.
*   **Affected Phabricator Component:**
    *   `Conduit` API
    *   All API methods (e.g., `project.edit`, `user.query`, `repository.edit`)
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Strong authentication/authorization, rate limiting/resource quotas, API usage monitoring, detailed logging, input validation/sanitization.
    *   **User/Admin:** Restrict API token access, review/revoke tokens, strong passwords/MFA, monitor API logs.

## Threat: [Differential Revision Bypass](./threats/differential_revision_bypass.md)

*   **Description:** An attacker bypasses the code review process in Differential, submitting malicious code, merging without approval, or exploiting vulnerabilities to gain unauthorized access or modify code.
*   **Impact:** Introduction of malicious code, application/infrastructure compromise, data breaches, reputational damage.
*   **Affected Phabricator Component:**
    *   `Differential` application
    *   `DifferentialRevision` model
    *   `DifferentialDiff` model
    *   Reviewer and blocking reviewer logic
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Strict code review policies, enforce them in Differential, require multiple reviewers, prevent unapproved merging, audit configuration, address vulnerabilities.
    *   **User/Admin:** Strong code review culture, train reviewers, blocking reviewers for sensitive changes, monitor activity.

## Threat: [Phabricator Core Vulnerability Exploitation](./threats/phabricator_core_vulnerability_exploitation.md)

*   **Description:** An attacker exploits a vulnerability in the Phabricator core codebase (logic error, insecure function, input handling flaw) to gain unauthorized access, execute code, exfiltrate data, or cause DoS.
*   **Impact:** Complete Phabricator compromise, data breaches, denial of service, reputational damage, infrastructure compromise.
*   **Affected Phabricator Component:** Potentially any part of the Phabricator core codebase.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Secure coding practices, security audits/penetration testing, vulnerability scanner, prompt response to advisories/patches, robust SDLC.
    *   **User/Admin:** Keep Phabricator updated, subscribe to advisories, monitor logs.

## Threat: [Audit Log Tampering](./threats/audit_log_tampering.md)

*   **Description:**  An attacker with sufficient privileges modifies or deletes audit logs to cover their tracks or hide malicious activity, hindering incident investigation.
*   **Impact:**  Loss of accountability, difficulty investigating incidents, potential for undetected ongoing attacks.
*   **Affected Phabricator Component:**
    *   `PhabricatorAuditManagementWorkflow`
    *   `PhabricatorAuditComment`
    *   Database tables storing audit logs.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Strong access controls for logs, protect from unauthorized modification/deletion, checksums/integrity checks, consider separate secure storage.
    *   **User/Admin:**  Restrict log management access, review logs, monitor for unauthorized access, use a SIEM system.

