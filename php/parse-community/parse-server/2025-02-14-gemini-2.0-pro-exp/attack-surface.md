# Attack Surface Analysis for parse-community/parse-server

## Attack Surface: [Weak Master Key / Credentials](./attack_surfaces/weak_master_key__credentials.md)

*Description:* The `masterKey` grants unrestricted access, bypassing all security (CLPs, ACLs). Weak or default application/client keys are also high risk.
*How Parse Server Contributes:* The `masterKey` is a *core* Parse Server concept for administrative access.
*Example:* Attacker finds a leaked `masterKey` and deletes all data.
*Impact:* Complete compromise of the Parse Server instance.
*Risk Severity:* Critical
*Mitigation Strategies:*
    *   **Strong, Unique Keys:** Use a cryptographically secure random number generator.
    *   **Secure Storage:** *Never* in source code. Use environment variables or a secrets manager.
    *   **Key Rotation:** Rotate regularly.
    *   **Restrict Client Access:** Disable `masterKey` use on the client-side if possible.
    *   **Monitoring:** Monitor logs for `masterKey` misuse.

## Attack Surface: [Inadequate Authentication and Authorization (CLPs/ACLs)](./attack_surfaces/inadequate_authentication_and_authorization__clpsacls_.md)

*Description:* Misconfigured or missing Class Level Permissions (CLPs) and Access Control Lists (ACLs) allow unauthorized data access/modification.
*How Parse Server Contributes:* CLPs and ACLs are the *primary* data access control mechanism *within* Parse Server.
*Example:* A CLP allows public read access to a "PrivateMessages" class.
*Impact:* Data breaches, unauthorized modification, privilege escalation.
*Risk Severity:* High to Critical (depends on data sensitivity and misconfiguration extent).
*Mitigation Strategies:*
    *   **Principle of Least Privilege:** Grant only *minimum* necessary permissions.
    *   **Careful Design:** Thoroughly plan CLPs/ACLs *before* implementation.
    *   **Rigorous Testing:** Test with different user roles and access patterns.
    *   **Regular Audits:** Periodically review and audit.
    *   **Cloud Code for Complex Logic:** Use `beforeSave`, `afterSave`, Cloud Functions for complex rules.
    *   **Default to Deny:** Configure CLPs to deny by default, then grant explicitly.

## Attack Surface: [NoSQL Injection (Query Injection)](./attack_surfaces/nosql_injection__query_injection_.md)

*Description:* Unsanitized user input in database queries (especially `$where`) can lead to injection, even in a NoSQL context.
*How Parse Server Contributes:* Parse Server's query abstraction layer can be bypassed or misused, leading to injection. The `$where` operator is particularly risky.
*Example:* Injection via `$where`: `{ "$where": "this.secret = 'admin' || true" }`.
*Impact:* Data breaches, unauthorized modification, potential server-side code execution.
*Risk Severity:* High to Critical
*Mitigation Strategies:*
    *   **Avoid `$where`:** Prefer Parse Server's built-in query constraints.
    *   **Strict Input Validation:** If `$where` is *essential*, rigorously validate and sanitize *all* input. Whitelist approach.
    *   **Parameterized Queries:** Use if the underlying database supports them.
    *   **Escape User Input:** Properly escape if constructing queries dynamically.

## Attack Surface: [Remote Code Execution (RCE) in Cloud Code](./attack_surfaces/remote_code_execution__rce__in_cloud_code.md)

*Description:* Cloud Code functions (`beforeSave`, `afterSave`, Cloud Functions) are vulnerable to code injection if user input is mishandled.
*How Parse Server Contributes:* Cloud Code is a *core* Parse Server feature for extending functionality, introducing RCE risk.
*Example:* `eval(userInput)` in a Cloud Function.
*Impact:* Complete server compromise, data breaches, DoS, lateral movement.
*Risk Severity:* Critical
*Mitigation Strategies:*
    *   **Avoid `eval()`:** *Never* use `eval()` or similar with unsanitized input.
    *   **Strict Input Validation/Sanitization:** Whitelist approach.
    *   **Avoid Dynamic Code Generation:** Don't build code from user input.
    *   **Secure Coding Practices:** Follow Node.js (or other language) security best practices.
    *   **Code Reviews:** Thorough reviews focusing on security.
    *   **Least Privilege:** Run Cloud Code with minimal privileges.

## Attack Surface: [Insecure Direct Object References (IDOR)](./attack_surfaces/insecure_direct_object_references__idor_.md)

*Description:* Predictable object IDs allow attackers to access/modify objects they shouldn't, even with CLPs/ACLs.
*How Parse Server Contributes:* Parse Server uses object IDs; the framework doesn't inherently prevent predictability.
*Example:* Incrementing an object ID in a URL to access another user's data.
*Impact:* Data breaches, unauthorized modification.
*Risk Severity:* High
*Mitigation Strategies:*
    *   **Random Object IDs:** Use UUIDs (Parse Server's default).
    *   **Server-Side Authorization:** *Always* enforce checks on the server (Cloud Code, CLPs/ACLs). Don't rely on client-side logic.
    *   **Don't Expose Internal IDs:** Avoid direct exposure in URLs/responses if possible.

