# Threat Model Analysis for parse-community/parse-server

## Threat: [Improper Class-Level Permissions (CLP) Exploitation](./threats/improper_class-level_permissions__clp__exploitation.md)

*   **Description:** An attacker leverages overly permissive CLPs to perform unauthorized actions on entire classes of data.  The attacker crafts API requests directly, bypassing client-side restrictions, to create, read, update, or delete objects within a class they shouldn't have access to.  For example, a public `create` permission on a sensitive class allows unauthorized data creation.
*   **Impact:**
    *   Data breaches: Unauthorized access to sensitive data.
    *   Data corruption: Modification or deletion of critical data.
    *   Denial of service: Resource exhaustion due to excessive object creation.
    *   Reputational damage.
*   **Affected Component:** Parse Server's CLP enforcement mechanism (database adapter and API request handling). Specifically, functions handling object creation, retrieval, updating, and deletion based on CLPs.
*   **Risk Severity:** High to Critical (depending on data sensitivity).
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:** Grant only minimum necessary permissions.
    *   **Role-Based Access Control (RBAC):** Use Parse Server's Roles for effective permission management.
    *   **Regular Audits:** Periodically review and audit CLPs.
    *   **Avoid Public Access:** Never set `create`, `update`, or `delete` CLPs to `public` for sensitive classes.
    *   **Cloud Code Validation:** Use `beforeSave`, `beforeFind`, `beforeDelete` triggers for additional validation.

## Threat: [Access Control List (ACL) Bypass](./threats/access_control_list__acl__bypass.md)

*   **Description:** An attacker manipulates API requests to bypass intended ACL restrictions on individual objects. They attempt to read, update, or delete objects they don't own or have permission to access, often by crafting requests with modified object IDs or exploiting flaws in Cloud Code ACL application.
*   **Impact:**
    *   Data breaches: Unauthorized access to specific sensitive objects.
    *   Data corruption: Modification or deletion of individual objects.
    *   Privacy violations.
*   **Affected Component:** Parse Server's ACL enforcement mechanism (database adapter and API request handling). Functions that check ACLs before object operations.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Proper ACL Configuration:** Ensure correct ACLs are set during object creation.
    *   **Cloud Code Validation:** Use `beforeSave`, `beforeFind`, `beforeDelete` triggers to verify user permissions based on the object's ACL, *even if* client-side code enforces it.
    *   **Pointer Permissions:** Use Pointer Permissions for granular control over relationships.
    *   **Avoid Client-Side ACL Trust:** Always validate on the server.

## Threat: [Cloud Code Injection/Vulnerability (Leading to Arbitrary Code Execution)](./threats/cloud_code_injectionvulnerability__leading_to_arbitrary_code_execution_.md)

*   **Description:** An attacker exploits vulnerabilities in custom Cloud Code functions to achieve *arbitrary code execution* on the Parse Server. This is a subset of the broader Cloud Code vulnerability, specifically focusing on the most severe outcome. This could involve severe input validation flaws or misuse of Node.js functions that allow the attacker to run their own code within the server's context.
*   **Impact:**
    *   **Complete system compromise:** The attacker gains full control over the Parse Server and potentially the underlying infrastructure.
    *   Data breaches: Access to *all* data accessible by the server.
    *   Data corruption/destruction.
    *   Denial of service.
    *   Use of the server for malicious purposes (e.g., sending spam, launching attacks).
*   **Affected Component:** Custom Cloud Code functions; the Node.js runtime environment within Parse Server.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Rigorous Input Validation:** Extremely strict validation of *all* input parameters to Cloud Code functions, including type checking, length limits, and format validation. Use a robust validation library.
    *   **Secure Coding Practices:** Follow secure coding guidelines for Node.js *meticulously*. Avoid any potentially unsafe functions (e.g., `eval`, functions that execute shell commands without proper sanitization).
    *   **Least Privilege:** Ensure the Parse Server process itself runs with the least necessary privileges on the operating system.
    *   **Code Reviews:** Mandatory, in-depth code reviews focusing on security.
    *   **Static Analysis:** Use advanced static analysis tools designed to detect code execution vulnerabilities.
    *   **Dependency Management:** Keep all Node.js dependencies up-to-date and audit them for known vulnerabilities.
    *   **Sandboxing (Advanced):** Consider using sandboxing techniques to isolate Cloud Code execution and limit its access to the server's resources (though this can be complex to implement).

## Threat: [Unauthorized Live Query Subscription](./threats/unauthorized_live_query_subscription.md)

*   **Description:** An attacker subscribes to a Live Query for a class or query they shouldn't have access to, receiving real-time updates about data changes, bypassing intended data access restrictions.
*   **Impact:**
    *   Data breaches: Real-time leakage of sensitive data.
    *   Privacy violations: Monitoring of user activity.
*   **Affected Component:** Parse Server's Live Query server and subscription management; the `Parse.Query` used for the subscription.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **ACL/CLP Enforcement:** Ensure underlying data accessed by the Live Query is protected by appropriate ACLs and CLPs.
    *   **Subscription Validation:** Use the `validateSubscription` function in Cloud Code to verify user permissions to subscribe.

## Threat: [Push Notification Credential Compromise](./threats/push_notification_credential_compromise.md)

*   **Description:** An attacker gains access to the push notification credentials (APNs certificates, FCM API keys) used by Parse Server. They can then send unauthorized push notifications, potentially with malicious content.
*   **Impact:**
    *   Phishing: Tricking users into revealing sensitive information.
    *   Malware distribution.
    *   Reputational damage.
*   **Affected Component:** Parse Server's push notification module; configuration settings storing credentials.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Credential Storage:** Store credentials securely, *not* in the configuration file or source code. Use environment variables or a secure key management service.
    *   **Access Control:** Restrict access to the Parse Server dashboard and configuration.
    *   **Regular Rotation:** Regularly rotate push notification credentials.
    *   **Cloud Code Validation:** Use `beforeSave` triggers on `_Installation` to validate push requests.

## Threat: [Denial of Service (DoS) via Resource Exhaustion](./threats/denial_of_service__dos__via_resource_exhaustion.md)

*   **Description:**  An attacker overwhelms Parse Server with requests, causing it to become unresponsive.  This could target Cloud Code, database queries, Live Queries, or general API requests.
*   **Impact:**
    *   Service outage.
    *   Financial loss.
    *   Reputational damage.
*   **Affected Component:** All Parse Server components (API server, Cloud Code runtime, database adapter, Live Query server).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Rate Limiting:** Implement rate limiting on API requests, Cloud Code, and Live Queries.
    *   **Throttling:** Dynamically adjust limits based on server load.
    *   **Cloud Code Optimization:** Optimize Cloud Code for performance.
    *   **Database Indexing:** Ensure proper database indexing.
    *   **Resource Monitoring:** Monitor server resources and set alerts.
    *   **Scalability:** Design for scalability.
    *   **Web Application Firewall (WAF):** Use a WAF for network-level DoS mitigation.

