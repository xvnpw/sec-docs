# Attack Surface Analysis for fastify/fastify

## Attack Surface: [Route Hijacking/Shadowing](./attack_surfaces/route_hijackingshadowing.md)

*   **Description:**  Overlapping or poorly defined routes can lead to a more specific, potentially vulnerable route being overshadowed by a broader, less secure one. Attackers can then access the unintended handler.
*   **How Fastify Contributes:** Fastify's route registration order matters. If a more general route is registered before a more specific one, the general route will match first.
*   **Example:**  Having routes `/users/:id` and `/users/admin` where `/users/*` is registered first. A request to `/users/admin` might incorrectly match the wildcard route.
*   **Impact:** Access to unintended resources, bypassing authorization checks, potential execution of vulnerable code.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Define routes with clear and non-overlapping patterns.
    *   Register more specific routes before more general ones.
    *   Thoroughly test route definitions to ensure they behave as expected.
    *   Use route prefixing or grouping to organize routes logically.

## Attack Surface: [Wildcard Route Abuse](./attack_surfaces/wildcard_route_abuse.md)

*   **Description:**  Wildcard routes (`/*`, `/:param*`) can be powerful but also risky if not carefully validated. Attackers might be able to bypass intended route structures or access sensitive resources.
*   **How Fastify Contributes:** Fastify provides flexible wildcard routing. The responsibility lies with the developer to properly validate the captured path within the handler.
*   **Example:** A route like `/files/*` intended to serve files from a specific directory could be abused with a request like `/files/../../etc/passwd` if the path is not sanitized.
*   **Impact:** Access to sensitive files, directory traversal vulnerabilities, potential for command injection if the path is used in system calls.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Thoroughly validate and sanitize the captured path within wildcard route handlers.
    *   Avoid using wildcard routes when more specific routes can be defined.
    *   Implement proper access controls and permissions for the resources being served.

## Attack Surface: [Abuse of Fastify Hooks](./attack_surfaces/abuse_of_fastify_hooks.md)

*   **Description:**  Malicious or poorly written plugins can abuse Fastify's hooks (`onRequest`, `preParsing`, etc.) to intercept and manipulate requests or responses in unintended ways.
*   **How Fastify Contributes:** Fastify's hook system provides powerful interception points, which, if misused, can introduce vulnerabilities.
*   **Example:** A plugin using the `onRequest` hook could bypass authentication checks or modify request headers to inject malicious data.
*   **Impact:** Authentication bypass, authorization flaws, data manipulation, introduction of new vulnerabilities.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Thoroughly review the code of any plugins that utilize hooks.
    *   Understand the order of hook execution and potential interactions between hooks from different plugins.
    *   Implement robust testing to ensure hooks are behaving as expected and not introducing security issues.

## Attack Surface: [`reply.sendFile()` Vulnerabilities](./attack_surfaces/_reply_sendfile____vulnerabilities.md)

*   **Description:**  If not used carefully, `reply.sendFile()` can be exploited to access arbitrary files on the server if the provided path is not properly sanitized or validated.
*   **How Fastify Contributes:** Fastify provides the `reply.sendFile()` method for serving static files. The security depends on how developers construct the file path.
*   **Example:**  Using user input directly in the file path without validation, allowing an attacker to request files outside the intended directory (e.g., `reply.sendFile(req.query.filePath)` with `filePath=../../etc/passwd`).
*   **Impact:** Access to sensitive files, potential for information disclosure or even code execution if executable files are accessed.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Never use unsanitized user input directly in the file path for `reply.sendFile()`.
    *   Use a whitelist of allowed file paths or a secure method for mapping user input to allowed files.
    *   Ensure the application has appropriate file system permissions to prevent access to sensitive files.

