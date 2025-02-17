# Attack Surface Analysis for remix-run/remix

## Attack Surface: [Server-Side Request Forgery (SSRF) in Loaders/Actions](./attack_surfaces/server-side_request_forgery__ssrf__in_loadersactions.md)

*   **Description:** Attackers manipulate user-supplied input to cause the Remix server (via `loader` or `action` functions) to make requests to unintended destinations, including internal systems or external services.
*   **How Remix Contributes:** Remix's core design *requires* server-side data fetching and processing within `loader` and `action` functions. This *inherently* creates a potential for server-side requests, and if those requests are influenced by user input without proper validation, SSRF is possible. This is a *direct* consequence of Remix's architecture.
*   **Example:** A `loader` function fetches data from a URL provided as a query parameter: `/profile?dataUrl=http://internal.api/admin`. The attacker changes `dataUrl` to point to a sensitive internal service.
*   **Impact:** Access to internal systems, databases, cloud metadata services, or sensitive external APIs; data exfiltration; potential for remote code execution (RCE) in some cases.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Use a robust validation library (e.g., Zod) to *strictly* validate *all* user-supplied input, especially URLs. Define a whitelist of allowed domains/URLs if possible. *Never* trust user input directly. This is *crucial* in the context of Remix `loader` and `action` functions.
    *   **Network Restrictions:** If possible, restrict the network access of the server running the Remix application.
    *   **Avoid User-Controlled URLs:** If feasible, avoid fetching data from URLs directly provided by users.
    *   **Proxy with Validation:** If user-provided URLs are unavoidable, use a proxy server that performs strict validation.

## Attack Surface: [Unintentional Data Exposure in Loaders](./attack_surfaces/unintentional_data_exposure_in_loaders.md)

*   **Description:** `loader` functions fetch more data than is needed for the UI, and this excess data is accidentally passed to the client, even if not directly rendered.
*   **How Remix Contributes:** Remix's `loader` functions are *the* designated mechanism for server-side data fetching.  The framework's design *directly* places the responsibility on the developer to ensure that only the necessary data is returned from these functions.  This is a *direct* attack surface created by the `loader` concept.
*   **Example:** A `loader` fetches a user object including `passwordHash` and `isAdmin` fields, but only the `username` is displayed. The full object is passed to the client (accessible via network inspection or component props).
*   **Impact:** Leakage of sensitive user data, internal system information, or other confidential details.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Data Minimization:** Fetch *only* the specific fields required by the UI within the `loader`.
    *   **Data Transformation:** Create a "view model" or DTO *within the `loader`* to transform the raw data into a client-safe format before returning it. This is a *direct* mitigation within the Remix `loader` context.
    *   **Code Review:** Carefully review `loader` functions to ensure data minimization.

## Attack Surface: [Injection Attacks (Indirect) via Loaders/Actions](./attack_surfaces/injection_attacks__indirect__via_loadersactions.md)

*   **Description:** Vulnerabilities in database libraries or ORMs used *within* `loader` or `action` functions can lead to injection attacks (SQLi, NoSQLi, etc.).
*   **How Remix Contributes:** While Remix doesn't *directly* handle database interaction, its architecture *strongly encourages* placing database interactions *within* `loader` and `action` functions for server-side data handling. This *directly* links the security of these external libraries to the Remix application's attack surface. The framework's design choice creates this indirect, but significant, risk.
*   **Example:** A `loader` uses an ORM to query a database based on user input without proper sanitization: `db.users.find({ username: req.query.username })`. An attacker provides a malicious `username` to inject a NoSQL query.
*   **Impact:** Data breaches, data modification, data deletion, potential for RCE.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Parameterized Queries/Prepared Statements:** *Always* use parameterized queries or prepared statements when interacting with databases *from within* `loader` or `action` functions.
    *   **ORM Security:** If using an ORM, ensure it's configured securely and understand its security features.
    *   **Input Validation:** Validate and sanitize *all* user input *before* using it in database queries, *especially within* `loader` and `action` functions. This is a *direct* mitigation within the Remix context.
    * **Principle of Least Privilege:** Ensure that the database user account used by the Remix application has the minimum necessary privileges.

