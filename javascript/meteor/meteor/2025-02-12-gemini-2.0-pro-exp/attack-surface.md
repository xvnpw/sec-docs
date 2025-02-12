# Attack Surface Analysis for meteor/meteor

## Attack Surface: [Insecure Data Publication/Subscription](./attack_surfaces/insecure_data_publicationsubscription.md)

*   **Description:**  Unauthorized access to sensitive data due to improperly configured Meteor publications and subscriptions.
*   **Meteor Contribution:** Meteor's real-time data synchronization model, if not carefully managed, can easily expose more data than intended to connected clients. The initial `autopublish` package exacerbates this. This is a *core* Meteor feature that requires careful attention.
*   **Example:** A publication that sends all user data (including email addresses, password hashes (even if hashed, this is bad), and private profile information) to all connected clients, even if the client-side UI only displays a username.
*   **Impact:** Data breach, privacy violation, potential for account takeover, regulatory non-compliance (e.g., GDPR).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Remove `autopublish`:**  Never use `autopublish` in production.  Remove it immediately.
    *   **Granular Publications:**  Create publications that *only* return the specific fields a client needs, based on role and permissions.  Avoid "select all" queries.
    *   **Parameterized Publications:**  Use parameters, but *thoroughly* validate them on the server using a schema.
    *   **Server-Side Validation:**  Validate *all* inputs to publication functions using a schema (e.g., `simpl-schema`, `zod`).
    *   **Authorization within Publications:**  Use `this.userId` within publication functions for authorization checks.
    *   **Regular Audits:**  Conduct regular code reviews of publications and subscriptions.
    *   **Testing:** Write unit and integration tests to verify publication behavior.

## Attack Surface: [Unvalidated Method Calls](./attack_surfaces/unvalidated_method_calls.md)

*   **Description:**  Execution of malicious or unintended actions due to improperly secured Meteor Methods.
*   **Meteor Contribution:** Meteor Methods provide a direct client-to-server communication channel, which is a core part of Meteor's design.  This requires careful security considerations.
*   **Example:** A method designed to update a user's profile that doesn't validate the input, allowing an attacker to inject malicious HTML (XSS) or modify other users' profiles.
*   **Impact:**  Data modification, data corruption, privilege escalation, XSS, denial-of-service, execution of arbitrary code (in extreme cases).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Schema Validation:**  Use a schema validation library (e.g., `simpl-schema`, `zod`) to validate *all* method arguments.
    *   **Authorization Checks:**  Implement robust authorization checks *within* each method using `this.userId`.
    *   **Rate Limiting:**  Use `ddp-rate-limiter` to prevent brute-force and denial-of-service attacks.
    *   **Input Sanitization:**  Sanitize user-provided data to prevent injection attacks.
    *   **Error Handling:**  Handle errors gracefully and avoid exposing sensitive information.
    *   **Testing:** Write comprehensive unit and integration tests for all methods.

## Attack Surface: [DDP Protocol Manipulation (Without HTTPS)](./attack_surfaces/ddp_protocol_manipulation__without_https_.md)

*   **Description:** Exploitation of vulnerabilities in the Distributed Data Protocol (DDP) when HTTPS is *not* used.
*   **Meteor Contribution:** Meteor uses DDP as its core communication protocol. While DDP itself has security considerations, the *lack* of HTTPS makes it critically vulnerable.
*   **Example:** An attacker in a man-in-the-middle position intercepts and modifies DDP messages to change data in transit.
*   **Impact:** Data manipulation, impersonation, complete compromise of data in transit.
*   **Risk Severity:** High (becomes *Critical* without HTTPS)
*   **Mitigation Strategies:**
    *   **Mandatory HTTPS:** *Always* use HTTPS. This is the *primary* mitigation. Without HTTPS, DDP is inherently insecure.
    *   **Meteor Updates:** Keep Meteor updated.
    *   **Network Monitoring:** Monitor for unusual DDP activity.
    *   **Connection Rate Limiting:** Implement at the network level.

