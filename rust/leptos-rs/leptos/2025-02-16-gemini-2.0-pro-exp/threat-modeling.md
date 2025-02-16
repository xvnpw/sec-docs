# Threat Model Analysis for leptos-rs/leptos

## Threat: [Unauthenticated Server Function Execution](./threats/unauthenticated_server_function_execution.md)

*   **Description:** An attacker directly calls a `#[server]` function without proper authentication. The attacker crafts a request (bypassing any client-side checks) and sends it to the server endpoint associated with the server function.  This bypasses any intended access controls.
*   **Impact:** Unauthorized access to server-side resources, data modification, data exfiltration, or execution of privileged operations. The attacker could potentially delete data, modify user accounts, or access sensitive information, depending on what the server function is designed to do.
*   **Leptos Component Affected:** `#[server]` macro and the generated server function endpoint. This is a *direct* consequence of how Leptos handles server functions.
*   **Risk Severity:** Critical (if the server function accesses sensitive data or performs privileged operations) or High (if the function has less critical access, but still should be protected).
*   **Mitigation Strategies:**
    *   **Authentication Enforcement:** Implement robust authentication *within* the server function itself. Do *not* rely solely on client-side authentication. Use a session management system or token-based authentication to verify the user's identity *before* executing *any* logic within the server function. This is crucial because Leptos makes calling server functions so seamless.
    *   **Authorization Checks:** After authentication, implement authorization checks to ensure the authenticated user has the necessary permissions to execute the specific server function and access the requested resources.

## Threat: [Server Function Input Validation Bypass](./threats/server_function_input_validation_bypass.md)

*   **Description:** An attacker sends malicious input to a `#[server]` function, bypassing client-side validation. The attacker crafts a request with specially designed data that exploits a lack of input validation or sanitization *within* the server function. Because Leptos handles the serialization/deserialization, developers might be less vigilant about server-side validation.
*   **Impact:** Depends on the server function's logic. Could lead to SQL injection (if the function interacts with a database without proper parameterization), command injection (if the function executes shell commands), or other vulnerabilities *on the server*. The ease of calling server functions increases the attack surface.
*   **Leptos Component Affected:** `#[server]` macro and the server function's input parameters. The threat arises from how Leptos handles the communication between client and server, potentially leading to developer oversight.
*   **Risk Severity:** Critical or High, depending on the specific vulnerability that can be exploited due to the lack of input validation. The severity is high because server functions often have direct access to backend resources.
*   **Mitigation Strategies:**
    *   **Server-Side Input Validation:** Implement rigorous input validation and sanitization *within* the server function. Treat *all* input as untrusted, regardless of any client-side checks. Use a validation library or framework to define and enforce validation rules. This is *essential* in the context of Leptos server functions.
    *   **Parameterized Queries:** If the server function interacts with a database, *always* use parameterized queries or an ORM that handles parameterization automatically. Never construct SQL queries by concatenating user input.
    *   **Safe Command Execution:** If the server function needs to execute shell commands (which should be avoided if possible), use a safe API that prevents command injection vulnerabilities.

## Threat: [Server Function Rate Limiting Abuse (DoS)](./threats/server_function_rate_limiting_abuse__dos_.md)

*   **Description:** An attacker repeatedly calls a computationally expensive `#[server]` function, overwhelming the server and causing a denial-of-service (DoS) condition. The attacker sends a large number of requests to the server function endpoint in a short period. Leptos, by default, doesn't provide built-in rate limiting for server functions.
*   **Impact:** The server becomes unresponsive, preventing legitimate users from accessing the application.
*   **Leptos Component Affected:** `#[server]` macro and the server function endpoint. This is a direct threat because Leptos provides the mechanism for easily calling server functions, but doesn't inherently protect against overuse.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Rate Limiting Middleware:** Implement rate limiting on server function endpoints. This can be done using custom middleware or a third-party rate-limiting library. Configure rate limits based on IP address, user ID, or other relevant factors. This is a *necessary* addition to a Leptos application to mitigate this threat.
    *   **Resource Monitoring:** Monitor server resource usage (CPU, memory, network) to detect and respond to potential DoS attacks.

