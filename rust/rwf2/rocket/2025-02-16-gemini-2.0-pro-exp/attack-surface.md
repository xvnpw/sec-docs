# Attack Surface Analysis for rwf2/rocket

## Attack Surface: [Route Parsing and Matching (ReDoS)](./attack_surfaces/route_parsing_and_matching__redos_.md)

*   **Description:**  Exploitation of Rocket's route parsing to cause a Denial of Service (DoS) via computationally expensive regular expression matching.
*   **Rocket's Contribution:** Rocket's routing mechanism, while generally robust, *may* use regular expressions internally (even if abstracted).  If these are not carefully crafted or limited, a ReDoS attack is possible.
*   **Example:** An attacker sends a request with a crafted URL designed to trigger worst-case performance in a poorly written regular expression used for route matching (e.g., a URL containing many repeating characters followed by a non-matching character).
*   **Impact:** Denial of Service (DoS).  The application becomes unresponsive.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Developer:**
        *   Avoid overly complex regular expressions in route definitions. If regex is unavoidable, use tools to analyze them for ReDoS vulnerabilities (e.g., regex101.com with a timeout, or specialized ReDoS checkers).
        *   Implement strict input validation *before* route matching occurs, limiting the characters and length allowed in URL segments. This limits the attacker's control over the input to the regex engine.
        *   Fuzz test the routing system with a wide range of valid and invalid URLs, specifically targeting potential ReDoS patterns.
    *   **User/Administrator:**
        *   Deploy a Web Application Firewall (WAF) with rules specifically designed to detect and block ReDoS patterns.  Many WAFs have pre-built rules for this.

## Attack Surface: [Request Data Handling (Oversized Payloads)](./attack_surfaces/request_data_handling__oversized_payloads_.md)

*   **Description:**  Attacks leveraging Rocket's request data handling to cause a Denial of Service (DoS) by sending excessively large request bodies.
*   **Rocket's Contribution:** Rocket provides mechanisms for handling various data formats (forms, JSON, etc.).  While it *should* have default limits, these might be insufficient or misconfigured.  Custom `FromData` implementations are a particular concern.
*   **Example:** An attacker sends a POST request with a multi-gigabyte JSON payload, causing the server to exhaust memory and crash.
*   **Impact:** Denial of Service (DoS). The application becomes unavailable.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Developer:**
        *   Use Rocket's built-in data validation features (`Form`, `Json`, `Valid`) to enforce *strict* size limits on all incoming data.  Explicitly set reasonable maximum sizes.
        *   Thoroughly audit and test any custom `FromData` implementations to ensure they handle large inputs safely and have appropriate size limits.
        *   Fuzz test data handling endpoints with a range of payload sizes, including very large ones.
    *   **User/Administrator:**
        *   Configure server-level limits on request body sizes (e.g., in a reverse proxy like Nginx or Apache). This provides a defense-in-depth layer, even if Rocket's limits are bypassed.

## Attack Surface: [Fairing Misconfiguration (Bypass)](./attack_surfaces/fairing_misconfiguration__bypass_.md)

*   **Description:**  Exploitation of incorrectly ordered or vulnerable Rocket fairings to bypass security controls.
*   **Rocket's Contribution:** Fairings are a core Rocket feature, providing extensibility.  Incorrect ordering can render security fairings ineffective.
*   **Example:** An authentication fairing is placed *after* a fairing that handles sensitive data or a routing fairing that exposes an unprotected endpoint, allowing an attacker to access the data or endpoint without authentication.
*   **Impact:** Bypass of security controls (authentication, authorization), leading to unauthorized access to data or functionality.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Developer:**
        *   Carefully review and document the order of *all* fairings.  Ensure that security-critical fairings (authentication, authorization, input validation) are executed *before* any fairings that handle sensitive data or perform routing to potentially vulnerable endpoints.  Use a clear, consistent naming convention for fairings to aid in understanding their purpose and order.
        *   Thoroughly audit and test all custom fairing implementations, paying close attention to their interaction with other fairings.
    *   **User/Administrator:**
        *   Regularly review application configuration and code to verify the correct ordering of fairings.

## Attack Surface: [Server-Side Template Injection (SSTI) - *If Templating is Used*](./attack_surfaces/server-side_template_injection__ssti__-_if_templating_is_used.md)

*   **Description:**  Injection of malicious template code into server-side templates, leading to arbitrary code execution.
*   **Rocket's Contribution:** While Rocket doesn't *enforce* a specific templating engine, it's commonly used with them. The vulnerability is *highly dependent* on the chosen engine and how it's used in conjunction with Rocket. Rocket's role is in how it passes data to the templating engine.
*   **Example:**  An attacker provides input like `{{ 7 * 7 }}` (or a more complex, engine-specific payload) to a field that is rendered directly into a template without proper sanitization or escaping. The server executes the code.
*   **Impact:** Arbitrary code execution on the server (extremely serious), data breaches, complete system compromise.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Choose a templating engine with automatic output escaping.** This is the *primary* defense. Examples include Tera (with autoescaping enabled) and newer versions of many popular engines.
        *   **Strictly validate and sanitize *all* user-supplied data before passing it to the template engine.** Never trust user input, even if it *appears* to be safe.
        *   **Avoid concatenating strings to build templates.** Use the templating engine's built-in features for variable substitution and control flow. This reduces the risk of accidental injection.
        *   **Regularly update the templating engine to the latest version** to patch any known vulnerabilities.
    * **User/Administrator:**
        * Use a Web Application Firewall (WAF) to detect and block common SSTI payloads. Many WAFs have rulesets specifically for this.

