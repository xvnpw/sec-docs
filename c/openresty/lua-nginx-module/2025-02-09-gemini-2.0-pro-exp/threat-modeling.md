# Threat Model Analysis for openresty/lua-nginx-module

## Threat: [Lua Code Injection via User Input](./threats/lua_code_injection_via_user_input.md)

*   **1. Threat: Lua Code Injection via User Input**

    *   **Description:** An attacker crafts malicious input that, when processed by the Lua code embedded within Nginx, results in the execution of arbitrary Lua commands within the Nginx worker process. This leverages the attacker's ability to influence how user-supplied data is used to construct or execute Lua code. The attacker's goal is to gain control of the Lua execution environment, which has access to Nginx internals and potentially the underlying system.
    *   **Impact:** Complete system compromise. The attacker gains full control over the Nginx worker process and, potentially, the underlying server. This leads to data breaches, service disruption, and the ability to launch further attacks (lateral movement).
    *   **Affected Component:** Any Lua directive that processes user input and uses it (directly or indirectly) to construct or execute Lua code.  This includes: `content_by_lua_block`, `access_by_lua_block`, `rewrite_by_lua_block`, `header_filter_by_lua_block`, `body_filter_by_lua_block`.  Vulnerable functions include those that read user input: `ngx.req.get_uri_args()`, `ngx.req.get_post_args()`, `ngx.req.get_headers()`, and `ngx.req.read_body()`.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Never Construct Lua Code from User Input:** This is paramount.  Avoid any situation where user-supplied data is concatenated into a Lua code string that is then executed.
        *   **Strict Input Validation and Sanitization:** Implement rigorous input validation, ensuring user input conforms to expected formats and lengths. Sanitize all input used within Lua code, even if it's not directly used for code construction.  Prioritize whitelisting (allowing only known-good characters) over blacklisting.
        *   **Parameterized Queries (for Database Interactions):** If Lua code interacts with databases, *always* use parameterized queries or prepared statements to prevent SQL injection, which could indirectly lead to Lua code injection.
        *   **Safe String Concatenation:** If dynamic string construction is absolutely necessary (and strongly reconsider if it is), use safe string concatenation methods that are designed to prevent injection vulnerabilities.

## Threat: [Denial of Service (DoS) via Infinite Loops or Resource Exhaustion (Lua-Specific)](./threats/denial_of_service__dos__via_infinite_loops_or_resource_exhaustion__lua-specific_.md)

*   **2. Threat: Denial of Service (DoS) via Infinite Loops or Resource Exhaustion (Lua-Specific)**

    *   **Description:** An attacker provides input specifically crafted to trigger an infinite loop, excessive memory allocation, or other resource-intensive operations within the Lua code running inside Nginx. This exploits vulnerabilities in the Lua logic or leverages computationally expensive operations with untrusted input. Because Lua runs within the Nginx worker process, this directly impacts Nginx's ability to handle requests.
    *   **Impact:** Denial of service. The affected Nginx worker process becomes unresponsive, preventing legitimate users from accessing the application. This leads to service disruption and potential financial losses.
    *   **Affected Component:** Any Lua code that handles user input, performs looping, recursion, or complex computations. This includes all `*_by_lua_block` directives and custom Lua modules. Functions involving loops or recursion are particularly at risk.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Timeouts:** Implement timeouts for *all* network operations initiated from Lua. Use `lua_socket_read_timeout`, `lua_socket_send_timeout`, and `lua_socket_connect_timeout`. Utilize `ngx.timer.at` for asynchronous tasks, ensuring they also have timeouts.
        *   **Input Validation (Size and Complexity):** Strictly limit the size and complexity of user input processed by Lua code. This includes limiting string lengths, array sizes, and the depth of nested data structures.
        *   **Loop Guards:** Implement safeguards within loops to prevent infinite loops. Set a maximum number of iterations or introduce conditions that will break the loop if it runs for too long.
        *   **Code Profiling:** Regularly profile Lua code to identify performance bottlenecks and potential DoS vulnerabilities. This helps pinpoint areas where resource consumption is unexpectedly high.

## Threat: [Bypassing Security Controls via Lua Code](./threats/bypassing_security_controls_via_lua_code.md)

*   **3. Threat: Bypassing Security Controls via Lua Code**

    *   **Description:** An attacker leverages Lua code to modify request headers, the request body, or other request attributes in a way that circumvents existing Nginx security configurations or modules. This could involve bypassing authentication checks, authorization rules, or Web Application Firewall (WAF) protections. The attacker exploits the ability of Lua to manipulate the request processing pipeline.
    *   **Impact:** Bypass of security controls, leading to unauthorized access to protected resources, data breaches, and other security compromises. The attacker can effectively disable or neutralize security measures.
    *   **Affected Component:** Lua code that modifies request or response headers (`ngx.req.set_header()`, `ngx.req.clear_header()`, `ngx.header.*`) or the request body (`ngx.req.set_body_data()`, `ngx.req.set_body_file()`). This primarily impacts `rewrite_by_lua_block`, `access_by_lua_block`, `header_filter_by_lua_block`, and `body_filter_by_lua_block`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Code Review:** Conduct thorough code reviews of all Lua code that modifies request or response components, paying close attention to how these modifications might interact with security mechanisms.
        *   **Least Privilege:** Limit the capabilities of Lua code. Avoid granting unnecessary access to Nginx internals or the ability to modify sensitive request attributes.
        *   **Input Validation (After Modification):** If Lua code modifies the request, *re-validate* the modified request to ensure it still meets all security requirements. This prevents attackers from bypassing initial validation checks.
        *   **Order of Execution:** Carefully control the order in which Lua code and other Nginx modules are executed. Ensure that security checks are performed *after* any modifications made by Lua code.

## Threat: [Server-Side Request Forgery (SSRF) via Lua](./threats/server-side_request_forgery__ssrf__via_lua.md)

*   **4. Threat: Server-Side Request Forgery (SSRF) via Lua**

    *   **Description:**  An attacker crafts input that causes the Lua code within Nginx to make unintended requests to arbitrary internal or external servers.  This allows the attacker to potentially access internal resources, scan the internal network, or launch attacks against other systems, all from the context of the Nginx server.  The attacker exploits Lua's ability to make HTTP requests.
    *   **Impact:**  Unauthorized access to internal resources, network reconnaissance, and the potential for launching further attacks against internal or external systems.
    *   **Affected Component:** Lua code that makes HTTP requests, especially using `ngx.location.capture()`, `ngx.location.capture_multi()`, or third-party Lua HTTP client libraries (like `lua-http`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Input Validation (URLs):**  Rigorously validate any user-supplied URLs or hostnames before making any requests.  Use a whitelist of allowed destinations whenever possible.
        *   **Avoid User-Controlled URLs:**  Whenever feasible, avoid using user input directly in URLs.  Instead, use a predefined set of allowed destinations or map user input to safe, pre-approved URLs.
        *   **Network Segmentation:**  Isolate the Nginx server from sensitive internal networks to limit the impact of successful SSRF attacks.
        *   **Firewall Rules:**  Configure firewall rules to restrict outbound connections from the Nginx server to only necessary and explicitly allowed destinations.

