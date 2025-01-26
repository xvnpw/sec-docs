# Attack Surface Analysis for openresty/openresty

## Attack Surface: [Lua Code Injection](./attack_surfaces/lua_code_injection.md)

*   **Description:** Attackers inject malicious Lua code into the application, which is then executed by the OpenResty Lua runtime.
*   **How OpenResty Contributes:** OpenResty's core functionality is executing Lua code within NGINX. Functions like `ngx.eval`, `loadstring`, and misused `require` become entry points for code injection if user-supplied data is not properly sanitized before being used in these functions.
*   **Example:** An application uses `ngx.timer.at(delay, function() ngx.eval(user_input) end)` to schedule Lua code execution based on user input. If `user_input` is not sanitized, an attacker can inject arbitrary Lua code that will be executed by the server after the delay.
*   **Impact:** Critical. Full server compromise, arbitrary code execution, data breach, denial of service, and complete application takeover are possible.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Input Sanitization:**  Thoroughly sanitize and validate all user inputs before incorporating them into Lua code, especially when using functions that execute code dynamically.
    *   **Avoid Dynamic Code Execution:** Minimize or eliminate the use of dynamic code execution functions like `ngx.eval` and `loadstring`. Prefer parameterized queries or pre-defined logic where possible.
    *   **Secure Code Review and Static Analysis:** Implement mandatory code reviews focusing on injection vulnerabilities. Utilize static analysis tools to automatically detect potential code injection flaws in Lua code.
    *   **Principle of Least Privilege in Lua:** Design Lua code with the principle of least privilege. Limit the capabilities of Lua scripts and restrict access to sensitive APIs or system resources.

## Attack Surface: [Server-Side Request Forgery (SSRF) via Lua](./attack_surfaces/server-side_request_forgery__ssrf__via_lua.md)

*   **Description:** Attackers exploit the application to make requests to internal or external resources that the attacker should not have direct access to.
*   **How OpenResty Contributes:** OpenResty's Lua API provides powerful networking capabilities through functions like `ngx.location.capture`, `ngx.socket.tcp`, and `ngx.socket.udp`.  If user-controlled data is used to construct URLs or network requests without proper validation, SSRF vulnerabilities are introduced.
*   **Example:** Lua code uses `ngx.location.capture("/internal-api?url=" .. user_provided_url)` to proxy requests. If `user_provided_url` is not validated, an attacker can set it to `http://localhost:8080/admin` to access internal admin interfaces or `http://internal-service/sensitive-data` to retrieve confidential information.
*   **Impact:** High. Access to internal resources, exposure of sensitive data from internal services, potential for further attacks on internal infrastructure, and denial of service of internal services.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Robust Input Validation for URLs:** Implement strict validation and sanitization of all user-provided URLs and parameters used in outbound requests. Use allowlists of permitted domains, protocols, and ports.
    *   **URL Parsing and Validation Libraries:** Utilize reliable URL parsing and validation libraries in Lua to ensure URLs are well-formed and conform to security policies.
    *   **Network Segmentation and Firewalls:** Implement network segmentation to isolate internal networks. Use firewalls to restrict outbound traffic from the OpenResty server to only necessary destinations.
    *   **Principle of Least Privilege (Network Access):** Limit the network access of the OpenResty server to the minimum required external and internal resources. Deny access to internal networks or sensitive services by default.
    *   **Disable Unnecessary Outbound Request Features:** If outbound requests are not essential, disable or restrict the use of Lua functions that enable them to reduce the attack surface.

## Attack Surface: [Lua Module Vulnerabilities](./attack_surfaces/lua_module_vulnerabilities.md)

*   **Description:** Security vulnerabilities present in third-party or even core Lua modules used within the OpenResty application.
*   **How OpenResty Contributes:** OpenResty applications heavily rely on Lua modules for extended functionality. Vulnerabilities in these modules directly impact the security of the OpenResty application.
*   **Example:** An application uses an outdated version of `lua-resty-jwt` with a known signature validation bypass vulnerability. An attacker could forge JWT tokens and bypass authentication, gaining unauthorized access to protected resources.
*   **Impact:** High to Critical (depending on the vulnerability and the compromised module's role). Potential for authentication bypass, data breaches, privilege escalation, and application compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Comprehensive Dependency Management:** Maintain a detailed inventory of all Lua modules used by the application and their versions.
    *   **Regular Module Updates:**  Establish a process for regularly updating Lua modules to the latest versions to patch known vulnerabilities. Automate dependency updates where possible.
    *   **Vulnerability Scanning for Modules:** Integrate vulnerability scanning tools into the development pipeline to automatically identify known vulnerabilities in Lua modules.
    *   **Secure Module Selection and Auditing:** Choose well-maintained and reputable Lua modules from trusted sources. For critical applications, conduct security audits of module source code, especially for modules handling sensitive data or security-critical functions.
    *   **Dependency Pinning:** Use dependency pinning to ensure consistent module versions across environments and to control updates carefully, allowing for testing before deployment.

