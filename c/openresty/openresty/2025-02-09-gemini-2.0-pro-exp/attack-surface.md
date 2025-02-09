# Attack Surface Analysis for openresty/openresty

## Attack Surface: [1. Nginx Core Vulnerabilities](./attack_surfaces/1__nginx_core_vulnerabilities.md)

*   **Description:**  Exploitable flaws in the core Nginx HTTP server code.
*   **OpenResty Contribution:** OpenResty directly relies on Nginx; any Nginx vulnerability is an OpenResty vulnerability.
*   **Example:**  A buffer overflow in Nginx's handling of HTTP headers could allow an attacker to execute arbitrary code (e.g., CVE-2013-2028).
*   **Impact:**  Remote Code Execution (RCE), Denial of Service (DoS), Information Disclosure.
*   **Risk Severity:**  Critical (if RCE is possible) or High (for DoS/Information Disclosure).
*   **Mitigation Strategies:**
    *   **Update Regularly:** Maintain the *absolute latest* stable version of OpenResty. This is paramount.
    *   **Monitor Advisories:** Actively monitor both Nginx and OpenResty security advisories.
    *   **WAF:** Employ a Web Application Firewall (WAF) with rules to detect and block exploits targeting known Nginx vulnerabilities.
    *   **Input Validation (Lua):** Use Lua scripting within OpenResty to perform strict input validation *before* data reaches Nginx's core.
    *   **Limit Exposure:** Minimize the exposure of the Nginx server to the public internet.

## Attack Surface: [2. Nginx Module Vulnerabilities](./attack_surfaces/2__nginx_module_vulnerabilities.md)

*   **Description:**  Flaws in enabled Nginx modules (e.g., `ngx_http_ssl_module`, `ngx_http_proxy_module`).
*   **OpenResty Contribution:** OpenResty uses Nginx modules; vulnerabilities in enabled modules are directly exploitable.
*   **Example:** A vulnerability in a specific module that allows for RCE or a significant DoS.
*   **Impact:** DoS, Information Disclosure, potentially RCE (depending on the module).
*   **Risk Severity:** High (depending on the module and vulnerability, RCE potential elevates to Critical).
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:** *Disable all unnecessary Nginx modules*. This is crucial.
    *   **Module Auditing:** Regularly review the list of enabled modules.
    *   **Monitor Advisories:** Track security advisories for *all* enabled modules.
    *   **Configuration Hardening:** Ensure secure configuration of each enabled module.

## Attack Surface: [3. Nginx Module Misconfiguration](./attack_surfaces/3__nginx_module_misconfiguration.md)

*   **Description:** Incorrect or insecure configuration of Nginx modules.
*   **OpenResty Contribution:** OpenResty relies on Nginx configuration; misconfigurations are directly exploitable.
*   **Example:** Misconfiguring `proxy_pass` leading to Server-Side Request Forgery (SSRF). Weak TLS cipher suites.
*   **Impact:** SSRF, Information Disclosure, DoS, Man-in-the-Middle (MitM) attacks.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Configuration Review:** Thoroughly review and understand *every* Nginx directive.
    *   **Configuration Management:** Use configuration management tools (Ansible, Chef, etc.) and version control.
    *   **Testing:** Use `nginx -t` and automated configuration testing.
    *   **Security Audits:** Regularly conduct security audits of Nginx configurations.
    *   **Least Privilege (File Permissions):** Run Nginx worker processes with minimal privileges.

## Attack Surface: [4. Lua/LuaJIT Vulnerabilities](./attack_surfaces/4__lualuajit_vulnerabilities.md)

*   **Description:** Exploitable flaws in the LuaJIT runtime itself.
*   **OpenResty Contribution:** OpenResty embeds LuaJIT; vulnerabilities in LuaJIT directly impact OpenResty.
*   **Example:** A hypothetical buffer overflow in LuaJIT allowing limited code execution.
*   **Impact:** DoS, potentially limited code execution within the Lua sandbox.
*   **Risk Severity:** High (if code execution is possible).
*   **Mitigation Strategies:**
    *   **Update OpenResty:** Keep OpenResty updated to the latest stable version.
    *   **Monitor LuaJIT Advisories:** Stay informed about LuaJIT security updates.

## Attack Surface: [5. Vulnerable Lua Libraries (LuaRocks)](./attack_surfaces/5__vulnerable_lua_libraries__luarocks_.md)

*   **Description:** Security flaws in third-party Lua libraries installed via LuaRocks.
*   **OpenResty Contribution:** OpenResty applications often use LuaRocks; vulnerable libraries introduce risk.
*   **Example:** A Lua library with a vulnerability allowing RCE or a significant DoS.
*   **Impact:** DoS, Information Disclosure, potentially RCE (depending on the library).
*   **Risk Severity:** High (depending on the library, RCE potential elevates to Critical).
*   **Mitigation Strategies:**
    *   **Dependency Vetting:** *Carefully* evaluate any Lua library before using it.
    *   **Dependency Management:** Use LuaRocks, pin library versions, and track updates.
    *   **Software Composition Analysis (SCA):** Use SCA tools to identify vulnerable libraries.
    *   **Regular Audits:** Periodically audit all dependencies.

## Attack Surface: [6. Insecure Lua Code](./attack_surfaces/6__insecure_lua_code.md)

*   **Description:** Vulnerabilities introduced by custom Lua code.
*   **OpenResty Contribution:** This is the *primary* OpenResty-specific attack surface.
*   **Example:** Command injection via `os.execute`, SQL injection within Lua, path traversal, lack of input validation.
*   **Impact:** RCE, DoS, Information Disclosure, Authentication/Authorization Bypass, Data Corruption, etc.
*   **Risk Severity:** Critical to High (depending on the specific vulnerability).
*   **Mitigation Strategies:**
    *   **Secure Coding Practices (Mandatory):** Strict input validation, output encoding, avoid `os.execute`, parameterized queries, safe file handling, robust error handling, least privilege.
    *   **Code Reviews:** Mandatory, thorough code reviews focusing on security.
    *   **Static Analysis (Limited):** Explore available static analysis tools for Lua.
    *   **Dynamic Analysis (Fuzzing):** Use fuzzing to test Lua code.
    *   **Limit `ffi`:** Restrict and carefully review any use of the `ffi` library.
    *   **Resource Limits (ngx_lua):** Configure Nginx to limit Lua script resource consumption (CPU, memory).

## Attack Surface: [7. Server-Side Request Forgery (SSRF)](./attack_surfaces/7__server-side_request_forgery__ssrf_.md)

*   **Description:** Attacker manipulates OpenResty to make requests to unintended systems.
*   **OpenResty Contribution:** OpenResty's reverse proxy use and Lua scripting make it a target.
*   **Example:** Attacker supplies a URL to an internal service, and OpenResty, lacking validation, uses it in `proxy_pass` or a Lua HTTP client.
*   **Impact:** Access to internal systems, data exfiltration, port scanning, DoS.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Validate *all* user-supplied data used to construct URLs.
    *   **Whitelist:** Maintain a whitelist of allowed upstream hosts or IP addresses.
    *   **Avoid User-Controlled `proxy_pass`:** Do *not* allow user input to directly control `proxy_pass`.
    *   **Network Segmentation:** Use firewalls to restrict outbound connections from OpenResty.
    *   **Dedicated DNS Resolver:** Use a DNS resolver that cannot resolve internal hostnames.

