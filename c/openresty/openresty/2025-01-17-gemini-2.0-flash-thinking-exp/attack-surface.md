# Attack Surface Analysis for openresty/openresty

## Attack Surface: [Lua Code Injection](./attack_surfaces/lua_code_injection.md)

**Description:** Attackers inject malicious Lua code that is then executed by the OpenResty application.

**How OpenResty Contributes:** OpenResty allows embedding Lua code within Nginx configuration and request handling. If user-supplied data is directly incorporated into Lua code executed by OpenResty (e.g., using `loadstring` or similar without proper sanitization), it creates an entry point for code injection.

**Example:** A web application takes user input for a search query and directly uses it within a Lua script to construct a database query without proper escaping. An attacker could inject Lua code within the search query to execute arbitrary commands.

**Impact:** Full server compromise, data breach, service disruption, installation of malware, and further attacks on internal networks.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Always sanitize and validate user inputs before using them in Lua code.
* Avoid dynamic code execution with user-supplied data whenever possible.
* Use parameterized queries for database interactions.
* Employ secure coding practices and code reviews.

## Attack Surface: [Server-Side Request Forgery (SSRF) via Cosockets](./attack_surfaces/server-side_request_forgery__ssrf__via_cosockets.md)

**Description:** An attacker can induce the OpenResty server to make requests to arbitrary internal or external resources.

**How OpenResty Contributes:** OpenResty's `ngx.socket.tcp` and `ngx.socket.udp` APIs in Lua allow developers to make arbitrary network requests from the server-side. If not properly controlled, this can be exploited.

**Example:** A Lua script takes a URL as input from the user and uses `ngx.socket.tcp` to fetch content from that URL. An attacker could provide an internal IP address or a sensitive service endpoint as the URL.

**Impact:** Access to internal resources, information disclosure, potential for further attacks on internal systems, and denial-of-service against internal or external services.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement strict input validation and sanitization for URLs or hostnames used in cosocket requests.
* Maintain a whitelist of allowed destination hosts or networks.
* Avoid directly using user-supplied data in cosocket requests.
* Consider using a proxy server for outbound requests to enforce security policies.

## Attack Surface: [Resource Exhaustion via Malicious Lua Scripts](./attack_surfaces/resource_exhaustion_via_malicious_lua_scripts.md)

**Description:** Attackers craft Lua scripts that consume excessive server resources (CPU, memory, file descriptors), leading to denial-of-service.

**How OpenResty Contributes:** OpenResty's execution of Lua code allows for complex logic. Poorly written or malicious scripts can create infinite loops, allocate excessive memory, or open a large number of connections.

**Example:** A Lua script contains an infinite loop that is triggered by a specific user request, causing the worker process to become unresponsive and consume excessive CPU.

**Impact:** Denial-of-service, impacting the availability of the application.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement timeouts and resource limits within Lua scripts (e.g., using `ngx.timer.at`).
* Carefully review Lua code for potential resource exhaustion issues.
* Monitor server resource usage and implement alerts for unusual activity.
* Consider using OpenResty's built-in rate limiting features.

## Attack Surface: [Shared Dictionary Abuse](./attack_surfaces/shared_dictionary_abuse.md)

**Description:** Attackers manipulate data stored in OpenResty's shared dictionaries to influence the behavior of other worker processes or gain access to sensitive information.

**How OpenResty Contributes:** OpenResty's `ngx.shared.DICT` allows sharing data between Nginx worker processes. If access to this dictionary is not properly controlled, attackers can modify or read sensitive data.

**Example:** A shared dictionary stores temporary authentication tokens. An attacker could manipulate this dictionary to invalidate legitimate tokens or inject their own.

**Impact:** Authentication bypass, privilege escalation, data manipulation, and service disruption.

**Risk Severity:** High

**Mitigation Strategies:**
* Carefully control access to shared dictionaries and validate data before using it.
* Avoid storing highly sensitive information directly in shared dictionaries if possible.
* Implement proper authorization checks before allowing access to or modification of shared dictionary entries.

## Attack Surface: [Vulnerabilities in Lua Libraries](./attack_surfaces/vulnerabilities_in_lua_libraries.md)

**Description:** Third-party Lua libraries used within the OpenResty application contain security vulnerabilities that can be exploited.

**How OpenResty Contributes:** OpenResty applications often rely on external Lua libraries for various functionalities. Vulnerabilities in these libraries become part of the application's attack surface due to OpenResty's Lua integration.

**Example:** A vulnerable version of a JSON parsing library is used, allowing an attacker to craft a malicious JSON payload that triggers a buffer overflow.

**Impact:** Depends on the vulnerability, but can range from information disclosure to remote code execution.

**Risk Severity:** Medium to Critical (depending on the vulnerability - including here as some library vulnerabilities can be critical)

**Mitigation Strategies:**
* Keep all Lua libraries up-to-date with the latest security patches.
* Regularly audit the dependencies of your OpenResty application.
* Use reputable and well-maintained libraries.
* Consider using static analysis tools to identify potential vulnerabilities in Lua code and libraries.

## Attack Surface: [Misconfigured `access_by_lua*` or `content_by_lua*` Directives](./attack_surfaces/misconfigured__access_by_lua__or__content_by_lua__directives.md)

**Description:** Incorrectly configured Nginx directives that execute Lua code can bypass intended security controls or expose sensitive information.

**How OpenResty Contributes:** OpenResty relies heavily on these directives to integrate Lua logic into the request processing pipeline. Misconfigurations directly expose the application to risks.

**Example:** An `access_by_lua_block` directive is used for authentication but fails to properly validate user credentials, allowing unauthorized access.

**Impact:** Unauthorized access, information disclosure, and potential for further exploitation.

**Risk Severity:** Medium to High (depending on the misconfiguration - including here as some misconfigurations can be high)

**Mitigation Strategies:**
* Thoroughly review and test all `access_by_lua*` and `content_by_lua*` configurations.
* Ensure proper authentication and authorization checks are implemented in the Lua code.
* Follow the principle of least privilege when granting access.

