# Attack Surface Analysis for openresty/lua-nginx-module

## Attack Surface: [Lua Code Injection](./attack_surfaces/lua_code_injection.md)

**Description:** Attackers inject malicious Lua code that is then executed by the Nginx worker process.

**How lua-nginx-module contributes:** The module allows embedding and executing Lua code within the Nginx request processing lifecycle. If user-controlled data is used to construct or influence the Lua code executed, it creates an injection point.

**Example:** An application takes a filename from a URL parameter and uses it in a Lua script to read the file content: `local filename = ngx.var.arg_filename; local f = io.open(filename, "r")`. An attacker could provide a malicious path like `/etc/passwd` as the filename.

**Impact:** Remote code execution on the Nginx server, potentially leading to full system compromise, data exfiltration, or denial of service.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Never directly use user input in code execution contexts.**
* **Sanitize and validate all user input rigorously.**
* **Use parameterized queries or safe APIs when interacting with external systems from Lua.**
* **Implement strict input validation and whitelisting.**
* **Employ code review and static analysis tools to identify potential injection points.

## Attack Surface: [Unsafe Lua Function Usage](./attack_surfaces/unsafe_lua_function_usage.md)

**Description:** Exploiting the use of dangerous Lua functions that provide access to system resources or allow execution of arbitrary commands.

**How lua-nginx-module contributes:** The module exposes standard Lua libraries and potentially custom Lua modules within the Nginx environment. If these libraries contain unsafe functions used without proper safeguards, vulnerabilities arise.

**Example:** A Lua script uses `os.execute(ngx.var.arg_command)` to execute a command based on a user-provided parameter. An attacker can inject arbitrary commands.

**Impact:** Remote code execution, file system access, information disclosure, denial of service.

**Risk Severity:** High

**Mitigation Strategies:**
* **Disable or restrict access to dangerous Lua functions like `os.execute`, `io.popen`, `io.open` (especially with dynamic paths), `require` with untrusted sources, and `loadstring` with untrusted input.**
* **Implement sandboxing or chroot environments for Lua execution if possible.**
* **Follow the principle of least privilege when granting access to Lua libraries and functions.**
* **Regularly review Lua code for the usage of potentially dangerous functions.

## Attack Surface: [Server-Side Request Forgery (SSRF)](./attack_surfaces/server-side_request_forgery_(ssrf).md)

**Description:** An attacker can induce the server to make requests to unintended locations, potentially internal services or external systems.

**How lua-nginx-module contributes:** Lua scripts can make outbound HTTP requests using functions like `ngx.location.capture` or external Lua HTTP libraries. If the target URL is constructed using user-controlled data without proper validation, it can lead to SSRF.

**Example:** A Lua script uses `ngx.location.capture("/internal_api?url=" .. ngx.var.arg_target_url)` where `target_url` is provided by the user. An attacker could set `target_url` to an internal service endpoint.

**Impact:** Access to internal resources, information disclosure, potential for further attacks on internal systems, denial of service against other services.

**Risk Severity:** High

**Mitigation Strategies:**
* **Sanitize and validate user-provided URLs thoroughly.**
* **Implement a whitelist of allowed destination hosts or IP addresses for outbound requests.**
* **Avoid directly using user input to construct URLs for outbound requests.**
* **Consider using a proxy server for outbound requests to enforce security policies.**
* **Disable or restrict access to functions that make outbound requests if not strictly necessary.**

