# Attack Surface Analysis for openresty/lua-nginx-module

## Attack Surface: [Code Injection (Lua)](./attack_surfaces/code_injection__lua_.md)

*   **Description:**  Attackers inject malicious Lua code into the application, which is then executed by the Nginx worker process.
*   **`lua-nginx-module` Contribution:**  The module provides the *core* execution environment for Lua code within Nginx. This is the fundamental enabler of this attack.
*   **Example:**  A URL parameter is directly used within a `ngx.say()` call without sanitization: `ngx.say("Hello, " .. ngx.var.arg_name)`. An attacker could supply a crafted `name` value to inject Lua code. More realistically, this could involve manipulating database queries, file system operations, or network requests constructed within Lua.
*   **Impact:**  Complete server compromise, data exfiltration, arbitrary code execution (within the context of the Nginx worker), denial of service.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Strict Input Validation:**  Rigorously validate and sanitize *all* user-supplied input (and data from any untrusted source) before using it in *any* Lua code.  Use whitelisting approaches whenever possible.  This is the *primary* defense.
    *   **Parameterized Queries:**  If interacting with databases from Lua, *always* use parameterized queries (prepared statements) to prevent SQL injection via Lua.  Never construct SQL queries through string concatenation.
    *   **Avoid `loadstring`/`load`:**  Do not use `loadstring` or `load` with untrusted input. These functions dynamically execute Lua code from strings and are extremely dangerous if misused.
    *   **Sandboxing (if available):**  Explore Lua sandboxing techniques (if supported and appropriate for your environment) to limit the capabilities of executed Lua code. This can provide a defense-in-depth layer.
    *   **Least Privilege:** Run Nginx worker processes with the *least* necessary privileges on the operating system. This limits the damage an attacker can do even if they achieve code execution.

## Attack Surface: [Denial of Service (Resource Exhaustion)](./attack_surfaces/denial_of_service__resource_exhaustion_.md)

*   **Description:**  Attackers exploit Lua code to consume excessive server resources (CPU, memory), leading to a denial-of-service condition.
*   **`lua-nginx-module` Contribution:**  The module allows Lua code to run within the Nginx worker processes, providing the direct mechanism for resource consumption.
*   **Example:**  An attacker triggers a Lua script containing an infinite loop or allocates large amounts of memory based on a controllable input parameter.  Another example is triggering computationally expensive operations (e.g., complex regular expressions, cryptographic operations) on user-supplied input within a Lua script.
*   **Impact:**  Service unavailability, degraded performance, potential server crash.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **Resource Limits (if possible):**  Configure resource limits for Lua scripts within the Nginx environment, if supported. This might involve setting memory limits or CPU time limits.
    *   **Timeouts:**  Implement timeouts for Lua script execution to prevent long-running or infinite loops from consuming resources indefinitely. Use `ngx.timer.at` for asynchronous tasks with timeouts.
    *   **Input Validation (Size Limits):**  Enforce strict size limits on user-supplied input that is processed by Lua scripts, especially if that input affects memory allocation or loop iterations.
    *   **Code Review:**  Thoroughly review Lua code for potential resource exhaustion vulnerabilities (infinite loops, excessive memory allocation, inefficient algorithms).
    *   **Rate Limiting:** Implement rate limiting (potentially within Lua itself, using `ngx.shared.dict`) to prevent attackers from overwhelming the server with requests that trigger resource-intensive Lua code.
    * **Monitoring:** Actively monitor CPU and memory usage of Nginx worker processes to detect and respond to DoS attempts.

## Attack Surface: [Security Bypass (Logic Errors)](./attack_surfaces/security_bypass__logic_errors_.md)

*   **Description:**  Flaws in the application's Lua logic allow attackers to bypass intended security controls (authentication, authorization, rate limiting, etc.).
*   **`lua-nginx-module` Contribution:**  The module provides the platform for implementing (and potentially misimplementing) security logic *within* Nginx, making this bypass possible.
*   **Example:**  A Lua script intended to enforce role-based access control has a logical error that grants access to unauthorized users under specific conditions. A script designed to prevent brute-force attacks has a flaw allowing bypass of login attempt limits.
*   **Impact:**  Unauthorized access to resources, data breaches, privilege escalation.
*   **Risk Severity:**  High to Critical (depending on the bypassed control and its consequences)
*   **Mitigation Strategies:**
    *   **Rigorous Code Review:**  Code reviews must focus specifically on the *security implications* of the Lua logic. Involve security experts in the review process.
    *   **Extensive Testing:**  Include unit tests, integration tests, and *security-focused* tests (fuzzing, penetration testing). Test boundary conditions and edge cases thoroughly.
    *   **Secure Coding Practices:**  Follow secure coding principles. Avoid complex logic in security-critical code. Keep it as simple and auditable as possible.
    *   **Formal Verification (if feasible):** For *highly* critical security logic, consider formal verification techniques to mathematically prove the correctness of the code (though this is often impractical).

## Attack Surface: [Insecure API Usage (`ngx.*`) - Specifically SSRF and High-Impact Misuse](./attack_surfaces/insecure_api_usage___ngx____-_specifically_ssrf_and_high-impact_misuse.md)

*   **Description:** Misuse of the `ngx.*` APIs, particularly those that can lead to Server-Side Request Forgery (SSRF) or other high-impact vulnerabilities.
*   **`lua-nginx-module` Contribution:** The module *defines* these APIs, making their misuse possible. This entry focuses on the most dangerous API misuses.
*   **Example:** Using `ngx.location.capture` or `ngx.location.capture_multi` to make internal requests *without* validating the target URL, allowing an attacker to access internal services or resources.  This is a classic SSRF scenario. Another example: using `ngx.req.read_body()` without `client_max_body_size` leading to DoS.
*   **Impact:** Server-Side Request Forgery (SSRF), denial of service, potentially data exfiltration or internal system compromise.
*   **Risk Severity:** High to Critical
*   **Mitigation Strategies:**
    *   **Strict Input Validation (for API parameters):**  *Always* validate any user-supplied data (or data from untrusted sources) that is passed as a parameter to a `ngx.*` API call, especially URLs or paths.
    *   **`ngx.location.capture` and SSRF:**  If using `ngx.location.capture` (or similar APIs for internal requests), *never* allow user input to directly control the target URL. Use a whitelist of allowed internal targets.
    *   **`client_max_body_size`:**  *Always* set `client_max_body_size` in your Nginx configuration to prevent denial-of-service attacks via large request bodies when using `ngx.req.read_body()`.
    *   **API Documentation:** Thoroughly understand the security implications of *each* `ngx.*` API used.
    * **Locking with `ngx.shared.dict`:** Use appropriate locking mechanisms (e.g., `ngx.shared.dict:lock`) when accessing shared resources to prevent race conditions that could lead to security issues.

## Attack Surface: [Vulnerable Third-Party Lua Modules](./attack_surfaces/vulnerable_third-party_lua_modules.md)

*   **Description:**  Vulnerabilities in external Lua modules used by the application are exploited.
*   **`lua-nginx-module` Contribution:**  The module allows the use of external Lua modules, thus inheriting their potential vulnerabilities. The module itself doesn't *cause* the vulnerability, but it enables the *use* of the vulnerable component.
*   **Example:**  A Lua module used for parsing JSON data has a vulnerability that allows an attacker to execute arbitrary code. A cryptography module has a weakness that allows an attacker to decrypt sensitive data.
*   **Impact:**  Varies depending on the vulnerability in the module, potentially ranging from denial of service to complete server compromise.
*   **Risk Severity:**  High to Critical (depending on the module and vulnerability)
*   **Mitigation Strategies:**
    *   **Dependency Management:**  Use a dependency management system (e.g., LuaRocks) to track and manage Lua modules.
    *   **Vulnerability Scanning:**  Regularly scan Lua modules for known vulnerabilities.  Use a software composition analysis (SCA) tool.
    *   **Module Updates:**  Keep Lua modules updated to the latest versions to patch known vulnerabilities.  Automate this process if possible.
    *   **Vetting:**  Carefully vet any third-party Lua modules before using them.  Consider the module's reputation, security history, and maintenance status.  Prefer well-maintained and widely used modules.
    * **SBOM:** Maintain a Software Bill of Materials (SBOM) to track all dependencies.

## Attack Surface: [Insecure FFI Usage](./attack_surfaces/insecure_ffi_usage.md)

*   **Description:**  Vulnerabilities introduced through the use of the Lua FFI (Foreign Function Interface) to interact with C libraries.
*   **`lua-nginx-module` Contribution:** The module provides the FFI capability, enabling this attack surface.
*   **Example:**  Calling a C function from Lua with incorrect parameters, leading to a buffer overflow or memory corruption. Using an insecure C library with known vulnerabilities.
*   **Impact:**  Memory corruption, arbitrary code execution, denial of service.
*   **Risk Severity:** High to Critical
*   **Mitigation Strategies:**
    *   **Minimize FFI Use:** Avoid using the FFI if possible. Prefer using pure Lua implementations or well-vetted Lua modules that abstract away the FFI. This is the *best* mitigation.
    *   **Expert Review:** If FFI use is *unavoidable*, have the code reviewed by a security expert with experience in *both* Lua and C security.
    *   **Safe C Libraries:** Use only well-vetted and secure C libraries. Keep C libraries updated to the latest versions.
    *   **Memory Safety:** Pay *extreme* attention to memory management when interacting with C code. Use appropriate techniques to prevent buffer overflows, memory leaks, and other memory-related vulnerabilities.
    *   **Input Validation (to C functions):** Carefully validate *all* data passed to C functions via the FFI.

