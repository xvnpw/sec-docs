# Threat Model Analysis for cesanta/mongoose

## Threat: [Connection Exhaustion DoS (due to Mongoose limits)](./threats/connection_exhaustion_dos__due_to_mongoose_limits_.md)

*   **Description:** An attacker sends a large number of connection requests, exceeding Mongoose's *configured* or *inherent* connection limits. This exploits limitations *within Mongoose's connection handling*, not just the application's use of it.
    *   **Impact:** Legitimate users are unable to connect, resulting in a denial of service. The application becomes unavailable.
    *   **Affected Mongoose Component:** Core networking code: connection handling logic (`mg_bind`, `mg_listen`, internal connection management structures).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Configure `MG_MAX_CONNECTIONS`:** Set a reasonable, *tested* limit on concurrent connections using Mongoose's configuration options. This must be appropriate for the expected load *and* the capabilities of the underlying system.
        *   **Implement Connection Timeouts (Mongoose Level):** Use Mongoose's `MG_IO_TIMEOUT` (or equivalent) to set timeouts for idle connections *within Mongoose itself*. This closes connections that are not actively used.
        *   **Monitor Mongoose Internals:** If possible, monitor Mongoose's internal connection counts and resource usage to detect attacks targeting its limits.

## Threat: [Slowloris Attack (targeting Mongoose's HTTP parsing)](./threats/slowloris_attack__targeting_mongoose's_http_parsing_.md)

*   **Description:** An attacker establishes connections and sends partial HTTP requests very slowly, exploiting potential vulnerabilities or limitations in Mongoose's *own* HTTP request parsing and connection handling. The focus is on how Mongoose *internally* handles slow requests, not just the application's response to them.
    *   **Impact:** Mongoose's connection pool becomes exhausted, preventing legitimate users from accessing the service.
    *   **Affected Mongoose Component:** HTTP request parsing and connection handling logic (specifically, how Mongoose receives and buffers incomplete requests).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Mongoose-Specific Timeouts:** Configure strict timeouts *within Mongoose* for receiving complete HTTP request headers. This might involve specific Mongoose configuration options or compile-time defines.
        *   **Review Mongoose Code:** Examine Mongoose's source code (if feasible) for how it handles incomplete requests and potential vulnerabilities related to slow clients.
        *   **Reverse Proxy (Defense in Depth):** While not a direct Mongoose mitigation, using a reverse proxy (Nginx, HAProxy) *in front* of Mongoose provides a strong defense, as these tools are designed to handle Slowloris.

## Threat: [Buffer Overflow in Mongoose's HTTP Header Parsing](./threats/buffer_overflow_in_mongoose's_http_header_parsing.md)

*   **Description:** An attacker sends a crafted HTTP request with an excessively long or malformed header, exploiting a *buffer overflow vulnerability within Mongoose's own header parsing code*. This is a direct vulnerability *in Mongoose*.
    *   **Impact:** Denial of service (crash of the Mongoose component, and thus the application). *Potentially* remote code execution (RCE) within the context of the application, leading to complete compromise.
    *   **Affected Mongoose Component:** HTTP request parsing code (specifically, functions responsible for parsing and storing HTTP headers, likely within `mg_http.c` or similar files).
    *   **Risk Severity:** Critical (if RCE is possible), High (if only DoS)
    *   **Mitigation Strategies:**
        *   **Keep Mongoose Updated:** This is the *primary* mitigation.  Regularly update to the latest version of Mongoose to obtain security patches.  Monitor the Mongoose project for security advisories.
        *   **Fuzz Testing (Targeted at Mongoose):** Perform fuzz testing *specifically on Mongoose's HTTP parsing code*, focusing on header handling. This should be done independently of the application.
        *   **Code Audit (of Mongoose):** If feasible, conduct a security audit of the relevant sections of the Mongoose codebase, focusing on buffer handling in the HTTP parsing logic.
        *   **Memory Protection (Compile-Time):** Ensure Mongoose (and the application) is compiled with memory protection features enabled (e.g., stack canaries, ASLR, DEP) to make exploitation more difficult.

## Threat: [Directory Traversal via URI Manipulation (within Mongoose's handling)](./threats/directory_traversal_via_uri_manipulation__within_mongoose's_handling_.md)

*   **Description:** An attacker crafts a URL with ".." sequences to attempt to access files outside the web root, exploiting a vulnerability *in Mongoose's file serving logic*. This focuses on how Mongoose *itself* handles path resolution, not just the application's use of it.
    *   **Impact:** Unauthorized access to sensitive files on the system. Information disclosure.
    *   **Affected Mongoose Component:** File serving logic (functions responsible for resolving file paths and serving files, likely within `mg_http.c` or similar).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Keep Mongoose Updated:**  Prioritize updates to address any potential path traversal vulnerabilities in Mongoose.
        *   **Code Audit (of Mongoose):** Review Mongoose's file serving code for proper path sanitization and handling of ".." sequences.
        *   **Chroot/Jail (System Level):**  Consider running the *entire application* (including Mongoose) within a chroot jail or similar restricted environment. This limits the impact even if Mongoose has a vulnerability. This is a system-level mitigation, but it directly protects against Mongoose vulnerabilities.
        * **Disable Directory Listing (Mongoose Config):** Ensure directory listing is disabled *within Mongoose's configuration* unless absolutely required.

## Threat: [Authentication Bypass (in Mongoose's *built-in* authentication)](./threats/authentication_bypass__in_mongoose's_built-in_authentication_.md)

*   **Description:** An attacker exploits a vulnerability *within Mongoose's built-in authentication mechanism* (if used) to gain unauthorized access. This is a direct vulnerability in Mongoose's authentication code.
    *   **Impact:** Unauthorized access to protected resources. The attacker can bypass authentication entirely.
    *   **Affected Mongoose Component:** Authentication and authorization logic (functions related to `mg_auth.c`, `mg_set_auth_handler`, or any other built-in authentication features).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid Mongoose's Built-in Authentication (Preferred):** If possible, *do not use* Mongoose's built-in authentication. Implement authentication and authorization *within the application logic* instead. This gives you much greater control and avoids relying on potentially less-secure built-in features.
        *   **Keep Mongoose Updated:** If you *must* use Mongoose's built-in authentication, keep it updated to the absolute latest version.
        *   **Code Audit (of Mongoose):** If using the built-in authentication, thoroughly review the relevant Mongoose code for potential vulnerabilities.

