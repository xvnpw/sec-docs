# Attack Surface Analysis for cesanta/mongoose

## Attack Surface: [Path Traversal Vulnerabilities](./attack_surfaces/path_traversal_vulnerabilities.md)

*   **Description:** Attackers can access files and directories outside the intended web root by manipulating file paths in requests.
    *   **How Mongoose Contributes:** If Mongoose is configured to serve static files and doesn't properly sanitize the requested file paths, it can be tricked into serving files from arbitrary locations on the server's file system.
    *   **Example:** An attacker might send a request like `GET /../../../../etc/passwd HTTP/1.1` to access the system's password file.
    *   **Impact:** Exposure of sensitive files, including configuration files, source code, or even system credentials.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Disable directory listing in Mongoose configuration.
        *   Use Mongoose's configuration options to restrict the document root to the intended directory.
        *   Avoid relying on user-provided input directly in file paths. If necessary, implement strict input validation and sanitization.
        *   Consider using a reverse proxy to further restrict access to the file system.

## Attack Surface: [CGI/SSI Command Injection (if enabled)](./attack_surfaces/cgissi_command_injection__if_enabled_.md)

*   **Description:** If CGI or Server-Side Includes (SSI) are enabled, attackers can inject arbitrary commands to be executed on the server.
    *   **How Mongoose Contributes:** Mongoose provides support for CGI and SSI. If these features are enabled and the application doesn't properly sanitize input passed to CGI scripts or SSI directives, it becomes vulnerable to command injection.
    *   **Example:** An attacker could craft a URL that executes a system command through a vulnerable CGI script, like `http://example.com/cgi-bin/vulnerable.cgi?command=rm -rf /`.
    *   **Impact:** Full server compromise, data breach, malware installation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Disable CGI and SSI if not absolutely necessary.**
        *   If CGI/SSI is required, implement strict input validation and sanitization for all data passed to these mechanisms.
        *   Run CGI scripts with the least privileges necessary.
        *   Consider using more modern and secure alternatives to CGI/SSI.

## Attack Surface: [Lua Scripting Vulnerabilities (if enabled)](./attack_surfaces/lua_scripting_vulnerabilities__if_enabled_.md)

*   **Description:** If Lua scripting is enabled, vulnerabilities in the Lua engine or the application's use of Lua can be exploited.
    *   **How Mongoose Contributes:** Mongoose allows embedding Lua scripts for dynamic content generation or application logic. If this feature is enabled and the application allows external input to influence the Lua scripts being executed, attackers could inject malicious Lua code.
    *   **Example:** An attacker might inject Lua code that executes system commands or accesses sensitive data.
    *   **Impact:** Remote code execution, full server compromise, data breach.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Disable Lua scripting if not absolutely necessary.**
        *   If Lua scripting is required, avoid allowing external input to directly influence the Lua scripts.
        *   Implement a secure sandbox for Lua execution with limited access to system resources.
        *   Carefully review and audit all Lua scripts used in the application.

