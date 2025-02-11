# Attack Surface Analysis for kataras/iris

## Attack Surface: [Route Parameter Injection](./attack_surfaces/route_parameter_injection.md)

*   **Description:**  Attackers manipulate route parameters (e.g., `/users/:id`) to inject malicious code or commands.
*   **How Iris Contributes:** Iris's flexible routing system with dynamic parameters (`:param`, `*param`) increases the potential for developer error if parameters are not rigorously validated and sanitized.  The framework *provides* the tools for safe handling (e.g., `ParamInt`, `ParamString`), but doesn't enforce their use, making this a direct Iris-related concern.
*   **Example:**
    *   **Attack:**  `/users/../../../etc/passwd` (Path Traversal, if the parameter is used to construct a file path).
    *   **Attack:** `/products/';DROP TABLE products;--` (SQL Injection, if the parameter is used directly in a query).
*   **Impact:**  Data breaches, unauthorized access, system compromise, data modification/deletion.
*   **Risk Severity:**  High to Critical (depending on how the parameter is used).
*   **Mitigation Strategies:**
    *   **Developer:** *Must* use Iris's built-in parameter validation functions: `ParamInt()`, `ParamFloat64()`, `ParamString()`, etc.  Implement custom validators when necessary.  *Always* sanitize and escape parameter values before using them in *any* sensitive context (database queries, file system operations, etc.).  Use parameterized queries/prepared statements for database interactions. Never construct file paths directly from user input.

## Attack Surface: [Overly Permissive Routing (Wildcards/Catch-Alls)](./attack_surfaces/overly_permissive_routing__wildcardscatch-alls_.md)

*   **Description:**  Using overly broad wildcard routes (`*`, `/*`) or catch-all routes without proper access controls exposes internal functionality or files unintentionally.
*   **How Iris Contributes:** Iris *directly* supports wildcard and catch-all routes, providing flexibility but also creating the risk of misconfiguration. This is a feature of the framework that must be used with extreme caution.
*   **Example:**
    *   **Attack:**  A route defined as `/admin/*` without proper authentication middleware allows an attacker to access `/admin/internal-api` or `/admin/sensitive-data.txt`.
*   **Impact:**  Information disclosure, unauthorized access to administrative interfaces or sensitive data.
*   **Risk Severity:**  High.
*   **Mitigation Strategies:**
    *   **Developer:** Avoid wildcard and catch-all routes whenever possible.  If necessary, use them *very* sparingly.  Implement robust middleware *before* the wildcard handler to enforce authentication, authorization, and input validation.  Ensure that sensitive files and directories are *not* accessible through these routes. Explicitly define routes for known, safe endpoints.

## Attack Surface: [Middleware Bypass/Misconfiguration](./attack_surfaces/middleware_bypassmisconfiguration.md)

*   **Description:**  Incorrect ordering or configuration of middleware allows attackers to bypass security controls (authentication, authorization, input validation).
*   **How Iris Contributes:** Iris's middleware system is a *core feature* of the framework.  Its flexibility and power, while beneficial, directly create the risk of misconfiguration leading to security vulnerabilities. The framework relies on the developer to correctly configure the middleware chain.
*   **Example:**
    *   **Attack:**  If authentication middleware is placed *after* middleware that logs request data, an attacker could bypass authentication and still have their (potentially malicious) request logged.
*   **Impact:**  Authentication bypass, authorization bypass, execution of malicious code, data breaches.
*   **Risk Severity:**  High to Critical.
*   **Mitigation Strategies:**
    *   **Developer:**  Carefully plan and implement the order of middleware.  Security-critical middleware (authentication, authorization, input validation) *must* be placed before any middleware or handlers that access sensitive data or perform privileged operations.  Thoroughly test all middleware configurations with various attack scenarios.  Use a consistent and well-documented middleware ordering strategy.

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:** Attackers inject malicious code into server-side templates, potentially leading to remote code execution.
*   **How Iris Contributes:** Iris *directly* supports multiple template engines. While the vulnerability itself stems from improper template usage, Iris's built-in support for templating makes this a relevant and Iris-related attack surface. The choice of template engine and its configuration is facilitated by Iris.
*   **Example:**
    *   **Attack:** If a user-provided name is rendered directly into a template without escaping: `<h1>Hello, {{.Name}}</h1>`, and the user inputs `{{.System "ls -l"}}`, the server might execute the `ls -l` command (depending on the template engine).
*   **Impact:** Remote Code Execution (RCE), complete system compromise.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Developer:** *Always* use the appropriate escaping functions provided by the chosen template engine (e.g., `{{ .Name | html }}` in Go's `html/template`). Never pass raw user input directly to templates. Consider using a template engine with built-in auto-escaping features. Understand the security implications of the chosen template engine (which Iris allows you to select).

## Attack Surface: [Unvalidated File Uploads](./attack_surfaces/unvalidated_file_uploads.md)

*   **Description:** Attackers upload malicious files (e.g., web shells) that can be executed on the server.
*   **How Iris Contributes:** Iris *directly* provides functionality for handling file uploads through its `Context.UploadFormFiles` and related methods. The security of this functionality is entirely dependent on the developer's implementation, but the *presence* of the file upload feature within Iris makes it a relevant attack surface.
*   **Example:**
    *   **Attack:** An attacker uploads a PHP file (e.g., `shell.php`) containing malicious code. If the server is configured to execute PHP files, and Iris is used to handle the upload without proper validation, the attacker can then access the file and execute arbitrary code.
*   **Impact:** Remote Code Execution (RCE), complete system compromise.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Strictly validate file types:** Use a whitelist of allowed file extensions and MIME types. Do *not* rely solely on the file extension provided by the client. Use Iris's context methods to access file metadata for validation.
        *   **Validate file sizes:** Enforce maximum file size limits.
        *   **Store uploaded files outside the web root:** This prevents direct access via the web server.
        *   **Rename uploaded files:** Use a secure random number generator to create unique filenames.
        *   **Scan uploaded files for malware:** Integrate with a virus scanner.
        *   **Do not execute uploaded files:** Configure the web server to *not* execute files in the upload directory.

