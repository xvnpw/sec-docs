*   **Attack Surface:** Regular Expression Denial of Service (ReDoS) in Route Handlers
    *   **Description:** Attackers craft malicious URLs that cause the regular expressions used in Tornado's routing to consume excessive CPU time, leading to a denial of service.
    *   **How Tornado Contributes:** Tornado's routing mechanism relies on regular expressions to match incoming URLs to the appropriate handlers. Complex or poorly written regex patterns are susceptible to ReDoS.
    *   **Example:** A route defined as `r"/items/([a-z]+)+"` could be vulnerable. An attacker could send a request like `/items/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!` which would cause the regex engine to backtrack excessively.
    *   **Impact:** High - Can lead to server unresponsiveness and denial of service, impacting availability.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Carefully design regular expressions used in routing, avoiding nested quantifiers and overlapping patterns.
        *   Implement timeouts for regular expression matching to prevent excessive processing time.
        *   Consider alternative routing mechanisms if regular expressions become too complex or a frequent source of vulnerabilities.

*   **Attack Surface:** Path Traversal via Route Parameters
    *   **Description:** If route parameters are used to access files or resources without proper sanitization, attackers can manipulate these parameters to access files outside the intended directories.
    *   **How Tornado Contributes:** Tornado allows capturing parts of the URL as parameters, which can be directly used in file system operations if not handled securely.
    *   **Example:** A route like `r"/download/(.*)"` where the captured parameter is directly used in `open(filepath)` without validation. An attacker could request `/download/../../../../etc/passwd`.
    *   **Impact:** High - Can lead to unauthorized access to sensitive files and information disclosure.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Thoroughly validate and sanitize all route parameters before using them to access files or resources.
        *   Use safe file path manipulation functions that prevent traversal (e.g., `os.path.join` and checking if the resolved path is within the allowed directory).
        *   Avoid directly using user-provided input in file paths.

*   **Attack Surface:** Server-Side Template Injection (SSTI)
    *   **Description:** If user-controlled data is directly embedded into Tornado templates without proper escaping or sanitization, attackers can inject malicious code that is executed on the server.
    *   **How Tornado Contributes:** Tornado integrates with various template engines (like Jinja2 or its own built-in engine). If not used carefully, these engines can execute arbitrary code.
    *   **Example:** Using Jinja2, if a template renders `{{ user_input }}` and `user_input` is attacker-controlled and contains `{{ ''.__class__.__mro__[2].__subclasses__()[406]('ls -la', shell=True, stdout=-1).communicate()[0].strip() }}`, it could execute system commands.
    *   **Impact:** Critical - Can lead to remote code execution, allowing attackers to completely compromise the server.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Always escape user-provided data when rendering it in templates. Use the template engine's built-in escaping mechanisms.
        *   Avoid allowing users to directly control template code or syntax.
        *   Consider using a template engine with strong sandboxing capabilities if user-provided content needs to be rendered.

*   **Attack Surface:** Resource Exhaustion due to Unbounded Asynchronous Tasks
    *   **Description:** If the application spawns an unlimited number of asynchronous tasks in response to requests, it could lead to resource exhaustion and denial of service.
    *   **How Tornado Contributes:** Tornado's asynchronous nature makes it easy to spawn many concurrent tasks, but without proper management, this can be abused.
    *   **Example:** An endpoint triggers an asynchronous task for each incoming request without any limits. An attacker sends a large number of requests, causing the server to create an excessive number of tasks, consuming memory and CPU.
    *   **Impact:** High - Can lead to server unresponsiveness and denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement rate limiting on endpoints that trigger asynchronous tasks.
        *   Use task queues with limited capacity to manage the number of concurrent tasks.
        *   Monitor resource usage and implement mechanisms to prevent runaway task creation.