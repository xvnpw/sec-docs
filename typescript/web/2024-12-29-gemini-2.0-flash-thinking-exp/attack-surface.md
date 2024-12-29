* **Server-Side Template Injection (SSTI)**
    * **Description:** Attackers inject malicious code into template expressions, which is then executed on the server.
    * **How Web Contributes:** If the framework's templating engine doesn't automatically escape user-provided data within template expressions, or if it allows for the execution of arbitrary code within templates, it creates this vulnerability.
    * **Example:** An attacker crafts a URL parameter like `name={{ system('whoami') }}` which, if directly rendered in a template without proper escaping, could execute the `whoami` command on the server.
    * **Impact:** Full server compromise, remote code execution, data exfiltration.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * Utilize the framework's built-in mechanisms for escaping user-provided data in templates.
        * Avoid directly embedding user input into template expressions.
        * Employ a templating engine that automatically escapes by default or has strong sandboxing capabilities.
        * Implement Content Security Policy (CSP) to restrict the sources from which the browser can load resources.

* **Insecure Route Handling**
    * **Description:** Vulnerabilities arising from how the framework defines and handles routes.
    * **How Web Contributes:** If the framework allows for overly flexible or dynamic route definitions without proper validation, or if it has default routes that are insecure, it increases the attack surface.
    * **Example:** A framework might allow routes like `/users/{id}` where `id` is not properly validated, allowing an attacker to try accessing `/users/../admin` if the underlying file system is accessible. Or, a default debug route like `/debug/info` might expose sensitive information if not disabled in production.
    * **Impact:** Unauthorized access to resources, information disclosure, potential for path traversal vulnerabilities.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Implement strict route validation and sanitization.
        * Avoid overly permissive or dynamic route definitions where possible.
        * Ensure all default or example routes are removed or secured in production.
        * Implement proper authorization checks on all routes to restrict access based on user roles.

* **Middleware Vulnerabilities**
    * **Description:** Security flaws within the framework's middleware components or how middleware is managed.
    * **How Web Contributes:** If the framework includes insecure default middleware, allows for the injection of malicious middleware, or doesn't enforce a secure order of middleware execution, it can introduce vulnerabilities.
    * **Example:** A default logging middleware might inadvertently log sensitive user data in plain text. Or, an attacker might be able to inject a malicious middleware that intercepts requests and steals credentials if the framework doesn't have proper safeguards.
    * **Impact:** Data leakage, unauthorized access, manipulation of requests and responses.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Carefully review and configure default middleware components.
        * Implement strict controls over adding or modifying middleware.
        * Ensure a well-defined and secure order of middleware execution.
        * Regularly update middleware dependencies to patch known vulnerabilities.