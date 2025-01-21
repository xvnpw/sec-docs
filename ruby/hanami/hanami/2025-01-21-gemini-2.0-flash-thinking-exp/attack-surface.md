# Attack Surface Analysis for hanami/hanami

## Attack Surface: [Route Constraint Bypass and Parameter Manipulation](./attack_surfaces/route_constraint_bypass_and_parameter_manipulation.md)

*   **Description:** Attackers can craft malicious URLs to bypass intended route constraints or manipulate parameters in unexpected ways, potentially accessing unauthorized actions or data.
    *   **How Hanami Contributes:** Hanami's routing system relies on developers defining constraints. If these constraints are too permissive, poorly defined, or if parameter handling within actions doesn't account for unexpected input, vulnerabilities can arise. The framework's parameter access methods (`params`) can directly expose unfiltered input.
    *   **Example:** A route is defined as `/users/:id(\d+)`, intending to only accept numeric IDs. However, if the action doesn't validate the `id` further, an attacker might try `/users/abc` or `/users/1; DELETE FROM users;` hoping to exploit weaknesses in the underlying data layer or application logic.
    *   **Impact:** Unauthorized access to resources, data manipulation, potential for code injection depending on how parameters are used within actions.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Define strict and specific route constraints:** Use regular expressions or custom constraint logic to precisely match expected parameter formats.
        *   **Implement robust input validation within actions:**  Use Hanami's validation features or custom validation logic to sanitize and verify all incoming parameters before using them.
        *   **Avoid direct use of raw parameters without validation:**  Always validate and sanitize `params` before using them in business logic or database queries.
        *   **Consider using parameter coercion:** Hanami's coercion can help ensure parameters are of the expected type, but it's not a substitute for validation.

## Attack Surface: [Unvalidated Action Parameters Leading to Injection Attacks](./attack_surfaces/unvalidated_action_parameters_leading_to_injection_attacks.md)

*   **Description:**  Actions directly use request parameters without proper sanitization or validation, leading to vulnerabilities like Cross-Site Scripting (XSS), SQL Injection (if parameters are used in database queries), or Command Injection.
    *   **How Hanami Contributes:** Hanami provides easy access to request parameters through the `params` object within actions. If developers directly use these parameters in views or database queries without sanitization, it creates an opening for injection attacks.
    *   **Example:** An action renders a view using `<h1>Hello, <%= params[:name] %></h1>`. An attacker could send a request with `?name=<script>alert('XSS')</script>`, leading to the execution of malicious JavaScript in the user's browser. Similarly, if `params[:search]` is directly used in a database query without proper escaping, it could lead to SQL injection.
    *   **Impact:** XSS can lead to session hijacking, data theft, and defacement. SQL Injection can result in data breaches, data manipulation, and even complete database takeover. Command Injection can allow attackers to execute arbitrary commands on the server.
    *   **Risk Severity:** Critical (for SQL and Command Injection), High (for XSS)
    *   **Mitigation Strategies:**
        *   **Always sanitize user input before rendering in views:** Utilize Hanami's built-in escaping mechanisms or use a dedicated sanitization library.
        *   **Use parameterized queries or ORM features for database interactions:** Avoid constructing SQL queries using string concatenation with user-provided input. Hanami's repositories encourage safe data access.
        *   **Avoid executing system commands based on user input:** If necessary, implement strict validation and sanitization, and use secure alternatives where possible.
        *   **Implement Content Security Policy (CSP):**  Helps mitigate XSS attacks by controlling the resources the browser is allowed to load.

## Attack Surface: [Template Injection Vulnerabilities](./attack_surfaces/template_injection_vulnerabilities.md)

*   **Description:** Attackers can inject malicious code into templates if user-provided data is directly used within template rendering logic without proper escaping or if the template engine itself has vulnerabilities.
    *   **How Hanami Contributes:** Hanami uses template engines (like ERB or Haml). If developers directly embed user input into templates without proper escaping, or if custom template helpers are not carefully written, it can lead to template injection.
    *   **Example:** A view uses a helper like `<%= unsafe_render(params[:content]) %>` where `unsafe_render` directly outputs the content without escaping. An attacker could provide malicious code in the `content` parameter that gets executed on the server or in the user's browser.
    *   **Impact:** Server-side template injection can lead to remote code execution. Client-side template injection (through XSS) can lead to session hijacking and data theft.
    *   **Risk Severity:** Critical (for server-side), High (for client-side)
    *   **Mitigation Strategies:**
        *   **Always escape user-provided data when rendering in templates:** Use Hanami's default escaping mechanisms or explicitly escape data.
        *   **Avoid creating custom template helpers that directly render unescaped user input.**
        *   **Keep the template engine updated:** Ensure you are using the latest version of the template engine to patch known vulnerabilities.
        *   **Consider using a template engine with strong security features:** Some template engines offer more robust security features than others.

## Attack Surface: [Insecure Handling of Configuration and Secrets](./attack_surfaces/insecure_handling_of_configuration_and_secrets.md)

*   **Description:** Sensitive information like API keys, database credentials, or encryption keys are stored insecurely, making them accessible to attackers.
    *   **How Hanami Contributes:** Hanami provides mechanisms for configuration management. If developers store sensitive information directly in configuration files, environment variables without proper protection, or commit them to version control, it creates a vulnerability.
    *   **Example:** Database credentials stored directly in `config/database.yml` or API keys hardcoded in application code. If these files are compromised or exposed, attackers gain access to critical resources.
    *   **Impact:** Complete compromise of the application and associated resources.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Use secure environment variable management:** Utilize tools like `dotenv` or platform-specific secret management services.
        *   **Avoid committing sensitive information to version control:** Use `.gitignore` to exclude sensitive files and consider using tools like `git-secrets`.
        *   **Encrypt sensitive data at rest:** If storing sensitive data in configuration files, encrypt it.
        *   **Restrict access to configuration files and environment variables.**
        *   **Regularly rotate sensitive credentials.**

