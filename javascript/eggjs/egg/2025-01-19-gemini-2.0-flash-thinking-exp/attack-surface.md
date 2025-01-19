# Attack Surface Analysis for eggjs/egg

## Attack Surface: [Route Parameter Injection](./attack_surfaces/route_parameter_injection.md)

*   **Description:** Attackers manipulate route parameters to inject malicious data, leading to unintended actions or information disclosure.
    *   **How Egg Contributes:** Egg's routing mechanism directly maps URL parameters to controller arguments, making it easy for developers to directly use these parameters without proper sanitization.
    *   **Example:** A route `/users/:id` where the `id` parameter is directly used in a database query like `db.query('SELECT * FROM users WHERE id = ' + ctx.params.id)`. An attacker could send `/users/' OR '1'='1'` to potentially bypass authentication or retrieve all user data.
    *   **Impact:** Data breaches, unauthorized access, potential for command injection if parameters are used in system calls.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Validation:** Implement robust input validation and sanitization within controllers before using route parameters.
        *   **Parameterized Queries/ORMs:** Use parameterized queries or ORMs that automatically handle escaping to prevent SQL/NoSQL injection.
        *   **Type Casting:**  Cast route parameters to the expected data type to prevent unexpected input.

## Attack Surface: [Vulnerabilities in Custom Middleware](./attack_surfaces/vulnerabilities_in_custom_middleware.md)

*   **Description:** Security flaws in custom middleware can introduce vulnerabilities affecting the entire application.
    *   **How Egg Contributes:** Egg's middleware system allows developers to inject custom logic into the request processing pipeline. Poorly written middleware can introduce vulnerabilities.
    *   **Example:** A custom authentication middleware that incorrectly verifies user credentials or is susceptible to timing attacks.
    *   **Impact:** Authentication bypass, authorization failures, information disclosure, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Secure Coding Practices:** Follow secure coding principles when developing custom middleware.
        *   **Thorough Testing:**  Implement comprehensive unit and integration tests for custom middleware, including security-focused tests.
        *   **Code Reviews:** Conduct peer reviews of custom middleware code to identify potential vulnerabilities.
        *   **Leverage Existing Middleware:** Utilize well-established and vetted middleware packages where possible instead of writing custom solutions from scratch.

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:** Attackers inject malicious code into templates, which is then executed on the server.
    *   **How Egg Contributes:** If user-provided data is directly embedded into templates without proper escaping within Egg's templating engine (e.g., Nunjucks), it can lead to SSTI.
    *   **Example:**  A view rendering user input directly like `<h1>{{ user.name }}</h1>` where `user.name` comes directly from user input without sanitization. An attacker could input `{{ _global.process.mainModule.require('child_process').execSync('whoami').toString() }}` to execute commands on the server.
    *   **Impact:** Remote code execution, full server compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid Direct User Input in Templates:**  Minimize the use of raw user input directly within templates.
        *   **Proper Escaping:**  Ensure all user-provided data is properly escaped by the templating engine to prevent code execution.
        *   **Use Secure Templating Practices:** Follow the security guidelines for the specific templating engine being used.

