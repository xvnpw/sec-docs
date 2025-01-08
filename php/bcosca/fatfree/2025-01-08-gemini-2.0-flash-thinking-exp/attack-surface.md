# Attack Surface Analysis for bcosca/fatfree

## Attack Surface: [Dynamic Route Parameter Injection](./attack_surfaces/dynamic_route_parameter_injection.md)

- **Description:** Attackers can manipulate URL parameters captured by FFF's routing mechanism to inject malicious code or data, leading to unintended actions.
    - **How Fat-Free Contributes:** FFF's flexible routing allows defining routes with dynamic parameters (e.g., `/user/@id`). If these parameters are directly used in database queries, file system operations, or other sensitive contexts without proper sanitization, it creates an injection point.
    - **Example:** A route `/view/@file` could be exploited by accessing `/view/../../etc/passwd` if the `@file` parameter is used directly to read a file. Similarly, `/users/edit/@id` could be vulnerable to SQL injection if `@id` is used unsanitized in a database query.
    - **Impact:**  SQL Injection (data breach, modification, deletion), Local File Inclusion (LFI), Remote Code Execution (RCE) depending on the context.
    - **Risk Severity:** Critical
    - **Mitigation Strategies:**
        - **Input Validation:**  Thoroughly validate all route parameters against expected formats and values.
        - **Parameterized Queries:** Use parameterized queries or prepared statements when interacting with databases to prevent SQL injection.
        - **Path Sanitization:** When dealing with file paths, use functions to sanitize and normalize paths to prevent directory traversal.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

- **Description:** Attackers can manipulate request data (e.g., POST parameters) to set object properties they shouldn't have access to, potentially leading to privilege escalation or data manipulation.
    - **How Fat-Free Contributes:** FFF's data binding features (e.g., using `$f3->copyFrom('POST')` to populate objects) can automatically assign values from request data to object properties. If not carefully controlled, this can lead to unintended modifications.
    - **Example:** An application has a `User` model with an `isAdmin` property. If the form submission directly maps to the `User` object without explicit filtering, an attacker could send `isAdmin=1` in the POST request to elevate their privileges.
    - **Impact:** Privilege escalation, data modification, bypassing security checks.
    - **Risk Severity:** High
    - **Mitigation Strategies:**
        - **Explicitly Define Allowed Fields:** Use whitelisting to specify which fields can be populated from request data.
        - **Data Transfer Objects (DTOs):** Use DTOs to map request data to specific objects, preventing direct assignment to sensitive model properties.

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

- **Description:** Attackers can inject malicious code into templates if user-controlled data is directly embedded without proper escaping, leading to code execution on the server.
    - **How Fat-Free Contributes:** If developers directly embed user input into template variables without proper escaping using FFF's templating engine (or a third-party one), it can create an SSTI vulnerability.
    - **Example:** A template might use `{{ @user_input }}` to display user input. If `@user_input` contains malicious code like `{{ system('rm -rf /') }}`, it could be executed on the server.
    - **Impact:** Remote Code Execution (RCE), information disclosure, denial of service.
    - **Risk Severity:** Critical
    - **Mitigation Strategies:**
        - **Proper Output Escaping:** Always escape user-provided data before rendering it in templates. Use FFF's built-in escaping mechanisms or the escaping functions provided by the templating engine.
        - **Avoid Raw Output:**  Minimize the use of raw output or unescaped variables in templates, especially for user-controlled data.

