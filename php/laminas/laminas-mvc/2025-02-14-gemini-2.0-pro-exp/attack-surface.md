# Attack Surface Analysis for laminas/laminas-mvc

## Attack Surface: [Route Parameter Manipulation](./attack_surfaces/route_parameter_manipulation.md)

**Description:** Attackers manipulating route parameters (defined within Laminas's routing configuration) to access unauthorized resources or inject malicious data. This is a *direct* consequence of how Laminas-MVC handles routing.

**How Laminas-MVC Contributes:** Laminas MVC's routing system heavily relies on parameters extracted from the URL.  The framework *provides* the mechanism for defining and extracting these parameters, making it a central point for this attack vector.  The vulnerability arises when these parameters are not *validated within the controller*.

**Example:** A route `/product/:id` where `:id` is directly used in a database query without sanitization: `/product/1;DROP TABLE products`. Or, `/download/:file` allowing directory traversal: `/download/../../etc/passwd` due to missing validation.

**Impact:** Information disclosure, data modification, potential for remote code execution (RCE) in extreme cases.

**Risk Severity:** Critical

**Mitigation Strategies:**

*   **Mandatory Input Validation:** *Always* validate and sanitize *all* route parameters within the controller action using `Laminas\InputFilter`. This is the primary defense.
*   **Parameterized Queries:** Use parameterized queries (prepared statements) for all database interactions, *never* concatenating user-supplied data.
*   **Whitelist Validation:** Use whitelisting to define *allowed* parameter values, rather than attempting to blacklist "bad" values.
*   **File Path Sanitization (if applicable):** If parameters are used in file system operations, rigorously sanitize them to prevent directory traversal. Use functions like `realpath()` and `basename()` and avoid direct user input in file paths.

## Attack Surface: [Insecure Service Configuration](./attack_surfaces/insecure_service_configuration.md)

**Description:** Misconfiguring services within the Laminas Service Manager, leading to insecure dependencies or exposed sensitive data. This is *directly* tied to Laminas-MVC's dependency injection system.

**How Laminas-MVC Contributes:** Laminas MVC *relies entirely* on the Service Manager for managing application components and dependencies.  The configuration of the Service Manager *is* the configuration of the application's core services.

**Example:** Storing database credentials in plain text within `config/autoload/local.php` (which might be accidentally committed to version control). Or, configuring a service to use an insecure connection (HTTP instead of HTTPS).

**Impact:** Information disclosure (e.g., database credentials), potential for man-in-the-middle attacks, compromise of dependent services.

**Risk Severity:** High

**Mitigation Strategies:**

*   **Secure Configuration Storage:** *Never* store sensitive data in configuration files checked into version control. Use environment variables or a dedicated secrets management solution.
*   **Configuration Auditing:** Regularly review and audit *all* Service Manager configurations.
*   **Principle of Least Privilege:** Configure services with the *minimum* necessary privileges.
*   **Secure Connections:** Enforce secure connections (HTTPS, TLS) for all inter-service communication.
*   **Factory Validation:** Use factories to create services, and within the factories, validate and sanitize configuration values and dependencies *before* using them.

## Attack Surface: [Missing or Weak Input Validation (Forms and InputFilters)](./attack_surfaces/missing_or_weak_input_validation__forms_and_inputfilters_.md)

**Description:** Failure to use or incorrect use of Laminas's `InputFilter` and form validation capabilities, leading to vulnerabilities like XSS and SQL injection.

**How Laminas-MVC Contributes:** While Laminas *provides* the `InputFilter` and form validation components, it's the developer's responsibility to *implement* them. The framework itself doesn't automatically enforce validation; it's a tool that must be used correctly. The close integration of forms and `InputFilter` with the MVC workflow makes this a Laminas-MVC specific concern.

**Example:** A form submission processed by a controller action that directly uses `$this->params()->fromPost('some_field')` without any validation, leading to SQL injection if `some_field` is used in a database query.

**Impact:** Allows various attacks, including XSS, SQL injection, and others, depending on how the unvalidated input is used.

**Risk Severity:** Critical

**Mitigation Strategies:**

*   **Universal Input Validation:** Use `Laminas\InputFilter` and form validation for *all* user-supplied data, without exception. This is a fundamental security requirement.
*   **Strict Validation Rules:** Define strict validation rules using `Laminas\Validator` classes.
*   **Whitelist Approach:** Prefer whitelisting allowed values over blacklisting.
*   **Context-Specific Validation:** Ensure validation rules are appropriate for the data type and context.
*   **Server-Side Validation:** *Always* perform validation on the server-side; client-side validation is easily bypassed.

