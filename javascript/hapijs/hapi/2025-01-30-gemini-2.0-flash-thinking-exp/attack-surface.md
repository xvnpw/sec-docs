# Attack Surface Analysis for hapijs/hapi

## Attack Surface: [Route Parameter Injection](./attack_surfaces/route_parameter_injection.md)

**Description:** Exploiting vulnerabilities by injecting malicious payloads into route parameters defined within Hapi routes, where these parameters are not properly validated or sanitized before use in application logic.
**Hapi Contribution:** Hapi's core routing mechanism allows defining routes with dynamic parameters (e.g., `/users/{id}`). This feature directly introduces the risk if developers fail to implement proper input handling for these parameters.
**Example:** A Hapi route defined as `/articles/{articleId}`. If `articleId` is directly used in a database query to fetch article content without validation, an attacker could inject SQL code within `articleId` to perform unauthorized database operations (SQL Injection).
**Impact:** Critical. Successful exploitation can lead to severe consequences including data breaches, unauthorized data modification, complete system compromise, and potentially remote code execution.
**Risk Severity:** Critical
**Mitigation Strategies:**
*   **Mandatory Input Validation with Joi:** Leverage Hapi's integration with Joi to enforce strict validation rules for all route parameters. Define schemas that specify allowed data types, formats, and constraints.
*   **Parameter Sanitization and Escaping:** Sanitize and escape route parameter values before using them in any backend operations, especially when constructing database queries, file system paths, or commands.
*   **Prepared Statements/Parameterized Queries:** When interacting with databases, utilize prepared statements or parameterized queries to prevent SQL injection by separating SQL code from user-supplied data.
*   **Principle of Least Privilege:** Ensure backend components that process route parameters operate with the minimum necessary privileges to limit the impact of potential injection attacks.

## Attack Surface: [Route Exposure and Information Disclosure](./attack_surfaces/route_exposure_and_information_disclosure.md)

**Description:** Unintentionally exposing sensitive or administrative routes due to misconfiguration or overly permissive route definitions within the Hapi application.
**Hapi Contribution:** Hapi's flexible routing system allows developers to define any route.  The framework itself doesn't inherently restrict route access, making it easy to inadvertently expose internal or sensitive endpoints if route definitions are not carefully managed.
**Example:**  Accidentally deploying a Hapi application with development routes like `/debug/admin` or `/internal/metrics` still active in production. Attackers could discover and access these routes to gain unauthorized insights into application internals, configuration, or even administrative functionalities.
**Impact:** High. Exposure of sensitive routes can lead to information disclosure about the application's architecture, internal workings, and potentially sensitive data. It can also provide attackers with access to administrative functionalities, enabling further compromise.
**Risk Severity:** High
**Mitigation Strategies:**
*   **Strict Route Definition Review:**  Thoroughly review all defined Hapi routes before deployment, ensuring only necessary and public-facing routes are exposed in production environments. Remove or restrict access to development, debugging, or internal routes.
*   **Environment-Specific Route Configuration:** Utilize environment variables or configuration files to manage route definitions.  Disable or restrict access to sensitive routes specifically in production environments.
*   **Authentication and Authorization for Sensitive Routes:** Implement robust authentication and authorization mechanisms for all routes that handle sensitive data or functionalities. Use Hapi authentication strategies and plugins to control access based on user roles and permissions.
*   **Regular Route Audits:** Periodically audit the application's route configuration to identify and remediate any unintentionally exposed or overly permissive routes.

