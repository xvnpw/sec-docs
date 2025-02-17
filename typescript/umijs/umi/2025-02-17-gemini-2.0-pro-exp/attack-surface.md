# Attack Surface Analysis for umijs/umi

## Attack Surface: [Accidental Route Exposure](./attack_surfaces/accidental_route_exposure.md)

*   **Description:** Sensitive files or internal APIs are unintentionally exposed as publicly accessible routes.
    *   **How Umi Contributes:** Umi's convention-based routing (files in `src/pages` become routes) makes it easy to accidentally expose files if developers aren't careful with naming and directory structure. This is a *direct* consequence of Umi's design.
    *   **Example:** A developer places a file named `admin.js` in `src/pages` containing administrative functionality without proper authentication. An attacker discovers `/admin` and gains unauthorized access.
    *   **Impact:** Unauthorized access to sensitive data or functionality, potential for privilege escalation.
    *   **Risk Severity:** High to Critical (depending on the exposed functionality).
    *   **Mitigation Strategies:**
        *   Use the `_` prefix for files in `src/pages` that should *not* be routes (e.g., `_components`, `_utils`).
        *   Implement robust server-side authentication and authorization checks for *all* routes. Do not rely on routing conventions.
        *   Use Umi's `routes` configuration in `config/config.ts` for explicit route definitions and access control.
        *   Regularly review the generated route configuration.

## Attack Surface: [Dynamic Route Parameter Injection](./attack_surfaces/dynamic_route_parameter_injection.md)

*   **Description:** Attackers inject malicious input into dynamic route parameters (e.g., `/users/:id`) to exploit vulnerabilities.
    *   **How Umi Contributes:** Umi *directly* supports dynamic route parameters, creating the potential for injection attacks if parameters are not handled securely on the backend. While the vulnerability itself is backend-focused, Umi's routing mechanism is the entry point.
    *   **Example:** An attacker uses `../` in a route parameter like `/products/../../etc/passwd` to attempt a path traversal attack. Or, injects a NoSQL query into a parameter like `/users/{$gt: ''}`.
    *   **Impact:** Path traversal, NoSQL/SQL injection, XSS, data leakage, denial of service.
    *   **Risk Severity:** High to Critical (depending on the backend systems and data accessed).
    *   **Mitigation Strategies:**
        *   **Strictly validate and sanitize all dynamic route parameters.** Use whitelists and type checking.
        *   Use parameterized queries or an ORM when interacting with databases.
        *   Employ output encoding to prevent XSS.

## Attack Surface: [Vulnerable Umi Plugins](./attack_surfaces/vulnerable_umi_plugins.md)

*   **Description:** Using outdated or insecure third-party Umi plugins introduces vulnerabilities.
    *   **How Umi Contributes:** Umi's plugin architecture is a *core feature* that allows for extensibility, but this *directly* introduces the risk of using vulnerable code from third parties.
    *   **Example:** A plugin for handling file uploads has a known vulnerability that allows arbitrary file uploads. An attacker exploits this to upload a malicious script.
    *   **Impact:** Wide range of impacts, depending on the plugin's functionality. Could include code execution, data breaches, denial of service.
    *   **Risk Severity:** Medium to Critical (depending on the plugin and vulnerability, but we're filtering for High/Critical here).
    *   **Mitigation Strategies:**
        *   Thoroughly vet all third-party plugins before use.
        *   Keep all plugins updated to their latest versions.
        *   Use dependency vulnerability scanners.
        *   Consider forking and maintaining critical plugins internally.

## Attack Surface: [Development Mode Exposure in Production](./attack_surfaces/development_mode_exposure_in_production.md)

*   **Description:** Deploying the application in development mode exposes debugging information and unminified code.
    *   **How Umi Contributes:** Umi has distinct development and production build modes, and the framework is *directly* responsible for handling the differences between these modes. Misconfiguration here is a Umi-specific issue.
    *   **Example:** Source maps are exposed, allowing attackers to easily view the application's source code.
    *   **Impact:** Easier vulnerability discovery, information disclosure, potential for reverse engineering.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   Always build the application in production mode (`NODE_ENV=production`) before deployment.
        *   Automate the build and deployment process.
        *   Use environment variables to control build settings.

## Attack Surface: [Sensitive Data in Configuration](./attack_surfaces/sensitive_data_in_configuration.md)

*   **Description:** Storing secrets (API keys, database credentials) directly in Umi's configuration files.
    *   **How Umi Contributes:** Umi *directly* uses configuration files (`config/config.ts`, `.umirc.ts`), and the framework's documentation and structure might lead developers to incorrectly store secrets there. This is a common misconfiguration pattern *specific* to how Umi is used.
    *   **Example:** An API key is hardcoded in `config/config.ts`, and the repository is compromised.
    *   **Impact:** Compromise of connected services, data breaches.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Never store secrets directly in configuration files.**
        *   Use environment variables.
        *   Use a secrets management solution.
        *   Ensure `.env` files are in `.gitignore`.

## Attack Surface: [`public` Directory Misuse](./attack_surfaces/_public__directory_misuse.md)

*   **Description:** Placing sensitive files in the `public` directory, making them directly accessible.
    *   **How Umi Contributes:** Umi *directly* defines and uses the `public` directory for serving static assets without processing. Misunderstanding this feature is a Umi-specific risk.
    *   **Example:** A developer accidentally places a database backup file (`backup.sql`) in the `public` directory.
    *   **Impact:** Data leakage, potential for unauthorized access.
    *   **Risk Severity:** High to Critical (depending on the exposed data).
    *   **Mitigation Strategies:**
        *   Only place static assets intended for public access in the `public` directory.
        *   Regularly review the contents of the `public` directory.

