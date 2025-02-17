# Attack Surface Analysis for modernweb-dev/web

## Attack Surface: [1. Development Server Exposure](./attack_surfaces/1__development_server_exposure.md)

*   **Description:**  The `@web/dev-server` is unintentionally exposed to the public internet or an untrusted network.
*   **How `web` Contributes:** The dev server is designed for local development and lacks production-grade security hardening. Its primary purpose is rapid development, not secure deployment.  It provides the core functionality that is being exposed.
*   **Example:** A developer runs the dev server on `0.0.0.0` (binding to all interfaces) and forgets to configure a firewall, making the server accessible from the internet. An attacker scans for open ports and finds the dev server running.
*   **Impact:**
    *   Source code disclosure.
    *   Access to internal files and potentially sensitive data (e.g., API keys in `.env` files if exposed).
    *   Potential for Remote Code Execution (RCE) if a vulnerability exists in the dev server or its dependencies.
    *   Server-Side Request Forgery (SSRF) via misconfigured proxies.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Network Isolation:**  *Never* run the dev server on a public IP address or `0.0.0.0` without a properly configured firewall.  Use `localhost` or `127.0.0.1` to bind only to the local machine.
    *   **Firewall Configuration:**  Configure a firewall to block all incoming connections to the dev server's port from untrusted networks.
    *   **VPN/SSH Tunneling:**  If remote access to the dev server is needed, use a secure VPN or SSH tunnel.
    *   **Regular Audits:** Regularly check network configurations and running processes to ensure the dev server is not accidentally exposed.
    *   **Educate Developers:** Ensure all developers understand the risks of exposing the dev server and the proper configuration procedures.

## Attack Surface: [2. Misconfigured `web-dev-server.config.js`](./attack_surfaces/2__misconfigured__web-dev-server_config_js_.md)

*   **Description:**  Incorrect settings in the dev server configuration file expose sensitive information or allow unintended access.
*   **How `web` Contributes:** The configuration file *directly* controls the behavior of the `web-dev-server`, including file serving, proxying, and middleware.  This is a core component of the framework.
*   **Example:**
    *   `rootDir` is set to `/` (the root of the file system), exposing the entire file system.
    *   A proxy is configured to forward requests to an internal API without proper authentication or authorization, allowing an attacker to bypass security controls (SSRF).
    *   Custom middleware is added that contains a vulnerability (e.g., allows directory traversal).
*   **Impact:**
    *   Source code disclosure.
    *   Access to sensitive files.
    *   SSRF attacks.
    *   Potential for RCE if middleware is vulnerable.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Careful Review:**  Thoroughly review and understand *every* configuration option.  Don't blindly copy configurations from examples.
    *   **Least Privilege:**  Set `rootDir` to the most restrictive directory possible (e.g., the project's `src` directory).
    *   **Secure Proxy Configuration:**  Ensure proxies are configured with proper authentication, authorization, and input validation to prevent SSRF.
    *   **Middleware Auditing:**  Carefully audit any custom middleware for vulnerabilities.  Use established and well-vetted middleware whenever possible.
    *   **Input Validation:** Validate all user-provided input used in the configuration file (e.g., environment variables).
    *   **Configuration Management:** Use a secure configuration management system to store and manage sensitive configuration values.

## Attack Surface: [3. Dependency Vulnerabilities (Dev Server & Build Tools)](./attack_surfaces/3__dependency_vulnerabilities__dev_server_&_build_tools_.md)

*   **Description:**  Vulnerabilities in the dependencies of `@web/dev-server` or Rollup plugins provided by `@web/rollup-plugin-*`.
*   **How `web` Contributes:** The framework and its official plugins *directly* introduce these dependencies. This is inherent to using the framework and its tooling.
*   **Example:**  A dependency of `@web/dev-server` has a known RCE vulnerability. An attacker exploits this vulnerability to gain control of the dev server. Or, a `@web/rollup-plugin-*` plugin used for a specific task has a vulnerability that allows code injection during the build.
*   **Impact:**
    *   RCE on the dev server or build machine.
    *   Code injection into the built application.
    *   Data breaches.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Regular Updates:**  Keep all dependencies up-to-date using `npm update` or `yarn upgrade`.
    *   **Vulnerability Scanning:**  Use tools like `npm audit`, `yarn audit`, or Snyk to automatically scan for known vulnerabilities in dependencies.
    *   **Dependency Locking:**  Use `package-lock.json` or `yarn.lock` to ensure consistent and reproducible builds.
    *   **Vulnerability Monitoring:**  Subscribe to security advisories for the framework and its dependencies, *especially* the official `@web` packages.
    *   **Supply Chain Security:** Use a secure package registry and verify the integrity of downloaded packages, paying close attention to the `@web` namespace.

