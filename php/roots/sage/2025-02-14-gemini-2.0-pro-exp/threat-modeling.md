# Threat Model Analysis for roots/sage

## Threat: [Compromised NPM Dependency (Supply Chain Attack)](./threats/compromised_npm_dependency__supply_chain_attack_.md)

*   **Description:** An attacker compromises a package within Sage's `node_modules` dependency tree. The attacker publishes a malicious update. When developers update dependencies, the malicious code is pulled in and executed during the build, injecting malicious JavaScript or CSS into the final compiled assets *that are deployed to the live site*.
    *   **Impact:**
        *   **Critical:** Complete site compromise. The attacker could inject code to steal user data, redirect users, deface the website, or perform other malicious actions. The attacker gains control over the front-end, and potentially the back-end if the injected code interacts with WordPress APIs.
    *   **Sage Component Affected:** The entire build process (`webpack.config.js`, `package.json`, `yarn.lock`, and all compiled assets within `dist/`). The *deployed* assets on the live server.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Regular Dependency Audits:** Use `npm audit` or `yarn audit` (or tools like Snyk, Dependabot) to automatically scan for known vulnerabilities. Integrate this into the CI/CD pipeline.
        *   **Pin Dependency Versions:** Use a `package-lock.json` or `yarn.lock` file and *strictly* adhere to the locked versions. Avoid using version ranges (`^`, `~`).
        *   **Manual Review of Dependency Updates:** Before updating *any* dependency, carefully review the changelog and code changes for suspicious activity.
        *   **Use a Private NPM Registry (Optional):** For larger projects, consider a private registry to control and vet packages.
        *   **Consider alternative package managers:** Yarn is recommended by Sage, and generally considered more secure than older npm versions.

## Threat: [Exposure of Source Files and Configuration](./threats/exposure_of_source_files_and_configuration.md)

*   **Description:** An attacker gains direct access to the `resources/` directory (or its contents) due to misconfigured *production* server settings (e.g., missing or incorrect `.htaccess` rules, improper Nginx configuration). This exposes uncompiled source code (Sass, JavaScript), potentially revealing sensitive information.
    *   **Impact:**
        *   **High:** Information disclosure. Attackers could gain insights into the application's inner workings, potentially identifying vulnerabilities or sensitive data. This could lead to further attacks.
    *   **Sage Component Affected:** The `resources/` directory and its subdirectories (e.g., `resources/assets/`, `resources/views/`). *Production* web server configuration.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Web Server Configuration:** Ensure the *production* web server (Apache, Nginx) is configured to *deny* direct access to the `resources/` directory and all subdirectories.
        *   **.htaccess Verification (Apache):** If using Apache, thoroughly verify that the `.htaccess` file is present, correctly configured, and actively blocking access on the *production* server. Test this directly.
        *   **Nginx Configuration:** If using Nginx, use appropriate `location` blocks to deny access to the `resources/` directory on the *production* server.
        *   **Never Store Secrets in `resources/`:** Absolutely avoid storing any sensitive information within the `resources/` directory. Use environment variables or WordPress configuration files (`wp-config.php`) instead.

## Threat: [Over-Reliance on Client-Side Security (Bypassing Sage-Built Features)](./threats/over-reliance_on_client-side_security__bypassing_sage-built_features_.md)

*   **Description:** Developers implement security checks (e.g., role-based access control, hiding admin-only UI elements) *solely* using JavaScript within Sage's compiled assets. An attacker bypasses these checks by modifying the JavaScript in their browser or using developer tools, gaining unauthorized access to features or data managed by the Sage theme.
    *   **Impact:**
        *   **High:** Bypass of security controls. Attackers could gain unauthorized access to data or functionality *specifically managed by the Sage theme*, potentially leading to data breaches or other serious consequences. This is distinct from general WordPress security; it's about features *built into the theme* using Sage.
    *   **Sage Component Affected:** Compiled JavaScript assets (`dist/scripts/`) that implement front-end security logic, potentially interacting with WordPress APIs *through the theme*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Server-Side Validation is Mandatory:** *Always* perform security checks and data validation on the server-side (within WordPress controllers, functions, or custom API endpoints *called by the theme*). Client-side checks are for user experience, *not* security.
        *   **Principle of Least Privilege:** Enforce the principle of least privilege on the server-side. Users should only have access to what they need.
        *   **WordPress Capabilities (within Theme Logic):** Use WordPress's capability system (`current_user_can()`) *within the theme's PHP code* to control access to features and data.

