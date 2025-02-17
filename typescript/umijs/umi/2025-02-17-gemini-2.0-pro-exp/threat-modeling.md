# Threat Model Analysis for umijs/umi

## Threat: [Exposed API Keys/Secrets via Configuration (Umi)](./threats/exposed_api_keyssecrets_via_configuration__umi_.md)

*   **Description:**  An attacker gains access to sensitive API keys, database credentials, or other secrets that were accidentally committed to the source code repository, specifically within Umi's configuration files (`config/config.ts`, `.umirc.ts`) or due to improper handling of environment variables within the Umi build process.  The attacker leverages Umi's configuration loading mechanism to obtain these secrets.
*   **Impact:**
    *   Data breaches (accessing sensitive user data, internal systems).
    *   Financial loss (if the keys are associated with paid services).
    *   Reputational damage.
    *   Service disruption.
*   **Affected Component:** `config/config.ts`, `.umirc.ts`, Umi's build process (how it handles environment variables).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Never** commit secrets to the repository.
    *   Use environment variables (`.env` files) for all sensitive data, and ensure `.env` files are in `.gitignore`.  Umi has built-in support for `.env` files, use it correctly.
    *   Use a secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager) for production.
    *   Implement pre-commit hooks or CI/CD pipeline checks to scan for potential secrets.
    *   Regularly rotate API keys and secrets.

## Threat: [Server-Side Request Forgery (SSRF) via Misconfigured Proxy (Umi)](./threats/server-side_request_forgery__ssrf__via_misconfigured_proxy__umi_.md)

*   **Description:** An attacker exploits a misconfigured proxy setting within Umi's `config/config.ts` (`proxy` option).  The attacker crafts malicious requests that leverage Umi's built-in proxy functionality to make requests to internal services or external resources that should be inaccessible.  This is a *direct* consequence of Umi providing a built-in proxy feature.
*   **Impact:**
    *   Access to internal services and data.
    *   Bypass of firewall rules.
    *   Potential for remote code execution on internal systems.
    *   Data exfiltration.
*   **Affected Component:** `config/config.ts` (specifically the `proxy` configuration), Umi's internal proxy handling.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement a strict allow-list for proxy targets within the `proxy` configuration.  Only allow requests to specific, trusted hosts and ports.  *Do not* allow arbitrary user input to control the proxy destination.
    *   Validate and sanitize all user-supplied input that *indirectly* influences the proxy configuration (e.g., parameters that might be used to construct the target URL).
    *   Consider using a dedicated, hardened proxy server (e.g., Nginx, HAProxy) with robust security configurations instead of relying solely on Umi's built-in proxy for production.
    *   Monitor Umi's proxy logs (if available) and server logs for suspicious activity.

## Threat: [Dependency Vulnerabilities (Supply Chain Attack - Umi Ecosystem)](./threats/dependency_vulnerabilities__supply_chain_attack_-_umi_ecosystem_.md)

*   **Description:** An attacker compromises a third-party dependency *specifically within the Umi ecosystem* (e.g., a Umi plugin, a library commonly used with Umi, or Umi itself). The compromised dependency injects malicious code. This is a higher risk within the Umi ecosystem due to the reliance on plugins and the potential for less-vetted community contributions.
*   **Impact:**
    *   Complete application compromise.
    *   Data theft.
    *   Malware distribution to users.
    *   Remote code execution.
*   **Affected Component:** `package.json`, `pnpm-lock.yaml` / `yarn.lock`, any installed npm package, *especially* Umi plugins and Umi itself.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Regularly update Umi and all dependencies, including plugins. Use `pnpm up` / `yarn upgrade` and check for updates to Umi itself.
    *   Use dependency analysis tools (Snyk, Dependabot, npm audit, pnpm audit, yarn audit) to *automatically* scan for vulnerabilities in Umi, its plugins, and all other dependencies.
    *   *Thoroughly vet* any third-party Umi plugins before using them. Review the source code, check for known vulnerabilities, and consider the plugin's reputation and maintenance status.  Prioritize official Umi plugins.
    *   Use a Software Composition Analysis (SCA) tool.
    *   Consider using a private npm registry.
    *   Pin dependency versions (with caution, balancing security updates).

## Threat: [Cross-Site Scripting (XSS) via Umi Plugin (Umi-Specific)](./threats/cross-site_scripting__xss__via_umi_plugin__umi-specific_.md)

*   **Description:** An attacker injects malicious JavaScript code through a *vulnerable Umi plugin*. This is a *direct* threat because Umi's plugin architecture allows plugins to significantly interact with the rendering process and application logic.  A poorly written plugin that handles user input without proper sanitization or escaping can introduce XSS.
*   **Impact:**
    *   Session hijacking.
    *   Data theft (cookies, local storage).
    *   Defacement of the application.
    *   Phishing attacks.
*   **Affected Component:** Any Umi plugin that handles user input or dynamically renders content, *especially* plugins that modify the DOM or interact with Umi's rendering lifecycle.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   *Extremely carefully vet* all Umi plugins before using them.  Review the source code for potential XSS vulnerabilities.  Favor official plugins and those with a strong reputation.
    *   If developing custom plugins, implement robust input validation and output encoding (escaping) within the plugin. Use appropriate escaping functions for the context (HTML, JavaScript, etc.).
    *   Use a Content Security Policy (CSP) to restrict script sources.  Umi allows configuring headers, including CSP, via `config/config.ts`.
    *   Avoid using `dangerouslySetInnerHTML` within plugins unless absolutely necessary, and if used, ensure the input is *thoroughly* sanitized using a dedicated sanitization library.

## Threat: [Build Process Manipulation (Compromised CI/CD - Umi Build)](./threats/build_process_manipulation__compromised_cicd_-_umi_build_.md)

*   **Description:** An attacker gains access to the CI/CD pipeline and modifies the *Umi build process* to inject malicious code. This is relevant to Umi because the attacker would specifically target Umi's build scripts and configuration files (`config/config.ts`, etc.) to inject their payload.
*   **Impact:**
    *   Complete application compromise.
    *   Distribution of malicious code to users.
    *   Data theft.
*   **Affected Component:** The Umi build process, including Umi's build scripts, CI/CD configuration related to Umi, and the build server itself.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Secure the CI/CD pipeline with strong access controls, multi-factor authentication, and regular security audits.
    *   Use a trusted and isolated build environment.
    *   Implement code signing to verify the integrity of the built Umi application.
    *   Monitor build logs for suspicious activity, paying particular attention to modifications of Umi-related files.
    *   Use immutable build artifacts.

## Threat: [Disabled or Misconfigured Security Features (Umi-Specific)](./threats/disabled_or_misconfigured_security_features__umi-specific_.md)

* **Description:** Umi provides built-in security features (e.g., CSRF protection with the `request` plugin, headers configuration via `config/config.ts`). Disabling these Umi-provided features without proper understanding or alternative mitigations, or configuring them incorrectly within Umi's configuration, directly increases the application's vulnerability *due to the reliance on Umi's mechanisms*.
* **Impact:**
    * Increased risk of CSRF, XSS, and other common web vulnerabilities.
    * Exposure to attacks that Umi's built-in features are designed to prevent.
* **Affected Component:** `config/config.ts` (security-related settings), `umi/request` (CSRF protection), any component relying on Umi's security features.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Enable and properly configure Umi's built-in security features, especially CSRF protection if using `umi/request`.
    * Understand the implications of disabling any Umi-provided security-related setting.
    * If disabling a built-in Umi feature, implement *equivalent* protection using alternative methods, and document this clearly.
    * Regularly review Umi's security configurations in `config/config.ts`.

