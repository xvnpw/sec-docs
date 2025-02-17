# Threat Model Analysis for nathanwalker/angular-seed-advanced

## Threat: [Dependency Spoofing (Typosquatting/Compromised Registry)](./threats/dependency_spoofing__typosquattingcompromised_registry_.md)

*   **Threat:** Dependency Spoofing (Typosquatting/Compromised Registry)

    *   **Description:** An attacker publishes a malicious npm package with a name very similar to a legitimate dependency used by `angular-seed-advanced` (e.g., `anguler-core` instead of `angular-core`). The attacker may also compromise the npm registry or a developer's machine to redirect dependency requests. The goal is to execute malicious code as part of the application's build or runtime. This is particularly dangerous because `angular-seed-advanced` relies on a complex dependency tree.
    *   **Impact:** Complete application compromise. The attacker's code could steal data, modify behavior, install backdoors, or perform any action with the application's privileges. This is a build-time compromise, making it more severe than many runtime attacks.
    *   **Affected Component:** `package.json`, `package-lock.json`, `yarn.lock`, npm/yarn client, build process (Webpack, Angular CLI).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:** Use a private npm registry or a proxy that verifies package integrity (checksums).
        *   **Developer:** Regularly audit `package-lock.json` or `yarn.lock` for unexpected changes.
        *   **Developer:** Employ tools like `npm audit`, `yarn audit`, or `snyk`.
        *   **Developer:** Use scoped packages (@scope/package-name) where possible.
        *   **Developer:** Implement a Software Composition Analysis (SCA) tool in the CI/CD pipeline.
        *   **Developer:** Pin dependencies to specific versions (avoid `^` or `~`), but balance this with security patch needs.

## Threat: [Build Configuration Manipulation](./threats/build_configuration_manipulation.md)

*   **Threat:** Build Configuration Manipulation

    *   **Description:** An attacker gains access to the source code repository or build server and modifies build configuration files (Webpack, Angular CLI, custom scripts) specific to `angular-seed-advanced`. They inject malicious code, disable security features, or alter the build output to include backdoors or exfiltrate data during the build. The advanced build configurations of the seed project provide more potential attack surface.
    *   **Impact:** Application compromise, data exfiltration, persistent backdoors. The attacker could modify the application to steal data, redirect users, or perform other harmful actions.
    *   **Affected Component:** Webpack configuration files, Angular CLI configuration files, custom build scripts – all specific configurations within the `angular-seed-advanced` structure.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:** Strict access control to the repository and build server; use MFA.
        *   **Developer:** Mandatory code reviews for *all* build configuration changes.
        *   **Developer:** CI/CD pipeline with automated security checks (static analysis, integrity checks).
        *   **Developer:** "Infrastructure as code" for build server configurations.

## Threat: [Lazy-Loaded Module Tampering](./threats/lazy-loaded_module_tampering.md)

*   **Threat:** Lazy-Loaded Module Tampering

    *   **Description:** An attacker gains write access to the web server or CDN. They modify the JavaScript files of lazy-loaded modules, a core feature of `angular-seed-advanced`. Because these modules are loaded on demand, the attack might be less obvious. The attacker injects code to steal data, modify behavior, or redirect users.
    *   **Impact:** Compromise of specific features, data theft, session hijacking. The impact is limited to the tampered module's functionality, but this can still be significant.
    *   **Affected Component:** Lazy-loaded modules (JavaScript files loaded via Angular's lazy loading, as configured in `angular-seed-advanced`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Implement Subresource Integrity (SRI) for *all* lazy-loaded modules.
        *   **Developer:** Use a Content Security Policy (CSP).
        *   **Developer:** Regularly monitor file integrity on the server and CDN (FIM tools).
        *   **Developer/User:** Employ a Web Application Firewall (WAF).

## Threat: [ngrx Store State Manipulation](./threats/ngrx_store_state_manipulation.md)

*   **Threat:** ngrx Store State Manipulation

    *   **Description:** An attacker exploits a vulnerability (e.g., XSS) to inject JavaScript. They use this to dispatch malicious actions to the ngrx store, a central feature of `angular-seed-advanced`, altering the application's state. They could change roles, grant permissions, or modify data.
    *   **Impact:** Bypass of security controls, unauthorized access, data corruption. The attacker could gain access to sensitive information or perform unauthorized actions.
    *   **Affected Component:** ngrx store, reducers, actions, effects – the entire ngrx implementation within `angular-seed-advanced`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Strictly validate *all* data before dispatching actions. Treat all input as untrusted.
        *   **Developer:** Use ngrx/entity and follow immutability best practices.
        *   **Developer:** Robust input validation and sanitization to prevent XSS.

## Threat: [Source Map Exposure in Production](./threats/source_map_exposure_in_production.md)

*   **Threat:** Source Map Exposure in Production

    *   **Description:** An attacker accesses the deployed application and finds publicly accessible source maps. This allows them to reverse-engineer the application's code, revealing the original TypeScript, including comments and logic. This is a greater risk with `angular-seed-advanced` due to its more complex build process.
    *   **Impact:** Information disclosure, easier vulnerability discovery, intellectual property theft.
    *   **Affected Component:** Build process (Webpack, Angular CLI), web server configuration – specifically how `angular-seed-advanced` configures these.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Ensure source maps are *not* included in the production build (`--source-map=false`).
        *   **Developer:** Verify source maps are not accessible from the deployed application.

## Threat: [ngrx Selector Authorization Bypass](./threats/ngrx_selector_authorization_bypass.md)

*   **Threat:** ngrx Selector Authorization Bypass

    *   **Description:**  An attacker, through another vulnerability, executes JavaScript within the application.  They find that ngrx selectors (used extensively in `angular-seed-advanced` for state access) don't properly restrict access to sensitive state.  They access data or trigger actions they shouldn't be able to.
    *   **Impact:**  Unauthorized access to data/functionality, bypass of security controls.
    *   **Affected Component:**  ngrx selectors – the specific selector implementations within the `angular-seed-advanced` project.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Design selectors to expose only the *minimum* necessary data.
        *   **Developer:** Use memoization (`createSelector`).
        *   **Developer:** Thoroughly test selectors.
        *   **Developer:** Consider a facade pattern for controlled state access.

## Threat: [Route Guard Bypass via ngrx](./threats/route_guard_bypass_via_ngrx.md)

*   **Threat:** Route Guard Bypass via ngrx

    *   **Description:** An attacker, with JavaScript execution capability, manipulates the ngrx store (a core part of `angular-seed-advanced`) to directly modify the application state to bypass route guards. They might change their role in the store to gain access to protected areas.
    *   **Impact:** Unauthorized access to protected routes and functionality, bypass of security controls.
    *   **Affected Component:** Angular Router, route guards, ngrx store – how these interact within the `angular-seed-advanced` structure.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Route guards *must* check the underlying application state in ngrx *and validate it rigorously*, not just the URL.
        *   **Developer:** Use `canActivate` and `canActivateChild` guards.
        *   **Developer:** Implement server-side authorization checks. Client-side guards are not sufficient.
        * **Developer:** Use JWT and verify it on backend for every request.

