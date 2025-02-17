# Threat Model Analysis for angular/angular

## Threat: [DOM-Based XSS via `bypassSecurityTrustHtml`](./threats/dom-based_xss_via__bypasssecuritytrusthtml_.md)

*   **Threat:** DOM-Based XSS via `bypassSecurityTrustHtml`

    *   **Description:** An attacker injects malicious JavaScript code into a user input field. The application then uses `bypassSecurityTrustHtml` to render this input directly into the DOM, bypassing Angular's sanitization. The attacker's script executes in the context of other users' browsers.
    *   **Impact:**
        *   Stealing user cookies and session tokens (account takeover).
        *   Defacing the website.
        *   Redirecting users to malicious websites.
        *   Keylogging and capturing sensitive input.
        *   Performing actions on behalf of the user.
    *   **Affected Angular Component:** `DomSanitizer` (specifically, the `bypassSecurityTrustHtml` method), any component that uses `[innerHTML]` or similar bindings with unsanitized data.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid `bypassSecurityTrustHtml` whenever possible.**
        *   If dynamic HTML is *absolutely necessary*, use a robust client-side sanitization library like DOMPurify *before* passing data to Angular. Sanitize *before* trusting.
        *   Use template expressions and built-in directives (e.g., `[textContent]`) instead of `[innerHTML]` for plain text.
        *   Implement a strong Content Security Policy (CSP).
        *   Educate developers about the dangers of bypassing sanitization.
        *   Regular code reviews, focusing on `bypassSecurityTrust*` usage.

## Threat: [DOM-Based XSS via `bypassSecurityTrustScript`](./threats/dom-based_xss_via__bypasssecuritytrustscript_.md)

*   **Threat:** DOM-Based XSS via `bypassSecurityTrustScript`

    *   **Description:** An attacker injects a malicious `<script>` tag or JavaScript code that is marked as "safe" using `bypassSecurityTrustScript`.
    *   **Impact:** Same as `bypassSecurityTrustHtml` XSS (Critical).
    *   **Affected Angular Component:** `DomSanitizer` (`bypassSecurityTrustScript` method), components that dynamically create or manipulate `<script>` tags.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Almost never use `bypassSecurityTrustScript`.**
        *   If dynamically loading scripts, load them from a trusted source and use Subresource Integrity (SRI).
        *   Use a strong CSP.
        *   Avoid scenarios where user input can directly influence `<script>` tag creation.

## Threat: [DOM-Based XSS via `bypassSecurityTrustStyle`](./threats/dom-based_xss_via__bypasssecuritytruststyle_.md)

*   **Threat:** DOM-Based XSS via `bypassSecurityTrustStyle`

    *   **Description:** An attacker injects malicious CSS containing expressions or behaviors that can execute JavaScript (older browsers) or manipulate the page layout for phishing, using `bypassSecurityTrustStyle` to apply this CSS.
    *   **Impact:**
        *   Phishing attacks via deceptive page elements.
        *   Data exfiltration using CSS selectors (less common).
        *   Denial of service (browser crashes).
    *   **Affected Angular Component:** `DomSanitizer` (`bypassSecurityTrustStyle` method), components that dynamically apply styles using `[style]` or similar.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid `bypassSecurityTrustStyle` whenever possible.**
        *   If dynamic styles are necessary, use a CSS-specific sanitization library.
        *   Use a CSP to restrict stylesheet sources and inline styles.
        *   Prefer Angular's built-in style binding (e.g., `[ngStyle]`).

## Threat: [DOM-Based XSS via `bypassSecurityTrustUrl`](./threats/dom-based_xss_via__bypasssecuritytrusturl_.md)

*   **Threat:** DOM-Based XSS via `bypassSecurityTrustUrl`

    *   **Description:** An attacker provides a malicious URL (e.g., `javascript:alert(1)`) used in an `<a>` tag's `href`, an `<img>` tag's `src`, etc., after being marked as safe with `bypassSecurityTrustUrl`.
    *   **Impact:**
        *   Executing arbitrary JavaScript (link click or image load).
        *   Redirecting users to malicious sites.
    *   **Affected Angular Component:** `DomSanitizer` (`bypassSecurityTrustUrl` method), components that dynamically generate URLs.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid `bypassSecurityTrustUrl` for untrusted URLs.**
        *   Validate and sanitize all URLs before use. Ensure they match expected patterns (e.g., `https://`).
        *   Use a CSP to restrict URL protocols and domains.
        *   Prefer Angular's `[routerLink]` for internal navigation.

## Threat: [DOM-Based XSS via `bypassSecurityTrustResourceUrl`](./threats/dom-based_xss_via__bypasssecuritytrustresourceurl_.md)

*   **Threat:** DOM-Based XSS via `bypassSecurityTrustResourceUrl`

    *   **Description:** An attacker provides a malicious URL to an untrusted resource (iframe, embed, object), bypassing sanitization with `bypassSecurityTrustResourceUrl`, loading arbitrary content within the application's context.
    *   **Impact:**
        *   Loading malicious iframes (data theft, phishing).
        *   Embedding malicious objects (exploiting browser vulnerabilities).
    *   **Affected Angular Component:** `DomSanitizer` (`bypassSecurityTrustResourceUrl` method), components dynamically loading external resources.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Extremely rarely use `bypassSecurityTrustResourceUrl`.** Only for *absolutely* trusted resources under your control.
        *   Use a CSP to restrict embedded resource sources.
        *   Consider sandboxing iframes.

## Threat: [Route Guard Bypass](./threats/route_guard_bypass.md)

*   **Threat:** Route Guard Bypass

    *   **Description:** An attacker bypasses client-side route guards (`CanActivate`, etc.), accessing a protected route without authentication/authorization.
    *   **Impact:**
        *   Accessing sensitive data or functionality.
        *   Performing unauthorized actions.
    *   **Affected Angular Component:** Route Guards (`CanActivate`, `CanActivateChild`, `CanDeactivate`, `Resolve`, `CanLoad`), `Router` module.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Implement server-side authorization checks.** Client-side guards are *only* for UX; the server *must* enforce authorization.
        *   Thoroughly test route guards.
        *   Use a centralized authentication/authorization service.
        *   Enforce authorization at the route and component level, not just UI element visibility.

## Threat: [Route Parameter Tampering](./threats/route_parameter_tampering.md)

*   **Threat:** Route Parameter Tampering

    *   **Description:** An attacker modifies route parameters in the URL to access data/functionality associated with a different user/resource.
    *   **Impact:**
        *   Accessing unauthorized data.
        *   Performing actions on behalf of other users.
        *   Triggering unintended behavior.
    *   **Affected Angular Component:** Components subscribing to `ActivatedRoute` parameters, `Router` module.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Validate and sanitize all route parameters within components.** Treat them as untrusted.
        *   Use strong typing for parameters.
        *   **Implement server-side authorization based on the authenticated user, not solely on route parameters.**
        *   Consider route resolvers for pre-fetching and validating data.

## Threat: [Supply Chain Attack on a Dependency *directly used by Angular features*](./threats/supply_chain_attack_on_a_dependency_directly_used_by_angular_features.md)

* **Threat:** Supply Chain Attack on a Dependency *directly used by Angular features*

    *   **Description:**  An attacker compromises a legitimate library *specifically required for core Angular functionality or a commonly used Angular-specific library*, injecting malicious code.  This is distinct from a general JS library; it's a library that Angular itself or a very common Angular add-on depends on.
    *   **Impact:**  Potentially very severe, ranging from XSS to complete application takeover, depending on the compromised library and the nature of the injected code.  Because it affects core Angular or a widely-used Angular-specific library, the impact is likely to be widespread within the application.
    *   **Affected Angular Component:**  Potentially *any* component, depending on the compromised dependency.  This could affect the `Compiler`, `Renderer`, `Router`, or any part of the application that relies on the compromised library.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use package managers with integrity checking (`npm` with `package-lock.json` or `yarn` with `yarn.lock`).
        *   Consider using a private package registry to control the source of dependencies, especially for critical Angular-related packages.
        *   Monitor for unusual changes in dependency behavior or size, paying close attention to core Angular dependencies and widely-used Angular libraries.
        *   Implement code signing and verification where possible, although this is often difficult with npm packages.
        *   Stay informed about security advisories related to Angular and its ecosystem.

