# Threat Model Analysis for hakimel/reveal.js

## Threat: [Cross-Site Scripting (XSS) via Malicious Presentation Content](./threats/cross-site_scripting__xss__via_malicious_presentation_content.md)

**Description:** An attacker injects malicious JavaScript code into the presentation content (Markdown, HTML slides, or Reveal.js configuration). This code executes when a user views the presentation. The attacker might steal session cookies, redirect the user to a malicious website, deface the presentation, or perform actions on behalf of the user.
*   **Impact:** High - Full account compromise, data theft, website defacement, malware distribution.
*   **Affected Reveal.js Component:** Core Reveal.js rendering engine, Markdown parser, HTML slide rendering, Configuration parsing.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Implement robust server-side and client-side sanitization of all user-provided content before it's used in presentations. Use a well-vetted HTML sanitizer library.
        *   Enforce Content Security Policy (CSP) to restrict script sources and inline script execution.
        *   Avoid dynamically generating Reveal.js configuration from user input without strict validation and sanitization.
        *   Regularly update Reveal.js and all plugins to the latest versions to patch known vulnerabilities.
    *   **Users (Content Creators):**
        *   Be cautious about including external content or code snippets from untrusted sources in presentations.
        *   Validate and sanitize any external content before including it in the presentation.

## Threat: [Client-Side Code Injection via Vulnerable/Malicious Plugins or Themes](./threats/client-side_code_injection_via_vulnerablemalicious_plugins_or_themes.md)

**Description:** An attacker leverages a vulnerability in a Reveal.js plugin or theme, or uses a deliberately malicious plugin/theme, to inject and execute arbitrary JavaScript code within the user's browser when viewing a presentation using that plugin/theme. This can lead to similar outcomes as XSS.
*   **Impact:** High - Depending on the plugin/theme's capabilities, potential for account compromise, data theft, or malicious actions within the presentation context.
*   **Affected Reveal.js Component:** Reveal.js Plugin system, Theme loading mechanism.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Thoroughly vet and audit all third-party Reveal.js plugins and themes before integrating them into the application.
        *   Only use plugins and themes from reputable and trusted sources with active maintenance and security records.
        *   Keep all plugins and themes updated to their latest versions.
        *   Implement Subresource Integrity (SRI) for plugin and theme files to ensure file integrity and prevent tampering.
    *   **Users (Developers/Administrators):**
        *   Carefully review the code of plugins and themes before installation, especially those from unknown sources.
        *   Prefer using official or widely adopted plugins and themes with community support.

