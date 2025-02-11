# Threat Model Analysis for ultraq/thymeleaf-layout-dialect

## Threat: [Layout File Injection](./threats/layout_file_injection.md)

*   **Threat:** Layout File Injection

    *   **Description:** An attacker manipulates the application to load a malicious layout file instead of the intended one. This is achieved by exploiting vulnerabilities where the layout file path is determined dynamically (e.g., from user input, URL parameters, or database values) without proper validation or sanitization. The attacker crafts a malicious layout file containing harmful code or altering the page structure. This is a *direct* threat because it exploits the core mechanism of the Layout Dialect – determining *which* layout file to use.
    *   **Impact:**
        *   Complete control over the rendered page's structure.
        *   Potential for Cross-Site Scripting (XSS) by injecting malicious scripts.
        *   Bypassing of security controls (e.g., authentication checks) implemented in the legitimate layout.
        *   Information disclosure by exposing sensitive data.
        *   Redirection to phishing sites.
    *   **Affected Component:** The core layout resolution mechanism, specifically how the `layout:decorate` attribute (or equivalent processing) determines the layout file to load. This involves the Layout Dialect's logic for interpreting `layout:decorate` and interacting with Thymeleaf's template resolver.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:**  Never directly use user-supplied data to construct layout file paths.
        *   **Whitelist Approach:**  Maintain a whitelist of allowed layout file names or paths.  Only load layouts from this whitelist.
        *   **Secure Configuration:**  Use a configuration-based approach (e.g., a mapping in a configuration file) to define layout file associations, rather than dynamically generating paths.
        *   **Secure Lookup:** If dynamic selection is unavoidable, use a secure lookup mechanism (e.g., a map of safe keys to safe file paths) instead of direct path construction.
        *   **File System Permissions:**  Restrict file system permissions to prevent unauthorized creation or modification of layout files.

## Threat: [Fragment Injection](./threats/fragment_injection.md)

*   **Threat:** Fragment Injection

    *   **Description:** An attacker exploits vulnerabilities where fragment names used in `layout:replace`, `layout:insert` are derived from user input without proper validation. The attacker injects arbitrary fragment names, potentially including fragments that were not intended to be accessible or that contain malicious content. This is a *direct* threat because it targets the Layout Dialect's specific fragment inclusion features.
    *   **Impact:**
        *   Inclusion of unexpected or malicious content within the page.
        *   Bypassing of security controls if the injected fragment circumvents authentication or authorization checks.
        *   Potential for limited XSS if the injected fragment contains unescaped user input (though this relies on a separate vulnerability in the fragment itself).
        *   Disruption of page layout and functionality.
    *   **Affected Component:** The fragment inclusion mechanisms: `layout:replace` and `layout:insert`. These are the core attributes provided by the Layout Dialect for manipulating fragments.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid User Input:** Do not use user-supplied data directly as fragment names.
        *   **Whitelist Fragments:**  If dynamic fragment selection is necessary, use a whitelist of allowed fragment names.
        *   **Indirect Selection:** Use a secure, indirect method for selecting fragments (e.g., a mapping based on a validated key).
        *   **Sanitize Indirect Input:**  Sanitize and validate any user input that *indirectly* influences fragment selection.

## Threat: [Unintended Fragment Exposure](./threats/unintended_fragment_exposure.md)

* **Threat:** Unintended Fragment Exposure
    * **Description:** If fragment visibility is controlled by logic that is bypassed due to layout manipulation, sensitive fragments might be exposed. For example, if a fragment containing administrative controls is only supposed to be included for administrators, but an attacker can inject that fragment name, they gain access. This is a direct threat as it leverages the layout dialect's fragment inclusion/replacement capabilities.
    * **Impact:**
        * Exposure of sensitive data or functionality.
        * Unauthorized access to administrative features.
    * **Affected Component:** `layout:replace`, `layout:insert`, and the logic controlling fragment inclusion. These are core components of the layout dialect.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Server-Side Control:** Ensure that fragment visibility is *always* controlled by server-side logic that cannot be bypassed by manipulating the layout or fragment names.  Do *not* rely on client-side checks.
        * **Authorization Checks:** Implement robust authorization checks *within* the fragments themselves, in addition to controlling their inclusion.  Even if a fragment is accidentally included, it should not reveal sensitive data or functionality without proper authorization.

