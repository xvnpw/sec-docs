# Threat Model Analysis for ampproject/amphtml

## Threat: [Component-Specific XSS (Cross-Site Scripting)](./threats/component-specific_xss__cross-site_scripting_.md)

*   **Description:** An attacker exploits a vulnerability *within* a specific AMP component (e.g., a built-in component like `<amp-form>`, `<amp-list>`, `<amp-bind>`, or a widely-used third-party component) to inject malicious JavaScript.  While AMP aims to prevent traditional XSS, vulnerabilities within the component's sandboxed JavaScript environment are possible. The attacker crafts input that, when processed by the vulnerable component, executes their script *within the AMP sandbox*.
    *   **Impact:**  Manipulation of the AMP page's content, redirection to malicious sites (within AMP's restrictions), theft of user data (limited to the AMP sandbox), or defacement.  The impact is less than traditional XSS, but still significant due to the potential for widespread exploitation if a popular component is affected.
    *   **Affected Component:**  Any AMP component, especially those with complex input handling or those from less-trusted third-party sources.  Key examples: `<amp-form>`, `<amp-list>`, `<amp-bind>`, custom extensions.
    *   **Risk Severity:** High (especially if a widely used component is vulnerable).
    *   **Mitigation Strategies:**
        *   **Vet Third-Party Components:** Thoroughly review the source code (if available) of *all* third-party AMP components. Check for known vulnerabilities and the provider's reputation.
        *   **Use Trusted Components:** Prioritize components from well-known and reputable providers.
        *   **Input Validation and Sanitization:**  *Crucially*, ensure that all user input is properly validated and sanitized *before* being used by any AMP component. This is essential for components that handle user input.
        *   **Output Encoding:** Ensure that any data displayed by the component is properly encoded to prevent script injection.
        *   **Regular Updates:** Keep all AMP components (including the AMP runtime) up-to-date to benefit from security patches.
        *   **Report Vulnerabilities:** If you find a vulnerability, report it responsibly to the component developer and/or the AMP Project.

## Threat: [Cache Poisoning](./threats/cache_poisoning.md)

*   **Description:** An attacker exploits a vulnerability in the AMP caching infrastructure (e.g., Google AMP Cache, Cloudflare AMP Cache) to inject malicious content or alter the cached version of an AMP page. The attacker might find a way to bypass the cache's validation checks or exploit a misconfiguration *in the caching infrastructure itself*.
    *   **Impact:** Widespread distribution of malicious content to users.  This can affect a very large number of visitors, as the cached version is served to many users.  The attacker could deface the page, inject malicious scripts (within AMP's limitations), or redirect users.
    *   **Affected Component:** AMP Caching infrastructure (e.g., Google AMP Cache, Cloudflare AMP Cache). This is not a component *within* the page, but the system that serves the page.
    *   **Risk Severity:** High (due to the potential for widespread impact).
    *   **Mitigation Strategies:**
        *   **Rely on Cache Provider Security:** AMP cache providers have a strong incentive to maintain security. This is a reliance on a third party, but a necessary one for AMP's performance benefits.
        *   **Correct Canonical URLs:** Ensure the `<link rel="canonical" ...>` tag *always* points to the correct, authoritative version of your content.
        *   **Monitor Cache Behavior:** Regularly check the cached versions of your AMP pages to ensure they haven't been tampered with. Use tools like Google Search Console.
        *   **HTTPS for Origin Server:** Ensure your origin server uses HTTPS. This is a general best practice, but it's also important for AMP cache integrity.

## Threat: [CORS Misconfiguration with AMP Components](./threats/cors_misconfiguration_with_amp_components.md)

*   **Description:** An attacker exploits misconfigured Cross-Origin Resource Sharing (CORS) settings on APIs used by AMP components (like `<amp-form>` or `<amp-list>`). The API might allow requests from unauthorized origins, leading to data leakage or unauthorized actions. This is a *direct* threat because AMP components are designed to interact with APIs.
    *   **Impact:** Exposure of sensitive data to unauthorized origins, or allowing unauthorized origins to perform actions on behalf of the user. This could lead to data breaches or account compromise.
    *   **Affected Component:** Components that interact with external APIs, such as `<amp-form>`, `<amp-list>`, `<amp-access>`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict CORS Headers:** Ensure your API endpoints *only* allow requests from trusted origins, *including* the AMP cache origin (e.g., `*.ampproject.org` and your own domain).
        *   **`amp-access` for Authentication:** Use the `amp-access` component to manage authorization for authenticated requests, ensuring only authorized users can access protected resources.
        *   **Validate `Origin` Header:** On the server-side, *always* validate the `Origin` header of incoming requests to ensure they are from allowed origins.

## Threat: [Vulnerabilities in AMP Runtime](./threats/vulnerabilities_in_amp_runtime.md)

*   **Description:** A vulnerability exists *within the core AMP runtime itself* (the JavaScript library that powers AMP), allowing attackers to bypass AMP's security restrictions. This is a less frequent but potentially very serious threat, as it affects *all* AMP pages.
    *   **Impact:** Could allow for arbitrary JavaScript execution, bypassing all of AMP's security measures, leading to a full compromise of the AMP page and potentially the user's limited interaction context.
    *   **Affected Component:** The AMP runtime itself (the JavaScript library).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Keep AMP Updated:** This is the *most critical* mitigation. The AMP Project releases updates to address vulnerabilities. Use the *latest stable version* of the AMP runtime.
        *   **Report Vulnerabilities:** If you discover a vulnerability, report it responsibly to the AMP Project.

