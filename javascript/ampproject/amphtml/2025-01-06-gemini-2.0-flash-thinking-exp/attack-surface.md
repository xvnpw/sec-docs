# Attack Surface Analysis for ampproject/amphtml

## Attack Surface: [Cross-Site Scripting (XSS) via AMP Component Attributes](./attack_surfaces/cross-site_scripting__xss__via_amp_component_attributes.md)

*   **Description:** Attackers inject malicious scripts through attributes of AMP components that accept user-provided data (e.g., URLs in `amp-img`, `amp-video`).
    *   **How AMPHTML Contributes:** AMP components, while aiming for safety, might have implementation flaws or overlook specific injection vectors in their attribute handling. The reliance on specific component implementations can introduce vulnerabilities if not rigorously secured.
    *   **Example:** An attacker crafts a malicious URL containing JavaScript code and injects it into the `src` attribute of an `amp-img` tag. If the AMP runtime doesn't properly sanitize this input, the script could execute in the user's browser.
    *   **Impact:** Full compromise of the user's session, redirection to malicious sites, data theft, or defacement of the page.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**  Ensure strict output encoding and sanitization of any user-provided data used in AMP component attributes on the server-side before it's rendered in the AMP HTML. Utilize Content Security Policy (CSP) to restrict the sources from which scripts can be executed. Regularly update the AMP library to benefit from security patches.

## Attack Surface: [Bypassing AMP Sanitization and Validation](./attack_surfaces/bypassing_amp_sanitization_and_validation.md)

*   **Description:** Attackers find ways to create AMP markup that circumvents the built-in AMP validator and sanitization mechanisms, allowing the inclusion of arbitrary HTML or JavaScript.
    *   **How AMPHTML Contributes:** The complexity of the AMP specification and the continuous evolution of browser technologies can create opportunities for bypasses. Subtle differences in parsing between the validator and browsers can be exploited.
    *   **Example:** An attacker discovers a specific combination of HTML tags or character sequences that the AMP validator accepts as valid but a browser interprets in a way that allows script execution.
    *   **Impact:** Allows injection of arbitrary client-side code, leading to XSS and other client-side vulnerabilities.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**  Strictly adhere to the AMP specification. Regularly test AMP pages with the official validator and different browsers. Implement server-side validation as an additional layer of security. Stay updated with reported AMP validation bypasses and update the AMP library accordingly.

## Attack Surface: [AMP Component-Specific Vulnerabilities](./attack_surfaces/amp_component-specific_vulnerabilities.md)

*   **Description:** Individual AMP components have vulnerabilities due to flaws in their implementation, leading to XSS, information disclosure, or other exploits.
    *   **How AMPHTML Contributes:** Each AMP component is a piece of code with its own potential for bugs. The complexity of some components increases the likelihood of vulnerabilities.
    *   **Example:** A vulnerability in the `amp-form` component could allow bypassing Cross-Site Request Forgery (CSRF) protection or leaking form data to an attacker's domain. A flaw in `amp-ad` could be exploited to serve malicious ads.
    *   **Impact:** Varies depending on the component, but can range from minor information leaks to full account compromise.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**  Thoroughly test the implementation of all used AMP components. Stay informed about reported vulnerabilities in specific components and update the AMP library promptly. Avoid using experimental or less mature components in production environments.

## Attack Surface: [Reliance on Vulnerable Third-Party AMP Extensions](./attack_surfaces/reliance_on_vulnerable_third-party_amp_extensions.md)

*   **Description:** Using custom or less-maintained AMP extensions introduces the risk of vulnerabilities within those extensions.
    *   **How AMPHTML Contributes:** AMP's extensibility through custom components means developers might incorporate code that hasn't undergone the same rigorous security review as core AMP.
    *   **Example:** A third-party analytics extension has an XSS vulnerability, allowing an attacker to inject malicious scripts on pages using that extension.
    *   **Impact:** Can lead to XSS, data theft, or other vulnerabilities depending on the extension's functionality.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**  Carefully evaluate the security of third-party AMP extensions before using them. Review the extension's code if possible. Keep extensions updated. Consider developing custom extensions in-house for critical functionality.

## Attack Surface: [AMP Real-Time Config (RTC) Vulnerabilities](./attack_surfaces/amp_real-time_config__rtc__vulnerabilities.md)

*   **Description:** Vulnerabilities in the endpoints providing real-time configuration data for AMP RTC can be exploited to inject malicious content or redirect users.
    *   **How AMPHTML Contributes:** AMP RTC introduces a dynamic element, relying on external data sources. If these sources are compromised or improperly secured, the AMP page's behavior can be manipulated.
    *   **Example:** An attacker compromises the RTC endpoint and injects malicious JavaScript code into the configuration data. This script then executes on the AMP page when the configuration is fetched.
    *   **Impact:** XSS, redirection to malicious sites, or manipulation of the page's content and functionality.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**  Secure the RTC endpoints with strong authentication and authorization. Implement robust input validation and sanitization on the RTC server. Use HTTPS for all communication.

## Attack Surface: [AMP Cache Poisoning](./attack_surfaces/amp_cache_poisoning.md)

*   **Description:** Attackers exploit vulnerabilities on the origin server to serve malicious content that gets cached by the Google AMP Cache and served to other users.
    *   **How AMPHTML Contributes:** The AMP Cache, while beneficial for performance, introduces a layer where compromised origin content can be widely distributed.
    *   **Example:** An attacker exploits an XSS vulnerability on the origin server. The malicious script is served to the AMP Cache, which then serves the poisoned content to other users requesting the AMP version of the page.
    *   **Impact:** Widespread distribution of malicious content, potentially affecting a large number of users.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**  Implement robust input validation and sanitization on the origin server. Secure the origin server against common web vulnerabilities. Use appropriate cache headers (e.g., `Cache-Control`) and consider using Signed Exchanges (SXG) to protect content integrity in the AMP Cache.

