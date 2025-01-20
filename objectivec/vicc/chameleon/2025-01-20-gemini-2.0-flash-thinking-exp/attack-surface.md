# Attack Surface Analysis for vicc/chameleon

## Attack Surface: [CSS Injection via Unsanitized Input](./attack_surfaces/css_injection_via_unsanitized_input.md)

* **Description:** An attacker can inject malicious CSS code into the application's styling by manipulating the input data used to dynamically generate CSS classes through Chameleon.
    * **How Chameleon Contributes:** Chameleon's core functionality involves dynamically generating CSS class names based on provided data. If this data originates from untrusted sources and is not properly sanitized before being used by Chameleon, it can be exploited to inject arbitrary CSS.
    * **Example:** Imagine Chameleon is used to add a class based on a user-provided theme name. If a user provides a theme name like `"dark-theme <style> body { background-color: red; }</style>"`, Chameleon might generate a class like `dark-theme <style> body { background-color: red; }</style>`, leading to the execution of the injected CSS.
    * **Impact:**
        * **Visual Defacement:** The attacker can alter the visual appearance of the application, potentially displaying misleading information or defacing the site.
        * **Information Disclosure:** Malicious CSS can be used to exfiltrate data by manipulating layout and visibility or by exploiting browser-specific CSS features.
        * **Phishing:** The attacker can create fake login forms or other UI elements to trick users into providing sensitive information.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Strict Input Validation:** Thoroughly validate all input data used to generate CSS classes via Chameleon. Implement allow-lists for acceptable characters and patterns.
        * **Output Encoding/Escaping:** While Chameleon itself doesn't directly handle output encoding, ensure that any data passed to Chameleon is properly escaped or encoded *before* being used to construct class names. Consider using libraries specifically designed for sanitizing HTML and CSS if user-provided content is involved.
        * **Content Security Policy (CSP):** Implement a strict CSP that limits the sources from which stylesheets can be loaded, mitigating the impact of injected styles.

