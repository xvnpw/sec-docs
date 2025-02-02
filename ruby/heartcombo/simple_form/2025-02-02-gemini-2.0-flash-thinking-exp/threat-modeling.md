# Threat Model Analysis for heartcombo/simple_form

## Threat: [Stored XSS via Form Hints/Placeholders/Labels](./threats/stored_xss_via_form_hintsplaceholderslabels.md)

*   **Description:** An attacker injects malicious JavaScript code into user-provided data that is subsequently used as form hints, placeholders, or labels within Simple Form. When other users view the form, the malicious script executes in their browsers.
*   **Impact:** Account takeover, data theft, malware distribution, defacement of the application for users viewing the form.
*   **Simple_form component affected:**  `hint`, `placeholder`, `label` options within form input definitions, custom wrappers.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Sanitize all user-provided data before using it in `hint`, `placeholder`, or `label` options. Utilize Rails' `sanitize` helper or `ERB::Util.html_escape`.
    *   Implement Content Security Policy (CSP) to restrict the execution of inline scripts and external resources.
    *   Regularly audit form definitions and custom wrappers for potential XSS vulnerabilities.

## Threat: [XSS in Custom Input Types/Wrappers](./threats/xss_in_custom_input_typeswrappers.md)

*   **Description:**  An attacker exploits vulnerabilities in custom input types or wrappers created for Simple Form. If these custom components are not properly coded, they might render user-controlled data unsafely, leading to XSS.
*   **Impact:** Similar to Stored XSS - account takeover, data theft, malware distribution, defacement.
*   **Simple_form component affected:** Custom input types, custom wrappers.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Thoroughly review and security test all custom input types and wrappers.
    *   Use secure coding practices when developing custom components, focusing on output encoding and sanitization.
    *   Prefer templating engines within custom components that automatically handle output encoding.
    *   Conduct regular security audits of custom code.

## Threat: [Mass Assignment via Exposed Form Fields](./threats/mass_assignment_via_exposed_form_fields.md)

*   **Description:** An attacker manipulates form data by adding or modifying parameters to exploit mass assignment vulnerabilities if the application's controller does not properly use strong parameters. Simple Form might inadvertently make it easier to expose more attributes in forms than intended, increasing the attack surface.
*   **Impact:** Unauthorized modification of data, privilege escalation, bypassing business logic, data corruption.
*   **Simple_form component affected:** Automatic form generation, form input definitions.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Always use strong parameters in Rails controllers to explicitly permit only intended attributes for mass assignment.
    *   Carefully review generated forms to ensure only necessary fields are exposed.
    *   Utilize Simple Form's options to control form field generation and visibility.
    *   Implement server-side validation to verify data integrity and authorization.

