# Attack Surface Analysis for wenchaod/fscalendar

## Attack Surface: [Cross-Site Scripting (XSS) via Event Data](./attack_surfaces/cross-site_scripting__xss__via_event_data.md)

*   **Description:** Malicious JavaScript code is injected into event data (e.g., title, description) and executed in the user's browser when the calendar renders.
*   **How fscalendar contributes to the attack surface:** `fscalendar` renders the provided event data within the HTML structure of the calendar. If this rendering doesn't properly escape HTML entities, injected scripts can execute.
*   **Example:** An attacker submits an event with the title `<script>alert('XSS')</script>`. When the calendar displays this event, the script will run in the user's browser.
*   **Impact:**  Account takeover, session hijacking, redirection to malicious sites, data theft, defacement of the application.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Input Sanitization:** Sanitize all user-provided event data on the server-side before storing it. Remove or encode potentially malicious characters and scripts.
    *   **Output Encoding:** Ensure that the application using `fscalendar` properly encodes event data (especially titles and descriptions) when rendering the calendar. Use HTML escaping techniques appropriate for the rendering context.
    *   **Content Security Policy (CSP):** Implement a strict CSP to limit the sources from which the browser is allowed to load resources, reducing the impact of successful XSS attacks.

## Attack Surface: [Cross-Site Scripting (XSS) via Configuration Options](./attack_surfaces/cross-site_scripting__xss__via_configuration_options.md)

*   **Description:**  If user input can influence `fscalendar`'s configuration options, attackers might inject malicious scripts through these options.
*   **How fscalendar contributes to the attack surface:** If the application dynamically sets configuration options based on user input without proper validation, it opens this attack vector. For example, if a custom header format allows arbitrary strings.
*   **Example:**  An attacker manipulates a parameter that influences the `header` configuration, injecting `<img src=x onerror=alert('XSS')>`.
*   **Impact:** Similar to event data XSS, leading to account takeover, session hijacking, etc.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid User-Controlled Configuration:**  Minimize or eliminate the ability for users to directly or indirectly influence `fscalendar`'s configuration options.
    *   **Validate Configuration Input:** If configuration options are derived from user input, strictly validate and sanitize this input before passing it to `fscalendar`.
    *   **Use Predefined Configuration:**  Favor using predefined and securely configured settings for `fscalendar`.

