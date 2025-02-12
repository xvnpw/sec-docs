# Attack Surface Analysis for chartjs/chart.js

## Attack Surface: [Cross-Site Scripting (XSS) via Untrusted Data (Labels, Tooltips, Legends)](./attack_surfaces/cross-site_scripting__xss__via_untrusted_data__labels__tooltips__legends_.md)

*   **1. Cross-Site Scripting (XSS) via Untrusted Data (Labels, Tooltips, Legends)**

    *   **Description:** Injection of malicious JavaScript code into the chart's rendered output through data used for labels, tooltips, legends, or other text-based elements.
    *   **How Chart.js Contributes:** Chart.js renders user-provided data into the chart. While it performs *some* escaping, it's not a comprehensive HTML sanitizer, especially for custom HTML content. The library's primary focus is on chart rendering, not robust input sanitization. This is a *direct* involvement because the vulnerability arises from how Chart.js handles and renders the provided data.
    *   **Example:** An attacker provides a dataset where a label contains `<script>alert('XSS')</script>`. If this is not properly escaped *before* being passed to Chart.js, the script will execute when the chart is rendered.
    *   **Impact:**  Compromise of user accounts, data theft, session hijacking, website defacement, phishing attacks.
    *   **Risk Severity:** High (Potentially Critical if user input directly controls callback functions or custom HTML).
    *   **Mitigation Strategies:**
        *   **Input Validation and Sanitization:**  Rigorously validate and sanitize *all* data *before* passing it to Chart.js. Use a dedicated HTML sanitization library (like DOMPurify) if you allow *any* HTML in labels, tooltips, etc.  Simple escaping might not be sufficient.
        *   **Content Security Policy (CSP):**  Implement a strict CSP to limit the execution of inline scripts.
        *   **Encode Data Appropriately:** Use appropriate encoding functions.
        *   **Avoid Custom HTML if Possible:** If you don't *need* custom HTML, don't use it.
        *   **Whitelist Allowed Characters/Tags:** If you must allow some HTML, use a whitelist approach.

## Attack Surface: [XSS via Malicious Configuration Options (Specifically Callbacks)](./attack_surfaces/xss_via_malicious_configuration_options__specifically_callbacks_.md)

*   **2. XSS via Malicious Configuration Options (Specifically Callbacks)**

    *   **Description:**  Exploiting configuration options that allow specifying JavaScript callback functions.  If user input can influence these callbacks, attackers can inject malicious code.
    *   **How Chart.js Contributes:** Chart.js *directly* provides and executes these callback functions as part of its configuration API. This is the core of the vulnerability. The attacker's code runs within the context of Chart.js's execution.
    *   **Example:**  An attacker manipulates a URL parameter that is used to construct a tooltip callback: `options.plugins.tooltip.callbacks.label = function(context) { return eval(urlParam); }`.  If `urlParam` contains malicious code, Chart.js will execute it.
    *   **Impact:**  Similar to standard XSS: account compromise, data theft, session hijacking, etc.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Avoid User Input in Callbacks:**  *Never* allow user input to directly control the code within callback functions. This is paramount.
        *   **Whitelist Allowed Values:** If user input *must* influence callback behavior, use a strict whitelist.
        *   **Indirect Control:** Allow users to select from predefined options that *indirectly* control the callback's behavior, not provide code directly.

