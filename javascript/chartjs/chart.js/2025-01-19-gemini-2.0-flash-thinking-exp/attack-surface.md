# Attack Surface Analysis for chartjs/chart.js

## Attack Surface: [Client-Side Cross-Site Scripting (XSS) via Data Injection](./attack_surfaces/client-side_cross-site_scripting__xss__via_data_injection.md)

**Description:** Malicious JavaScript code is injected through chart data (labels, data points, etc.) and executed in the user's browser when Chart.js renders the chart.

**How Chart.js Contributes:** Chart.js renders the provided data, and if this data is not properly sanitized, it can interpret malicious strings as executable JavaScript, especially within tooltips or custom HTML labels.

**Example:** An attacker injects a label like `<img src=x onerror=alert('XSS')>` into the chart data. When the chart is rendered or the label is displayed (e.g., in a tooltip), the `onerror` event executes the JavaScript.

**Impact:** Session hijacking, cookie theft, redirection to malicious websites, defacement of the application, execution of arbitrary actions on behalf of the user.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Developers:** Implement robust input validation and output encoding (HTML escaping) on the server-side *before* passing data to Chart.js. Specifically escape HTML entities in chart labels, tooltips, and data values.
* **Developers:** Utilize Content Security Policy (CSP) to restrict the sources from which the browser can load resources, mitigating the impact of successful XSS.

## Attack Surface: [Client-Side Cross-Site Scripting (XSS) via Configuration Injection](./attack_surfaces/client-side_cross-site_scripting__xss__via_configuration_injection.md)

**Description:** Malicious JavaScript code is injected through Chart.js configuration options, leading to its execution in the user's browser.

**How Chart.js Contributes:** Chart.js allows for extensive configuration, including event handlers and custom functions. If user input directly influences these configuration options without sanitization, attackers can inject malicious scripts.

**Example:** An attacker manipulates a URL parameter that sets a custom tooltip callback function in the Chart.js configuration to `function(context) { alert('XSS'); return { text: '...' }; }`.

**Impact:** Similar to data injection XSS, including session hijacking and malicious actions.

**Risk Severity:** High

**Mitigation Strategies:**
* **Developers:** Avoid allowing user input to directly control Chart.js configuration options. If necessary, implement a strict allow-list of configurable options and sanitize any user-provided values.
* **Developers:**  Do not dynamically construct configuration objects based on untrusted input without careful validation.

