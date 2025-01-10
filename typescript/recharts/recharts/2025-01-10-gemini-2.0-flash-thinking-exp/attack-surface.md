# Attack Surface Analysis for recharts/recharts

## Attack Surface: [Cross-Site Scripting (XSS) through User-Provided Data in Chart Elements](./attack_surfaces/cross-site_scripting__xss__through_user-provided_data_in_chart_elements.md)

* **Description:**  Malicious JavaScript code is injected into the application and executed in a user's browser when the chart is rendered.
    * **How Recharts Contributes:** Recharts renders data as SVG elements. If user-controlled data is directly used for labels, tooltips, or custom shapes without sanitization, attackers can inject script tags or JavaScript event handlers within these SVG elements.
    * **Example:** A user's name, fetched from an unsanitized source, is used as a label on a bar chart. If the name contains `<script>alert("XSS");</script>`, this script will execute when the chart is displayed.
    * **Impact:**  Account takeover, redirection to malicious sites, data theft, defacement of the application.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Developers:** Sanitize all user-provided data before passing it to Recharts components. Utilize appropriate escaping mechanisms provided by the frontend framework (e.g., React's default escaping for text content) or dedicated sanitization libraries like DOMPurify. Avoid directly embedding raw HTML from user input into Recharts elements.

## Attack Surface: [SVG Injection through Custom Shapes or Components](./attack_surfaces/svg_injection_through_custom_shapes_or_components.md)

* **Description:**  Malicious SVG code containing JavaScript is injected into the application through custom Recharts shapes or components.
    * **How Recharts Contributes:** Recharts allows the use of custom SVG elements and components. If the source of these custom SVG elements is not trusted or if user input influences their generation without proper sanitization, malicious SVG code can be injected.
    * **Example:** An application allows users to upload custom icons that are then used as markers in a scatter chart. If a user uploads an SVG file containing `<script>...</script>` tags, this script will execute when the chart is rendered.
    * **Impact:** Account takeover, redirection to malicious sites, data theft, defacement of the application.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Developers:**  Strictly control the source of custom SVG shapes and components. If user input is involved in generating SVG, implement robust sanitization techniques specifically for SVG. Use a secure SVG sanitization library to remove potentially harmful elements and attributes. Consider allowing only a predefined set of safe SVG elements and attributes.

