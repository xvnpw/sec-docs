# Threat Model Analysis for recharts/recharts

## Threat: [Client-Side XSS via Data Injection](./threats/client-side_xss_via_data_injection.md)

*   **Description:** An attacker injects malicious JavaScript code into data provided to Recharts components (e.g., chart labels, tooltip content, data point names, custom labels). Recharts renders this data within SVG elements without sufficient sanitization. This allows the injected script to execute in the user's browser when the chart is rendered. The attacker might steal session cookies, redirect users to malicious sites, deface the application displaying the chart, or perform actions on behalf of the user viewing the chart.
*   **Impact:** Critical. Full compromise of user session and potential data breach. Attackers can gain control over the user's browser within the context of the application using Recharts.
*   **Recharts Component Affected:**  Primarily affects Recharts components that render user-provided strings and allow customization through props that process data, such as:
    *   `Label` component and `LabelList`
    *   `Tooltip` component and `CustomizedTooltip`
    *   `Legend` component and `CustomizedLegend`
    *   `Axis` components (`XAxis`, `YAxis`, `ZAxis`, `RadialAxis`) and their `tickFormatter`, `label` props.
    *   Custom shape components that render user-provided data.
    *   Any component utilizing `formatter` props on data-driven elements.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Sanitization:**  **Crucially sanitize all user-provided data** on the server-side *before* sending it to the client and again on the client-side *immediately before* passing it to Recharts components. Use robust HTML escaping functions (e.g., libraries specifically designed for XSS prevention in your backend and frontend frameworks) to ensure data is treated as text and not executable code. Pay special attention to data used in `formatter` functions and custom label/tooltip components.
    *   **Content Security Policy (CSP):** Implement a strict CSP that significantly reduces the risk of XSS.  Specifically, ensure CSP directives restrict `script-src` to only allow trusted sources and disallow `unsafe-inline` and `unsafe-eval`. This acts as a defense-in-depth measure.
    *   **Regular Recharts Updates:** Keep Recharts updated to the latest version. While sanitization should be handled by the application, staying updated ensures you benefit from any potential security improvements or bug fixes within Recharts itself.
    *   **Code Reviews:** Conduct thorough code reviews, specifically focusing on how user-provided data is handled and passed to Recharts components. Ensure developers are aware of XSS risks and are implementing proper sanitization techniques.

