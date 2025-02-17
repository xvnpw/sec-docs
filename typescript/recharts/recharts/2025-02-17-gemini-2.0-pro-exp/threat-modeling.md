# Threat Model Analysis for recharts/recharts

## Threat: [XSS via Unsanitized Labels/Tooltips in `Label`, `Tooltip`, `Legend`](./threats/xss_via_unsanitized_labelstooltips_in__label____tooltip____legend_.md)

*   **Threat:** XSS via Unsanitized Labels/Tooltips in `Label`, `Tooltip`, `Legend`

    *   **Description:** An attacker injects malicious JavaScript code into data fields that are used for labels, tooltips, or legend entries.  If Recharts doesn't properly escape these values, the injected code could be executed in the context of the user's browser. This is most likely if you are using custom components for labels or tooltips and are not sanitizing the input, or if a vulnerability exists in Recharts' own escaping mechanisms.
    *   **Impact:**
        *   Cross-Site Scripting (XSS) vulnerability, allowing the attacker to steal cookies, redirect users, deface the page, or perform other malicious actions.
    *   **Affected Recharts Component:** `Label`, `Tooltip`, `Legend` (and any custom components used for these purposes), specifically the props that accept text or HTML content (e.g., `value`, `formatter`, `content`).  Also potentially affects internal rendering functions if they don't properly escape data.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **HTML Escaping:**  Ensure that all text displayed in labels, tooltips, and legends is properly HTML-escaped.  Use a dedicated HTML escaping library (e.g., `he`, `dompurify`) to prevent XSS.  *Do not rely solely on React's built-in escaping, especially if you are using custom components or dangerouslySetInnerHTML.* Verify that Recharts' internal escaping is functioning correctly (and report any issues to the Recharts maintainers).
        *   **Content Security Policy (CSP):** Implement a strict Content Security Policy to limit the sources from which scripts can be executed.
        *   **Avoid `dangerouslySetInnerHTML`:**  Avoid using `dangerouslySetInnerHTML` with Recharts components unless absolutely necessary, and if you do, ensure the input is thoroughly sanitized.
        * **Use Formatter Functions Carefully:** If using formatter functions for labels or tooltips, ensure they do not directly inject user-provided data into the DOM without escaping.

## Threat: [Malformed Data Injection into `CartesianChart` (and derived charts)](./threats/malformed_data_injection_into__cartesianchart___and_derived_charts_.md)

*   **Threat:** Malformed Data Injection into `CartesianChart` (and derived charts)

    *   **Description:** An attacker provides intentionally malformed data (e.g., extremely large numbers, non-numeric values where numbers are expected, or specially crafted strings) to the `data` prop of a `CartesianChart` component (or any chart component that accepts a `data` prop, like `BarChart`, `LineChart`, `AreaChart`, etc.).  While input validation *should* happen upstream, a vulnerability *within Recharts* could exist where malformed data triggers unexpected behavior or crashes within its internal calculations or rendering logic.
    *   **Impact:**
        *   Application crash or unresponsiveness (Denial of Service).
        *   Incorrect chart rendering, leading to misinformation.
        *   *Potentially* triggering a vulnerability within Recharts' internal logic if the malformed data interacts poorly with a specific calculation or rendering function.
    *   **Affected Recharts Component:** `CartesianChart` (and all derived chart components like `LineChart`, `BarChart`, `AreaChart`, `ScatterChart`, `ComposedChart`), specifically the `data` prop and internal rendering functions that process this data.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Data Validation:** Implement rigorous data validation *before* passing data to Recharts.  Validate data types, ranges, and formats. Use a schema validation library (e.g., Joi, Yup) to enforce data integrity. This is the primary defense.
        *   **Data Sanitization:** Sanitize the input data to remove or replace any potentially harmful characters or values.
        *   **Input Size Limits:** Enforce limits on the size of the data array passed to Recharts.
        *   **Error Handling:** Wrap Recharts components in error boundaries (React's `ErrorBoundary` component) to gracefully handle rendering errors and prevent application crashes.  *However, this only mitigates the impact, not the root cause if the vulnerability is within Recharts.*
        * **Fuzz Testing (for Recharts developers):** If you are contributing to Recharts, perform fuzz testing on the data processing and rendering functions to identify potential vulnerabilities related to malformed input.

## Threat: [Denial of Service via Excessive Data Points in `ScatterChart`](./threats/denial_of_service_via_excessive_data_points_in__scatterchart_.md)

*   **Threat:** Denial of Service via Excessive Data Points in `ScatterChart`

    *   **Description:** An attacker provides an extremely large dataset to a `ScatterChart` component, overwhelming the browser's rendering capabilities.  `ScatterChart` is particularly vulnerable because each data point is rendered as a separate DOM element. This is a direct consequence of how Recharts renders scatter charts.
    *   **Impact:**
        *   Browser freeze or crash (Denial of Service).
        *   Severe performance degradation.
    *   **Affected Recharts Component:** `ScatterChart`, specifically the `data` prop and the internal rendering logic for individual scatter points.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Data Aggregation:** Aggregate data on the server-side before sending it to Recharts.  For example, use binning or other techniques to reduce the number of data points.
        *   **Data Sampling:**  If aggregation isn't feasible, use random sampling to select a representative subset of the data for display.
        *   **Pagination/Lazy Loading:** Implement pagination or lazy loading to load and render data points in smaller chunks.
        *   **Virtualization:** Explore using virtualization techniques (e.g., `react-virtualized`) to render only the visible data points. This is a more advanced technique but can significantly improve performance for large datasets. *This is often the best solution for very large scatter plots.*
        *   **Client-Side Throttling:** Implement client-side throttling to limit the frequency of chart updates, even if the server sends large amounts of data.

## Threat: [Overriding Default Event Handlers](./threats/overriding_default_event_handlers.md)

* **Threat:** Overriding Default Event Handlers

    *   **Description:** Recharts components often have default event handlers (e.g., `onClick`, `onMouseEnter`, `onMouseLeave`). If your application allows users to override these event handlers, and you don't properly validate or sanitize the provided handlers, an attacker could inject malicious code.
    *   **Impact:**
        *   XSS vulnerability if the injected code is executed in the context of the user's browser.
        *   Unexpected application behavior.
    *   **Affected Recharts Component:** Any component that accepts event handler props (e.g., `Line`, `Bar`, `Scatter`, `Pie`, etc.).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Controlled Event Handlers:**  Avoid allowing users to directly provide event handler functions. Instead, provide a controlled set of actions that users can trigger, and map these actions to pre-defined, safe event handlers within your application.
        *   **Sandboxing (Advanced):**  In very specific scenarios where you *must* allow users to provide custom event handlers, consider using a sandboxing technique (e.g., Web Workers, iframes with restricted permissions) to isolate the execution of the user-provided code. This is a complex approach and should only be used as a last resort.

