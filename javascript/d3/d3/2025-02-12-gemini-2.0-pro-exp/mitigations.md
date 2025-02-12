# Mitigation Strategies Analysis for d3/d3

## Mitigation Strategy: [Safe Data Binding Practices with D3](./mitigation_strategies/safe_data_binding_practices_with_d3.md)

1.  **Prefer `.text()` over `.html()`:** When binding data to display text content, *always* use D3's `.text()` method.  `.text()` automatically escapes HTML entities, preventing XSS.  *Never* use `.html()` with untrusted data.
    ```javascript
    // SAFE:
    d3.select("#myElement").text(untrustedData.label);

    // UNSAFE (unless untrustedData.htmlContent is meticulously sanitized):
    d3.select("#myElement").html(untrustedData.htmlContent);
    ```
2.  **Sanitize Before `.html()` (if unavoidable):** If you *absolutely must* use `.html()` (e.g., for rendering SVG elements from data), sanitize the data *thoroughly* using a dedicated library like DOMPurify *before* passing it to `.html()`.  This is *critical*.
    ```javascript
    import DOMPurify from 'dompurify';

    function sanitizeData(rawData) {
        const config = { /* ... restrictive DOMPurify config ... */ };
        return DOMPurify.sanitize(rawData, config);
    }

    d3.select("#myElement").html(sanitizeData(untrustedData.htmlContent));
    ```
3.  **Attribute Sanitization with D3's `.attr()`:** When using D3's `.attr()` to set attributes, sanitize the attribute *value* using a library like DOMPurify, configured for attribute context.  Different escaping rules apply to attributes compared to HTML content.
    ```javascript
    d3.select("circle").attr("title", sanitizeData(untrustedData.tooltip)); // Sanitize for attribute context
    d3.select("a").attr("href", sanitizeData(untrustedData.url));      // Sanitize for URL context
    ```
4.  **Avoid Dynamic Event Handler Strings:** *Never* construct event handler strings dynamically using untrusted data and D3's `.on()`. This is a direct XSS vector.
    ```javascript
    // UNSAFE:
    d3.select("#myElement").on("click", "alert('" + untrustedData.message + "')");

    // SAFE:
    d3.select("#myElement").on("click", function() {
        alert(sanitizeData(untrustedData.message)); // Sanitize within the handler
    });
    ```
5.  **Sanitize Data within Event Handlers (using `.on()`):** Even when using D3's `.on()` to attach event handlers in a safe way (without string concatenation), sanitize any data from the event object (`d3.event`) or the bound data that is used *within* the handler.
    ```javascript
    d3.select("#myElement").on("mouseover", function(d) {
        const tooltipText = sanitizeData(d.tooltip); // Sanitize bound data
        showTooltip(tooltipText);
    });
    ```
6. **Use D3's data joining correctly:** When updating visualizations, use D3's data join mechanism (enter, update, exit) correctly. Incorrect use can lead to unexpected DOM manipulations and potential vulnerabilities if combined with unsanitized data. Ensure that you are properly handling the `enter()` selection (new elements), the `update()` selection (existing elements), and the `exit()` selection (elements to be removed).

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) via Data Binding:** (Severity: **Critical**) - Prevents attackers from injecting malicious JavaScript code through data bound to the DOM using D3's methods.
    *   **Cross-Site Scripting (XSS) via Event Handlers:** (Severity: **High**) - Prevents XSS attacks that leverage D3's event handling mechanism.
    *   **Data Exfiltration via Event Handlers (Indirectly):** (Severity: **High**) - Sanitizing data used within D3 event handlers reduces the risk of sensitive information leakage.

*   **Impact:**
    *   **XSS via Data Binding:** Risk reduction: **Very High** (essential for preventing D3-specific XSS).
    *   **XSS via Event Handlers:** Risk reduction: **High** (critical for secure event handling with D3).
    *   **Data Exfiltration:** Risk reduction: **Moderate** (reduces the attack surface within D3 event handlers).

*   **Currently Implemented:** *(Fill this in based on your project)*
    *   Example: "Consistently using `.text()` instead of `.html()`.  Attribute sanitization is implemented for most cases, but needs review."
    *   Example: "Event handlers are attached using `.on()`, but data sanitization within handlers is inconsistent."

*   **Missing Implementation:** *(Fill this in based on your project)*
    *   Example: "Missing attribute sanitization for the `href` attribute in `src/components/Links.js`."
    *   Example: "The `src/components/LegacyChart.js` component still uses `.html()` with unsanitized data."
    *   Example: "No consistent sanitization of data used within event handlers attached via `.on()`."

## Mitigation Strategy: [Controlled DOM Manipulation with D3](./mitigation_strategies/controlled_dom_manipulation_with_d3.md)

1.  **Limit Data Size Processed by D3:**  Even with sanitization, excessively large datasets can lead to performance issues or DoS.  Impose limits on the amount of data D3 processes *before* it interacts with the DOM.  This is often done in conjunction with data validation, but the *D3-specific* aspect is limiting the data *passed to D3 functions*.
2.  **Use D3's Transitions Carefully:** D3's transitions can be resource-intensive.  Avoid unnecessary or excessively long transitions, especially with large datasets.  An attacker might try to trigger many transitions simultaneously to cause performance problems.
3.  **Virtualization/Windowing with D3:** If you *must* display a very large dataset, integrate D3 with a virtualization library (e.g., `react-virtualized`, or a custom solution).  This involves rendering only the visible portion of the visualization, minimizing the number of DOM elements D3 manages.  This is a *D3-specific* integration, even though it uses an external library.
4. **Progressive Rendering with D3:** For large or complex visualizations, render them in stages using D3. Instead of creating the entire visualization at once, add elements incrementally. This can be achieved using D3's timers (`d3.timeout`, `d3.interval`) or by breaking down the rendering process into smaller chunks.
5. **Avoid unnecessary D3 selections:** Minimize the use of `d3.selectAll("*")` or other broad selectors that could potentially select a large number of elements, especially if the DOM structure is manipulated by untrusted input.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) via Excessive DOM Manipulation:** (Severity: **High**) - Reduces the likelihood of D3 causing browser slowdowns or crashes due to excessive DOM manipulation.

*   **Impact:**
    *   **DoS:** Risk reduction: **High** (makes the application more resilient to DoS attacks targeting D3).

*   **Currently Implemented:** *(Fill this in based on your project)*
    *   Example: "We limit the number of data points passed to D3 to 1000.  We don't currently use virtualization."

*   **Missing Implementation:** *(Fill this in based on your project)*
    *   Example: "The `src/components/LargeDatasetChart.js` component does not limit the data size and could be vulnerable to DoS."
    *   Example: "We need to implement virtualization for the scatterplot component, which can handle very large datasets."

