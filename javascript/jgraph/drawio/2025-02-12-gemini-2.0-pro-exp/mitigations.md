# Mitigation Strategies Analysis for jgraph/drawio

## Mitigation Strategy: [Disable JavaScript Execution](./mitigation_strategies/disable_javascript_execution.md)

**1. Disable JavaScript Execution**

*   **Description:**
    1.  **Locate Configuration:** Identify where the drawio editor is initialized in your application's JavaScript code. This is typically where you create an instance of `mxEditor`, `Graph`, or a similar drawio object.
    2.  **Set `allowEval` to `false`:** Within the configuration object passed to the drawio constructor (or through a subsequent method call), explicitly set the `allowEval` property to `false`. This disables the execution of any JavaScript embedded within the diagram. Example:
        ```javascript
        // Example (adapt to your specific drawio integration)
        let config = { /* other configuration options */ };
        let editor = new mxEditor(config); // Or Graph, etc.
        editor.graph.allowEval = false; // Or directly in config: config.allowEval = false;
        ```
    3.  **Verify Configuration:** Use browser developer tools to inspect the running drawio instance and confirm that `allowEval` is indeed set to `false`. You can often do this by inspecting the `graph` object in the console.
    4.  **Test Thoroughly:** Create test diagrams containing JavaScript (e.g., `<script>` tags, `onclick` handlers) and verify that the code *does not* execute when the diagram is loaded or interacted with.

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS):** (Severity: **Critical**) Prevents attackers from injecting malicious JavaScript into diagrams, which could be used to steal user cookies, redirect users to phishing sites, deface the application, or perform other harmful actions. This is the *primary* threat addressed by this mitigation.
    *   **Client-Side Code Injection:** (Severity: **High**) More broadly, prevents any unauthorized client-side code execution, even if not strictly XSS.

*   **Impact:**
    *   **XSS:** Risk reduction: **Very High** (Eliminates the primary XSS vector).
    *   **Client-Side Code Injection:** Risk reduction: **High** (Significantly reduces the attack surface).

*   **Currently Implemented:**
    *   Implemented in the main diagram editor component (`/src/components/DiagramEditor.js`). Verified through code review and manual testing.

*   **Missing Implementation:**
    *   Missing in the "quick preview" feature (`/src/components/DiagramPreview.js`), which uses a simplified drawio instance to render thumbnails. This needs to be updated to also disable JavaScript execution.

## Mitigation Strategy: [Configure drawio for Secure External Resource Handling (with Proxy)](./mitigation_strategies/configure_drawio_for_secure_external_resource_handling__with_proxy_.md)

**2. Configure drawio for Secure External Resource Handling (with Proxy)**

*   **Description:**
    1.  **Identify Image Loading Configuration:** Locate where drawio is configured to handle image loading. This might involve settings like `imageBasePath`, `imageRoot`, or custom URL handling functions.
    2.  **Proxy URL Integration:** Modify drawio's configuration to use your server-side image proxy endpoint for *all* external image requests.  This typically involves:
        *   Setting `imageBasePath` to point to your proxy endpoint.
        *   Or, if drawio uses absolute URLs, implementing a custom URL rewriting function within drawio (if supported) to redirect image requests to your proxy.  This function would need to be carefully crafted to avoid introducing new vulnerabilities.
        *   Example (Conceptual, adapt to your integration):
            ```javascript
            // Assuming you're using a custom URL function
            editor.graph.getImage = function(url) {
                if (isExternalUrl(url)) {
                    return '/api/image-proxy?url=' + encodeURIComponent(url);
                }
                return url; // Or a default local image path
            };

            // OR, if using imageBasePath:
            // editor.graph.imageBasePath = '/api/image-proxy?url='; // Less flexible
            ```
    3.  **Disable Direct External Loading (If Possible):** If drawio provides an option to completely disable the loading of external images, use it in conjunction with the proxy. This provides an extra layer of defense.
    4.  **Test Thoroughly:** Create test diagrams that reference external images (both allowed and disallowed by your proxy) and verify that:
        *   Allowed images are loaded correctly through the proxy.
        *   Disallowed images are *not* loaded.
        *   No direct external image requests are made by drawio.

*   **Threats Mitigated:**
    *   **Server-Side Request Forgery (SSRF):** (Severity: **High**) By forcing all external image requests through your controlled proxy, you prevent drawio from directly accessing arbitrary URLs.
    *   **Data Exfiltration:** (Severity: **High**) Reduces the risk of attackers using image requests to send data to external servers.
    *   **Cross-Origin Resource Sharing (CORS) Bypass:** (Severity: **Medium**) Helps prevent bypassing CORS restrictions.

*   **Impact:**
    *   **SSRF:** Risk reduction: **High** (Eliminates the direct SSRF vector within drawio).
    *   **Data Exfiltration:** Risk reduction: **Medium** (Reduces the likelihood of successful data exfiltration via image requests).
    *   **CORS Bypass:** Risk reduction: **Medium** (Provides additional control).

*   **Currently Implemented:**
    *   Not implemented (since the proxy itself is not yet implemented).

*   **Missing Implementation:**
    *   The entire integration with the (yet-to-be-built) image proxy is missing. This requires modifying drawio's configuration to use the proxy endpoint.

## Mitigation Strategy: [Limit Diagram Complexity (Within drawio, if possible)](./mitigation_strategies/limit_diagram_complexity__within_drawio__if_possible_.md)

**3. Limit Diagram Complexity (Within drawio, if possible)**

*   **Description:**
    1.  **Explore drawio API:** Investigate the drawio API (JavaScript) to see if it provides any mechanisms for limiting diagram complexity *during* the editing process. This might include:
        *   Maximum number of cells (nodes, edges).
        *   Maximum nesting depth.
        *   Custom validation functions that can be triggered on diagram changes.
    2.  **Implement Client-Side Limits (If Supported):** If drawio provides such mechanisms, implement them to enforce reasonable limits on diagram complexity. This can help prevent DoS attacks *before* the diagram is even sent to the server.
        *   Example (Hypothetical, as drawio's API might not have these exact features):
            ```javascript
            // Example (IF drawio had such features)
            editor.graph.maxCells = 1000; // Limit to 1000 cells
            editor.graph.validateGraph = function(graph, context) {
                if (getNestingDepth(graph) > 5) {
                    context.error('Diagram is too deeply nested.');
                    return false;
                }
                return true;
            };
            ```
    3.  **Inform Users:** If you implement client-side limits, clearly inform users about these restrictions.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS):** (Severity: **Medium**) Reduces the risk of client-side DoS attacks by preventing the creation of excessively complex diagrams that could freeze the browser.  Also provides *early* mitigation for server-side DoS, before the diagram is even uploaded.

*   **Impact:**
    *   **DoS:** Risk reduction: **Low to Medium** (Provides some client-side protection and early server-side mitigation). The effectiveness depends heavily on whether drawio provides suitable API features.

*   **Currently Implemented:**
    *   Not implemented. We haven't yet explored the drawio API for these capabilities.

*   **Missing Implementation:**
    *   We need to investigate the drawio API and implement client-side complexity limits if possible.

