# Attack Surface Analysis for markedjs/marked

## Attack Surface: [Cross-Site Scripting (XSS)](./attack_surfaces/cross-site_scripting__xss_.md)

*   **Description:** Injection of malicious client-side scripts due to `marked`'s handling of Markdown input, which can include or be manipulated to produce unsafe HTML.
*   **How Marked Contributes:** `marked`'s core function is to parse Markdown and generate HTML.  Its sanitization process is the primary defense against XSS, but vulnerabilities or misconfigurations can lead to bypasses.
*   **Example:**
    *   Input: `<img src=x onerror=alert(1)>` (if sanitization is disabled or bypassed).
    *   Input: `[link](javascript:alert('XSS'))` (if `javascript:` URLs are mishandled).
*   **Impact:**
    *   Theft of user cookies/session tokens.
    *   Redirection to malicious sites.
    *   Page defacement.
    *   Arbitrary code execution in the user's browser.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Mandatory Sanitization:**  *Always* use `marked.use({ sanitize: true });`.  This is non-negotiable.
    *   **Secondary Sanitization (DOMPurify):**  *Always* pipe `marked`'s output through DOMPurify: `DOMPurify.sanitize(marked.parse(markdownInput))`. This is a crucial second layer of defense.
    *   **Content Security Policy (CSP):** Implement a strict CSP to limit script execution and resource loading. Example: `Content-Security-Policy: default-src 'self'; script-src 'self'; ...`.
    *   **Regular Updates:** Keep both `marked` *and* DOMPurify updated to their latest versions.
    *   **Minimize `marked` Features:** Disable unnecessary `marked` options (e.g., `headerIds`, `mangle`) to reduce the attack surface.

## Attack Surface: [Regular Expression Denial of Service (ReDoS)](./attack_surfaces/regular_expression_denial_of_service__redos_.md)

*   **Description:**  Crafting malicious Markdown input that exploits vulnerabilities in `marked`'s regular expressions, causing excessive CPU consumption and denial of service.
*   **How Marked Contributes:** `marked` uses regular expressions extensively for Markdown parsing.  Poorly designed or vulnerable regexes can be exploited.
*   **Example:**
    *   Input: Extremely long strings with repeating characters or deeply nested Markdown structures designed to trigger catastrophic backtracking.  The precise example depends on the specific regex vulnerability.
*   **Impact:**
    *   Application unresponsiveness.
    *   Server resource exhaustion.
    *   Denial of service for all users.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Length Limits:** Strictly enforce reasonable maximum lengths for Markdown input. Example: `if (input.length > 10000) { rejectInput(); }`. 
    *   **Parsing Timeouts:** Implement a timeout for the `marked.parse()` operation.  Terminate parsing if it exceeds a predefined threshold (e.g., 5 seconds).  Use a Promise-based approach for asynchronous handling (see previous example).
    *   **Regular Updates:** Keep `marked` updated to benefit from ReDoS fixes.
    *   **Minimize `marked` Features:** Disable unnecessary `marked` options that might introduce additional regular expressions.

