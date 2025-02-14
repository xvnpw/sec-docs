Okay, here's a deep analysis of the "Aggressive HTML Sanitization" mitigation strategy for FreshRSS, following the structure you requested:

# Deep Analysis: Aggressive HTML Sanitization in FreshRSS

## 1. Define Objective

**Objective:** To thoroughly evaluate the effectiveness of "Aggressive HTML Sanitization" using HTMLPurifier within FreshRSS as a primary defense against Cross-Site Scripting (XSS) and Content Spoofing attacks originating from malicious feed content.  This analysis aims to identify potential weaknesses, recommend specific configuration improvements, and establish a process for ongoing maintenance.

## 2. Scope

This analysis focuses specifically on the HTML sanitization process performed by HTMLPurifier within FreshRSS.  It encompasses:

*   **Configuration Review:**  Examining the existing HTMLPurifier configuration files and FreshRSS settings related to sanitization.
*   **Whitelist Validation:**  Assessing the completeness and strictness of the whitelisted HTML elements and attributes.
*   **URI Scheme Validation:**  Verifying the handling of URI schemes, particularly within `href` and `src` attributes.
*   **Update Mechanism:**  Evaluating the process for keeping HTMLPurifier up-to-date.
*   **Integration with FreshRSS:**  Understanding how FreshRSS utilizes HTMLPurifier and where sanitization occurs within the application's code.
*   **Testing Methodology:** Defining how to test the effectiveness of the sanitization.

This analysis *does not* cover:

*   Other XSS mitigation techniques (e.g., Content Security Policy, input validation on user-provided data *outside* of feed content).
*   Vulnerabilities unrelated to feed content parsing and rendering.
*   Performance impacts of overly aggressive sanitization (although this is a consideration).

## 3. Methodology

The analysis will employ the following methods:

1.  **Code Review:**  Direct examination of FreshRSS source code (from the provided GitHub repository) and HTMLPurifier configuration files.  This includes searching for relevant files (e.g., `lib/htmlpurifier/`, `data/config.php`, and files related to feed parsing and rendering).
2.  **Configuration Analysis:**  Detailed inspection of the HTMLPurifier configuration to identify allowed elements, attributes, and URI schemes.  Comparison against a known-secure baseline configuration.
3.  **Vulnerability Research:**  Reviewing known HTMLPurifier bypasses and common XSS attack vectors to identify potential weaknesses in the configuration.
4.  **Dynamic Testing (Black-Box & Gray-Box):**
    *   **Black-Box:**  Creating malicious RSS feeds containing various XSS payloads and observing the rendered output in FreshRSS.
    *   **Gray-Box:**  Using debugging tools (e.g., browser developer tools, network inspectors) to inspect the sanitized HTML and identify any remaining potentially dangerous elements or attributes.
5.  **Documentation Review:**  Consulting FreshRSS and HTMLPurifier documentation to understand best practices and recommended configurations.
6.  **Reporting:**  Summarizing findings, providing specific recommendations, and outlining a maintenance plan.

## 4. Deep Analysis of Aggressive HTML Sanitization

Based on the provided description and common FreshRSS setups, here's a breakdown of the analysis:

### 4.1. Locate HTMLPurifier Configuration

*   **Expected Location:** The primary configuration is likely within a file like `lib/htmlpurifier/HTMLPurifier.standalone.php` or a similar file within that directory.  FreshRSS might also have its own configuration settings that override or extend the default HTMLPurifier settings, potentially in `data/config.php` or a dedicated configuration file.  It's crucial to identify *all* relevant configuration sources.
*   **Action:**  Thoroughly search the FreshRSS codebase for all files related to HTMLPurifier and its configuration.  Document the file paths and their roles.

### 4.2. Customize Configuration (Whitelist Approach)

*   **Default Configuration Weakness:**  The default HTMLPurifier configuration is designed for general-purpose use and is *not* sufficiently strict for a security-critical application like an RSS reader.  It allows many elements and attributes that could be exploited for XSS.
*   **Recommended Whitelist:**
    *   **Elements:**  `p`, `a`, `img`, `strong`, `em`, `ul`, `ol`, `li`, `br`, `blockquote`, `code`, `pre`, `h1`, `h2`, `h3`, `h4`, `h5`, `h6`, `hr`, `span`, `div` (with careful attribute restrictions).  Consider adding `table`, `thead`, `tbody`, `tr`, `th`, `td` if table support is essential, but with *extreme* caution and strict attribute filtering.
    *   **Attributes:**
        *   `a`: `href`, `title`, `rel` (with careful validation of `rel` values, e.g., disallowing `noopener noreferrer` bypasses).
        *   `img`: `src`, `alt`, `title`, `width`, `height`.
        *   `span`, `div`:  Potentially `class` (if used for styling, but *strictly* validate class names to prevent CSS injection).
        *   `blockquote`, `code`, `pre`:  Potentially `class` (for syntax highlighting, but with strict validation).
        *   `table`, `thead`, `tbody`, `tr`, `th`, `td`:  If allowed, *very* limited attributes like `colspan`, `rowspan` (with numeric validation).  Absolutely *no* styling attributes.
    *   **Disallowed Elements:**  `script`, `iframe`, `object`, `embed`, `form`, `input`, `textarea`, `button`, `select`, `option`, `style`, `link`, `meta`, `base`, `applet`, `param`.
    *   **Disallowed Attributes:**  *All* event handlers (`on*`), `style`, `data-*` (unless specifically validated), `id` (unless strictly necessary and controlled by FreshRSS), `class` (unless strictly validated).
*   **Action:**  Create a *new* configuration file (or modify an existing one) that implements the strict whitelist.  Document the rationale behind each allowed element and attribute.  Use HTMLPurifier's configuration directives (e.g., `%HTML.AllowedElements`, `%HTML.AllowedAttributes`, `%URI.AllowedSchemes`) to enforce the whitelist.

### 4.3. Restrict Attributes & Sanitize `href`

*   **`href` Validation:**  This is *critical*.  The configuration *must* explicitly allow only `http:` and `https:` schemes for `href` attributes.  It should also prevent any attempts to bypass this restriction using URL encoding or other tricks.  HTMLPurifier provides mechanisms for this (e.g., `%URI.AllowedSchemes`).
*   **`src` Validation:** Similar to `href`, `src` attributes (primarily for `img` tags) should be restricted to `http:` and `https:`.  Consider also validating the domain against a whitelist of trusted image sources if feasible (this can help prevent image-based tracking).
*   **Other Attributes:**  All allowed attributes should be carefully scrutinized for potential injection vectors.  For example, `title` attributes should be properly escaped to prevent XSS.
*   **Action:**  Configure HTMLPurifier to enforce strict URI scheme validation for `href` and `src`.  Implement additional validation logic if necessary (e.g., domain whitelisting for images).  Thoroughly test with various malicious URLs.

### 4.4. Update HTMLPurifier

*   **Importance:**  HTMLPurifier is actively maintained, and updates often include security fixes.  Regular updates are essential to protect against newly discovered vulnerabilities.
*   **Update Mechanism:**  FreshRSS likely includes HTMLPurifier as a dependency.  The update process might involve manually replacing files in the `lib/` directory or using a package manager (if FreshRSS supports one).
*   **Action:**  Document the current HTMLPurifier version.  Establish a clear process for updating HTMLPurifier, ideally automated.  Subscribe to HTMLPurifier's security announcements to be notified of new releases.

### 4.5. Integration with FreshRSS

*   **Sanitization Points:**  Identify *where* in the FreshRSS code HTMLPurifier is invoked.  This is likely to be in the feed parsing and/or rendering logic.  Understanding this is crucial for ensuring that *all* feed content is properly sanitized.
*   **Potential Bypasses:**  Look for any code that might manipulate feed content *after* sanitization, as this could introduce vulnerabilities.
*   **Action:**  Review the FreshRSS codebase to identify all calls to HTMLPurifier.  Ensure that sanitization occurs *before* any other processing of feed content that could introduce vulnerabilities.

### 4.6. Testing Methodology

*   **Test Feeds:**  Create a set of malicious RSS feeds containing various XSS payloads, including:
    *   Basic script tags: `<script>alert(1)</script>`
    *   Event handlers: `<img src="x" onerror="alert(1)">`
    *   `javascript:` URLs: `<a href="javascript:alert(1)">Click me</a>`
    *   Encoded payloads: `<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">Click me</a>`
    *   CSS-based attacks (if CSS is allowed): `<style>body { background-image: url("javascript:alert(1)"); }</style>`
    *   Known HTMLPurifier bypasses (search for "HTMLPurifier bypass" to find examples).
    *   Malformed HTML to test for unexpected behavior.
*   **Testing Procedure:**
    1.  Add the test feeds to FreshRSS.
    2.  View the feeds in FreshRSS using a modern web browser.
    3.  Inspect the rendered HTML using the browser's developer tools.
    4.  Verify that *no* malicious code is executed.
    5.  Check for any unexpected elements or attributes that might indicate a sanitization failure.
*   **Automated Testing:**  Consider integrating the testing process into FreshRSS's build or testing pipeline to automatically detect regressions.

## 5. Recommendations

1.  **Implement a Strict Whitelist:**  Create a new HTMLPurifier configuration file (or significantly modify the existing one) based on the whitelist recommendations above.
2.  **Enforce URI Scheme Validation:**  Explicitly allow only `http:` and `https:` for `href` and `src` attributes.
3.  **Establish an Update Process:**  Document and automate the process for updating HTMLPurifier.
4.  **Thoroughly Test:**  Create a comprehensive set of test feeds and regularly test the sanitization process.
5.  **Regular Review:**  Periodically review the HTMLPurifier configuration and FreshRSS code to ensure that the sanitization remains effective.
6.  **Consider Content Security Policy (CSP):**  While not part of this specific analysis, implementing a strong CSP is a highly recommended additional layer of defense against XSS.

## 6. Conclusion

Aggressive HTML sanitization using HTMLPurifier is a *crucial* component of FreshRSS's security.  However, the default configuration is likely insufficient.  By implementing the recommendations outlined in this analysis, the development team can significantly reduce the risk of XSS and content spoofing attacks originating from malicious feed content.  Continuous monitoring, testing, and updates are essential to maintain a strong security posture.