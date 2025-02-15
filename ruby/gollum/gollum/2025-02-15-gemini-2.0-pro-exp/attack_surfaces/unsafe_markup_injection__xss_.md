Okay, here's a deep analysis of the "Unsafe Markup Injection (XSS)" attack surface for a Gollum-based application, following the structure you requested:

## Deep Analysis: Unsafe Markup Injection (XSS) in Gollum

### 1. Define Objective, Scope, and Methodology

**Objective:**

The primary objective of this deep analysis is to thoroughly understand the risks associated with Unsafe Markup Injection (specifically Cross-Site Scripting - XSS) within a Gollum wiki application.  This includes identifying the specific conditions under which Gollum becomes vulnerable, evaluating the effectiveness of various mitigation strategies, and providing actionable recommendations for developers to minimize the attack surface.  We aim to go beyond a superficial understanding and delve into the practical implications of configuration choices.

**Scope:**

This analysis focuses solely on the XSS vulnerability arising from unsafe markup handling within Gollum.  It covers:

*   Gollum's built-in markup processing capabilities.
*   The role of the `sanitize` gem and its configuration.
*   The interaction between Gollum and external libraries used for markup rendering.
*   The impact of different markup languages (Markdown, reStructuredText, HTML, etc.).
*   The effectiveness of mitigation strategies, including CSP, input validation, and output encoding.
*   The impact of user roles and permissions on the attack surface (if applicable - Gollum itself doesn't have built-in user management, but the application *using* Gollum might).

This analysis *does not* cover:

*   Other potential XSS vulnerabilities outside the context of markup processing (e.g., vulnerabilities in custom JavaScript code added to the application *around* Gollum).
*   Other attack vectors against Gollum (e.g., path traversal, denial of service).
*   Security of the underlying web server or operating system.

**Methodology:**

This analysis will employ a combination of the following methods:

*   **Code Review:** Examining the Gollum source code (and relevant libraries like `sanitize`) to understand how markup is processed and sanitized.  This is crucial for identifying potential bypasses.
*   **Configuration Analysis:**  Evaluating the default and recommended configurations for Gollum and `sanitize`, identifying potentially unsafe settings.
*   **Vulnerability Research:**  Searching for known vulnerabilities (CVEs) and public exploits related to Gollum and its dependencies, particularly focusing on XSS.
*   **Threat Modeling:**  Considering various attacker scenarios and how they might attempt to exploit the vulnerability.
*   **Best Practices Review:**  Comparing Gollum's implementation and configuration options against established security best practices for preventing XSS.
*   **Hypothetical Exploit Construction:**  Developing proof-of-concept (PoC) exploit scenarios to demonstrate the vulnerability under different configurations.  (This would be done in a controlled testing environment, *not* against a live system.)

### 2. Deep Analysis of the Attack Surface

**2.1. Gollum's Markup Processing Pipeline:**

Gollum's core functionality revolves around rendering user-provided content into HTML for display.  This process involves several steps, each presenting a potential point of vulnerability:

1.  **Input Reception:** Gollum receives user input, typically through a web form, when a user creates or edits a wiki page.
2.  **Markup Language Detection/Selection:** Gollum determines the markup language used (e.g., Markdown, reStructuredText, HTML). This can be based on file extensions or explicit user settings.
3.  **Markup Rendering:** Gollum uses external libraries (e.g., `kramdown` for Markdown, `Docutils` for reStructuredText) to convert the input into HTML.  This is a *critical* step, as vulnerabilities in these libraries can lead to XSS.
4.  **Sanitization (Optional, but Crucial):**  If configured, Gollum uses the `sanitize` gem to filter the generated HTML, removing potentially dangerous elements and attributes (like `<script>` tags).  The effectiveness of this step *entirely* depends on the `sanitize` configuration.
5.  **Output:** The final (potentially sanitized) HTML is sent to the user's browser.

**2.2. The Role of `sanitize`:**

The `sanitize` gem is the primary defense against XSS in Gollum when HTML is involved (either directly or as the output of another markup language).  `sanitize` works by parsing the HTML and applying a whitelist-based approach.  It *only* allows specific HTML elements and attributes defined in its configuration.  Anything not explicitly allowed is removed or escaped.

**Key Configuration Points for `sanitize` (and their security implications):**

*   **`elements`:**  This array defines the allowed HTML elements.  Allowing elements like `<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`, or `<meta>` (with `http-equiv="refresh"`) is *extremely dangerous* and should be avoided.
*   **`attributes`:** This defines allowed attributes for each element.  Allowing attributes like `onload`, `onerror`, `onclick`, `onmouseover`, etc. (event handlers) on *any* element opens the door to XSS.  Similarly, allowing `href` attributes on `<a>` tags without proper validation can lead to `javascript:` URL-based XSS.
*   **`protocols`:** This controls allowed URL protocols for attributes like `href` and `src`.  It's crucial to *only* allow `http` and `https` (and potentially `mailto`, with careful consideration).  Allowing `javascript:` is a direct XSS vulnerability.
*   **`transformers`:**  `sanitize` allows custom transformers to modify the HTML before or after sanitization.  A poorly written transformer could introduce XSS vulnerabilities.
*   **`remove_contents`:** This option can be used to remove the *content* of certain elements, but keep the tags themselves.  This is generally safer than allowing the elements entirely, but can still have unexpected consequences.

**2.3. Markup Language Considerations:**

*   **Markdown (Generally Safe):**  Markdown, by design, is relatively safe from XSS.  Good Markdown renderers (like `kramdown`) will escape HTML tags within the Markdown source.  However, if Gollum is configured to allow *raw HTML within Markdown*, this safety is compromised.  Also, vulnerabilities in the Markdown renderer itself could lead to XSS.
*   **reStructuredText (Generally Safe):** Similar to Markdown, reStructuredText is generally safe, but allowing raw HTML or using a vulnerable renderer can introduce XSS.
*   **HTML (Inherently Dangerous):**  Allowing users to directly input raw HTML is *extremely dangerous* and should be avoided unless absolutely necessary.  If allowed, *extremely strict* sanitization with `sanitize` is mandatory.  Even with sanitization, there's a high risk of bypasses.
*   **Other Markup Languages:**  The security of other markup languages depends on their design and the quality of their renderers.  Each language needs to be evaluated individually.

**2.4. Attacker Scenarios and Exploit Examples:**

*   **Scenario 1: Raw HTML Allowed, Weak Sanitization:**
    *   Attacker inputs: `<script>alert('XSS');</script>`
    *   Gollum (with weak `sanitize` config) fails to remove the `<script>` tag.
    *   The malicious JavaScript executes in the victim's browser.

*   **Scenario 2: Raw HTML Allowed, `javascript:` Protocol Allowed:**
    *   Attacker inputs: `<a href="javascript:alert('XSS')">Click me</a>`
    *   `sanitize` allows the `<a>` tag and `href` attribute, but doesn't block the `javascript:` protocol.
    *   Clicking the link executes the malicious JavaScript.

*   **Scenario 3: Markdown with Raw HTML Enabled, Weak Sanitization:**
    *   Attacker inputs:  `This is some text. <img src="x" onerror="alert('XSS')">`
    *   Gollum allows raw HTML within Markdown.
    *   `sanitize` allows the `<img>` tag and `onerror` attribute (a common oversight).
    *   The malicious JavaScript executes when the image fails to load.

*   **Scenario 4: Vulnerable Markdown Renderer:**
    *   Attacker inputs seemingly harmless Markdown that exploits a vulnerability in the `kramdown` library (or another renderer).
    *   The vulnerability allows the attacker to inject arbitrary HTML, bypassing Gollum's sanitization.  This highlights the importance of keeping dependencies up-to-date.

*   **Scenario 5:  Bypassing `sanitize` with Obfuscation:**
    *   Attackers may try to obfuscate their malicious code to bypass `sanitize`.  For example, they might use HTML entities (`&lt;` instead of `<`), URL encoding, or other techniques.  A robust sanitizer should handle these cases.

**2.5. Mitigation Strategies (Detailed):**

*   **Safe Markup Language (Priority 1):**  Use Markdown or reStructuredText as the *default* and *strongly discourage* or disable raw HTML input.  This significantly reduces the attack surface.

*   **Robust HTML Sanitization (Priority 1, if HTML is allowed):**
    *   Use a *very strict* `sanitize` configuration.  Start with the most restrictive preset (e.g., `Sanitize::Config::RELAXED`) and *carefully* consider any additions.
    *   **Explicitly disallow:**
        *   `<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`, `<meta>` (with `http-equiv`)
        *   *All* event handler attributes (`onload`, `onerror`, etc.)
        *   The `javascript:` protocol (and any other potentially dangerous protocols).
        *   `style` attributes (unless you *absolutely* need them, and then sanitize them *very* carefully).
    *   Regularly review and update the `sanitize` configuration.
    *   Test the configuration thoroughly with a variety of potential XSS payloads.

*   **Content Security Policy (CSP) (Priority 1):**
    *   Implement a strict CSP to limit the resources the browser can load and execute.  This is a *critical* defense-in-depth measure.
    *   A good CSP for a Gollum application might look like this (adjust as needed):
        ```http
        Content-Security-Policy:
          default-src 'self';
          script-src 'self' 'unsafe-inline' https://cdn.example.com;  # Allow inline scripts (if necessary) and scripts from a trusted CDN
          style-src 'self' 'unsafe-inline' https://cdn.example.com;  # Allow inline styles (if necessary) and styles from a trusted CDN
          img-src 'self' data: https://cdn.example.com;  # Allow images from self, data URIs, and a trusted CDN
          font-src 'self' https://cdn.example.com;
          connect-src 'self';  # Limit AJAX requests to the same origin
          frame-src 'none';  # Prevent framing (clickjacking protection)
          object-src 'none';  # Prevent embedding of objects
        ```
    *   **`script-src 'unsafe-inline'`:**  This is often necessary for Gollum's JavaScript to function, but it's a potential weakness.  Consider using nonces or hashes to allow only specific inline scripts.
    *   **`style-src 'unsafe-inline'`:** Similar to `script-src`, this might be needed, but try to minimize its use.
    *   Use a CSP reporting mechanism to monitor for violations.

*   **Input Validation (Priority 2):**
    *   Validate user input *before* it reaches the markup processing stage.
    *   This can help prevent certain types of attacks, but it's *not* a replacement for sanitization or CSP.
    *   Focus on validating data types, lengths, and allowed characters.

*   **Output Encoding (Priority 2):**
    *   Ensure that all output is properly encoded for the context in which it's used.  This is generally handled by the web framework and templating engine, but it's worth verifying.
    *   HTML entity encoding (e.g., `&lt;` for `<`) is crucial to prevent injected HTML from being interpreted as code.

*   **Keep Dependencies Updated (Priority 1):**
    *   Regularly update Gollum, `sanitize`, `kramdown`, `Docutils`, and any other dependencies to the latest versions.  This is crucial to patch known vulnerabilities.
    *   Use a dependency management tool (like Bundler for Ruby) to track and update dependencies.

*   **Regular Security Audits (Priority 2):**
    *   Conduct regular security audits and penetration testing to identify potential vulnerabilities.

* **Consider Context:**
    * If Gollum is used internally, with trusted users, the risk is lower (but still present).  If it's exposed to the public internet, the risk is *much* higher.

### 3. Conclusion and Recommendations

Unsafe markup injection, leading to XSS, is a serious threat to Gollum applications if not properly mitigated.  The primary risk stems from allowing raw HTML input or using a weak sanitization configuration.  A multi-layered approach is essential for effective protection:

**Recommendations (in order of importance):**

1.  **Default to Safe Markup:** Use Markdown or reStructuredText as the default and strongly discourage or disable raw HTML input.
2.  **Implement a Strict CSP:**  This is a critical defense-in-depth measure that can mitigate XSS even if other defenses fail.
3.  **Use Robust HTML Sanitization (if HTML is allowed):**  Configure `sanitize` with a very restrictive whitelist-based approach.  Regularly review and test the configuration.
4.  **Keep Dependencies Updated:**  Regularly update Gollum and all its dependencies to patch known vulnerabilities.
5.  **Input Validation and Output Encoding:** Implement these as additional layers of defense, but don't rely on them as the primary protection against XSS.
6.  **Regular Security Audits:** Conduct regular security audits and penetration testing.

By following these recommendations, developers can significantly reduce the risk of XSS vulnerabilities in their Gollum-based applications and protect their users from potential attacks. The key is to understand that Gollum's security posture is heavily reliant on *configuration* and the security of its dependencies. A proactive and layered approach is crucial.