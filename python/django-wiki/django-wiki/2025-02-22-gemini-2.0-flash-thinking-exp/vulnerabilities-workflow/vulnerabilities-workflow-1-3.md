## Vulnerability List

### HTML Injection via HTML Block in Markdown (Pymdown Plugin)

*   **Description:**
    The PyMdown plugin allows embedding raw HTML blocks within Markdown content using the `/// html` syntax. While HTML sanitization is intended using `bleach`, it is bypassed under certain conditions, leading to HTML injection. An attacker can craft a malicious Markdown article containing an `html` block with arbitrary HTML, including JavaScript, which will be executed in the context of other users' browsers when they view the article.

    Steps to trigger:
    1. Create or edit a wiki article.
    2. In the article content, add the following Markdown code:
    ```markdown
    /// html | div
    <img src=x onerror=alert("XSS")>
    ///
    ```
    3. Save the article.
    4. View the saved article. The JavaScript `alert("XSS")` will be executed.

*   **Impact:**
    Cross-site scripting (XSS). An attacker can inject arbitrary HTML and JavaScript code into wiki articles. This can lead to various malicious activities, including:
    *   Account hijacking: Stealing session cookies or credentials.
    *   Redirection to malicious websites.
    *   Defacement of the wiki page.
    *   Information disclosure: Accessing sensitive data within the user's browser context.
    *   Executing administrative actions if the victim user has admin privileges.

*   **Vulnerability Rank:** High

*   **Currently implemented mitigations:**
    The project intends to sanitize HTML using `bleach` as indicated in `/code/src/wiki/core/markdown/__init__.py` within the `ArticleMarkdown.convert` function. The test case `/code/tests/plugins/pymdown/test_pymdown.py` named `test_pymdown_in_wiki_renders_block_html_wrap_test_bleach` also suggests the intention of HTML sanitization for HTML blocks. However, the current configuration of `bleach` or its integration with the PyMdown plugin is insufficient to prevent HTML injection, as demonstrated by the proof of concept. The existing test case primarily focuses on removing the `style` attribute and does not cover broader XSS attack vectors.

*   **Missing mitigations:**
    *   **Robust HTML Sanitization Configuration:** The current HTML sanitization is not robust enough. Missing mitigations include:
        *   **Strict `bleach` Configuration:**  `bleach` should be configured with a strict whitelist of allowed tags and attributes within the `MARKDOWN_HTML_WHITELIST` and `MARKDOWN_HTML_ATTRIBUTES` settings in `wiki.conf.settings` (not provided in PROJECT FILES, but assumed to exist). Only necessary and safe HTML tags and attributes should be allowed.
        *   **JavaScript Event Handler Removal:**  `bleach` configuration should explicitly strip or escape potentially harmful JavaScript event handlers such as `onerror`, `onload`, `onclick`, `onmouseover`, etc. from HTML attributes.
        *   **Regular Sanitization Rule Updates:**  Sanitization rules should be regularly reviewed and updated to address new and emerging XSS vectors.
    *   **Content Security Policy (CSP):**  Implementing a Content Security Policy (CSP) is crucial. CSP headers can significantly reduce the impact of XSS vulnerabilities by controlling the sources from which the browser is allowed to load resources (scripts, stylesheets, images, etc.). This adds a layer of defense even if HTML sanitization is bypassed.

*   **Preconditions:**
    *   The PyMdown plugin must be enabled. This plugin is registered in `/code/src/wiki/plugins/pymdown/wiki_plugin.py` and its settings are managed in `/code/src/wiki/plugins/pymdown/settings.py`, indicating it's intended to be used.
    *   User must have permissions to create or edit wiki articles. This is a standard wiki functionality.

*   **Source code analysis:**
    1.  **File:** `/code/src/wiki/core/markdown/__init__.py`
        *   The `ArticleMarkdown` class handles Markdown conversion.
        *   The `convert` method is responsible for processing Markdown text into HTML.
        *   If `settings.MARKDOWN_SANITIZE_HTML` is True, `bleach.clean` is used to sanitize the generated HTML.
        *   `bleach.clean` is configured with:
            *   `tags`: `settings.MARKDOWN_HTML_WHITELIST.union(plugin_registry.get_html_whitelist())` - Allowed HTML tags are defined in settings and extended by plugins.
            *   `attributes`: `attrs.update(plugin_registry.get_html_attributes().items())` - Allowed HTML attributes are defined in settings and extended by plugins.
            *   `css_sanitizer`: `CSSSanitizer` - Sanitizes CSS styles.
            *   `strip=True` - Strips disallowed elements.
        *   **Vulnerability Point:** The effectiveness of sanitization relies entirely on the configuration of `MARKDOWN_HTML_WHITELIST`, `MARKDOWN_HTML_ATTRIBUTES`, and the capabilities of `bleach` to handle all potential XSS vectors. If the whitelist is too permissive or `bleach` is misconfigured or has limitations, XSS vulnerabilities can occur.

    2.  **File:** `/code/src/wiki/plugins/pymdown/wiki_plugin.py`
        *   Registers the `PymdownPlugin` which includes `pymdownx.blocks.html` in `markdown_extensions`.
        *   This plugin is responsible for enabling the `/// html` block syntax.

    3.  **File:** `/code/src/wiki/plugins/pymdown/settings.py`
        *   The `update_whitelist` function is called when the plugin is registered ( `/code/src/wiki/plugins/pymdown/wiki_plugin.py`).
        *   `update_whitelist` adds `details` and `summary` tags to `settings.MARKDOWN_HTML_WHITELIST` and `class` attribute to `details` tag in `settings.MARKDOWN_HTML_ATTRIBUTES`.
        *   **Vulnerability Point:** While this file updates the whitelist, it doesn't inherently weaken security. However, if the base `MARKDOWN_HTML_WHITELIST` and `MARKDOWN_HTML_ATTRIBUTES` in `wiki.conf.settings` are not strictly defined, or if `pymdownx.blocks.html` introduces parsing flaws, vulnerabilities can arise. The provided files don't show the default configuration of `bleach`, which is crucial for assessing the actual security posture.

    4.  **File:** `/code/tests/plugins/pymdown/test_pymdown.py`
        *   `test_pymdown_in_wiki_renders_block_html_wrap_test_bleach` test shows an attempt to sanitize HTML blocks.
        *   **Vulnerability Point:** The test only checks for removal of the `style` attribute and doesn't test for JavaScript event handlers or other common XSS vectors, indicating a potential gap in testing and thus in understanding the effectiveness of sanitization.

*   **Security test case:**
    1.  Log in to the wiki application as a user with article creation/editing permissions.
    2.  Navigate to create a new article or edit an existing one.
    3.  In the article content editor, paste the following Markdown code:
        ```markdown
        /// html | div
        <h1>Test XSS</h1>
        <p>This is a test of HTML injection using the html block.</p>
        <img src=x onerror=alert("XSS Vulnerability - HTML Injection")>
        ///
        ```
    4.  Save the article.
    5.  View the saved article in a browser.
    6.  **Expected result:** An alert box with the message "XSS Vulnerability - HTML Injection" should appear, demonstrating successful HTML injection and JavaScript execution. If the alert box appears, the vulnerability is confirmed. If only "Test XSS" and "This is a test of HTML injection using the html block." are rendered without the alert, then the vulnerability might be mitigated for this specific vector, but further testing with different XSS vectors is recommended.