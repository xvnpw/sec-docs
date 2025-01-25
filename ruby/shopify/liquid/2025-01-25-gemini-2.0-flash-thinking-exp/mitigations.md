# Mitigation Strategies Analysis for shopify/liquid

## Mitigation Strategy: [Output Encoding (Escaping) within Templates using Liquid Filters](./mitigation_strategies/output_encoding__escaping__within_templates_using_liquid_filters.md)

*   **Description:**
    1.  **Identify Dynamic Content in Templates:** Within your Liquid templates, pinpoint every instance where dynamic content (variables, outputs of filters, etc.) is rendered. This is any data that is not static text within the template.
    2.  **Determine Output Context:** For each dynamic content location, determine the context in which it will be rendered in the final output (HTML, JavaScript, CSS, URL).  Most web contexts will be HTML.
    3.  **Apply Relevant Liquid Filters:**  Utilize Shopify Liquid's built-in filters to encode the dynamic content based on the determined context *directly within the template*.
        *   **HTML Context:**  Use the `escape` or `h` filter. These filters HTML-escape characters like `<`, `>`, `&`, `"`, and `'` to prevent them from being interpreted as HTML tags or attributes. Example: `{{ user_name | escape }}`.
        *   **JSON Context:** Use the `json` filter when embedding data within `<script>` tags or other JavaScript contexts. This filter ensures data is safely encoded as a JSON string. Example: `<script> var data = {{ data_object | json }}; </script>`.
        *   **URL Context:** Use the `url_encode` filter when constructing URLs with dynamic parameters. This filter encodes characters that are not allowed in URLs. Example: `<a href="/search?q={{ search_term | url_encode }}">Search</a>`.
    4.  **Default to `escape` Filter for HTML:**  Establish a practice of using the `escape` filter (or `h`) as the default for almost all dynamic content rendered in HTML contexts within Liquid templates.
    5.  **Minimize and Justify `raw` Filter Usage:**  Avoid using the `raw` filter unless absolutely necessary. The `raw` filter bypasses Liquid's automatic escaping and renders content as is. If `raw` is used, thoroughly review the source of the data and ensure it is already safely sanitized *before* being passed to Liquid, or that it originates from a completely trusted and controlled source. Document the explicit reason for using `raw` and the security justification.
    6.  **Template Code Reviews for Filter Usage:** During template development and code reviews, specifically verify that appropriate Liquid filters are applied to all dynamic content based on the output context.
*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) - High Severity:**  By properly encoding output with Liquid filters, you prevent the injection of malicious scripts into the HTML rendered by Liquid templates. This directly mitigates XSS vulnerabilities.
    *   **HTML Injection - Medium Severity:**  HTML injection is prevented as special HTML characters are encoded, ensuring they are displayed as text rather than interpreted as HTML markup.
*   **Impact:**
    *   **XSS:** High impact - If consistently and correctly applied, this strategy is highly effective in preventing XSS vulnerabilities arising from Liquid templates.
    *   **HTML Injection:** High impact - Effectively prevents HTML injection vulnerabilities.
*   **Currently Implemented:**
    *   **Partially Implemented:**  Usage of `escape` filter is present in some Liquid templates, but not consistently applied across all dynamic content. Older templates and recently added dynamic content might lack proper escaping.
    *   **Location:** Liquid templates throughout the application.
*   **Missing Implementation:**
    *   **Consistent Filter Application:**  A systematic review and update of all Liquid templates is needed to ensure `escape` (or context-appropriate filters like `json`, `url_encode`) are applied to *every* instance of dynamic content.
    *   **Enforcement and Best Practices:**  Establish clear coding guidelines and best practices for developers regarding output encoding in Liquid templates. Consider using template linters or static analysis tools (if available for Liquid or adaptable) to help enforce consistent filter usage.
    *   **Training:** Provide developer training on the importance of output encoding in Liquid and how to correctly use Liquid's filters for different contexts.

## Mitigation Strategy: [Careful Use of `raw` Filter in Liquid Templates](./mitigation_strategies/careful_use_of__raw__filter_in_liquid_templates.md)

*   **Description:**
    1.  **Treat `raw` as Exception:** Consider the `raw` Liquid filter as a feature to be used only in exceptional circumstances, not as a standard practice.
    2.  **Justify `raw` Usage:**  Whenever the `raw` filter is considered for use, rigorously question its necessity.  Ask: "Is it absolutely essential to render this content without any escaping?"
    3.  **Trusted Data Source for `raw`:** If `raw` is deemed necessary, ensure that the data being rendered with `raw` originates from a completely trusted and highly controlled source. This source should be immune to user input or external manipulation. Examples of potentially acceptable (but still carefully reviewed) `raw` usage might include rendering content from a secure CMS that is managed by trusted administrators, or rendering pre-sanitized HTML generated by a secure server-side process.
    4.  **Pre-Sanitization (If Applicable and Extremely Careful):** In very rare cases, if you must use `raw` with data that *could* potentially be influenced by less-trusted sources, you *must* perform extremely rigorous and context-aware sanitization of the data *before* it is passed to Liquid and rendered with `raw`. This pre-sanitization should be performed using robust and well-vetted sanitization libraries, and the sanitization logic must be thoroughly reviewed by security experts. **However, pre-sanitization followed by `raw` is generally discouraged due to the high risk of errors and bypasses. Prefer using `escape` and structuring your data to avoid needing `raw` whenever possible.**
    5.  **Documentation and Review for `raw`:**  Every instance of `raw` filter usage in Liquid templates should be clearly documented, explaining *why* `raw` is used, the source of the data, and the security measures taken to ensure the data is safe to render without escaping. These documented uses of `raw` should be regularly reviewed during security audits and code reviews.
*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) - High Severity:**  By minimizing and carefully controlling `raw` filter usage, you reduce the risk of accidentally or intentionally rendering unsanitized content that could contain malicious scripts, thus mitigating XSS vulnerabilities.
    *   **HTML Injection - Medium Severity:**  Reduces the risk of HTML injection by ensuring that most dynamic content is properly escaped, and only explicitly trusted and reviewed content is rendered raw.
*   **Impact:**
    *   **XSS:** Medium to High impact - Significantly reduces XSS risk by limiting the attack surface associated with unescaped content. The impact depends on how effectively `raw` usage is minimized and controlled.
    *   **HTML Injection:** Medium impact - Reduces HTML injection risk in conjunction with consistent use of `escape` filter.
*   **Currently Implemented:**
    *   **Partially Implemented:**  Awareness of the risks of `raw` is present, but there are no strict guidelines or enforcement mechanisms in place to minimize or control its usage. Some instances of `raw` might exist in templates without clear justification or documentation.
    *   **Location:** Liquid templates throughout the application.
*   **Missing Implementation:**
    *   **Establish `raw` Usage Policy:**  Define a clear policy that strongly discourages the use of `raw` and mandates justification, documentation, and review for any instance where it is used.
    *   **Template Review for `raw`:**  Conduct a targeted review of all Liquid templates to identify existing uses of the `raw` filter. For each instance, assess the justification, data source, and security measures. Refactor templates to eliminate `raw` usage where possible, or implement proper documentation and controls where it is deemed necessary.
    *   **Code Review Process for `raw`:**  Incorporate specific checks for `raw` filter usage into the code review process for Liquid templates. Ensure that any new or existing uses of `raw` are thoroughly scrutinized and comply with the established policy.

