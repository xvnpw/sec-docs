# Mitigation Strategies Analysis for formatjs/formatjs

## Mitigation Strategy: [Context-Aware Escaping and Sanitization Within `formatjs`](./mitigation_strategies/context-aware_escaping_and_sanitization_within__formatjs_.md)

**Mitigation Strategy:** Context-Aware Escaping and Sanitization within `formatjs`

**Description:**

1.  **Understand `formatjs`'s Escaping:** Thoroughly understand how `formatjs` handles escaping by default for different data types and formatting options (numbers, dates, plurals, etc.). Read the documentation carefully.
2.  **Rich Text Handling:** If using `rich text markup` (allowing HTML tags within messages), be *extremely* cautious.  `formatjs`'s built-in escaping may *not* be sufficient for all cases, especially if user data is embedded within HTML tags or attributes.
3.  **Pre-Sanitize Rich Text Components:** *Before* passing data to `formatjs` for rich text formatting, sanitize any user-provided values that will be part of the rich text. Use a library like DOMPurify, configured with a strict whitelist of allowed tags and attributes.  Apply this sanitization to *each individual component* of the rich text, not just the overall message string.
4.  **Custom Formatter Auditing:** If you have defined *any* custom formatters, audit them meticulously.  Ensure that they:
    *   Properly escape any user-provided data before incorporating it into the output.
    *   Handle different data types correctly.
    *   Are not vulnerable to injection attacks themselves.
    *   Consider the context where the formatted output will be used (HTML, attribute, JavaScript).
5.  **Explicit Escaping (if needed):** If you are unsure about the default escaping behavior, or if you are dealing with a particularly sensitive context, consider using explicit escaping functions provided by your templating engine or framework *in conjunction with* `formatjs`.  For example, if you're using React, you might use `React.createElement` to ensure proper escaping.
6.  **Testing with Malicious Input:** Test your `formatjs` usage with a variety of inputs, including known XSS payloads and other potentially malicious strings, to verify that escaping and sanitization are working as expected.  Use automated testing where possible.

**Threats Mitigated:**

*   **Cross-Site Scripting (XSS) (High Severity):** Directly addresses the primary threat of XSS by ensuring that user-provided data is properly escaped or sanitized *within* the formatting process.
*   **HTML Injection (High Severity):** Prevents the injection of arbitrary HTML tags and attributes, particularly within rich text messages.

**Impact:**

*   **XSS:** Significantly reduces the risk, especially when combined with pre-formatting input sanitization. This is a *critical* layer of defense.
*   **HTML Injection:** Significantly reduces the risk.

**Currently Implemented:**

*   Example: Custom formatters for date and number formatting have been reviewed and are confirmed to escape output correctly.

**Missing Implementation:**

*   Example: The `Notification` component uses `formatjs` rich text formatting, but the user-provided data that populates the notification message is *not* sanitized *before* being passed to `formatjs`. This is a high-priority area for remediation.

## Mitigation Strategy: [Avoid/Minimize `formatjs` Rich Text Features](./mitigation_strategies/avoidminimize__formatjs__rich_text_features.md)

**Mitigation Strategy:** Avoid/Minimize `formatjs` Rich Text Features

**Description:**

1.  **Re-evaluate Necessity:** For each localized message, critically assess whether `formatjs`'s rich text features (allowing HTML within messages) are *truly essential*.
2.  **Prefer Plain Text:** If the message can be effectively conveyed using plain text, *always* choose plain text. This eliminates the risk of HTML-based injection attacks.
3.  **Strict Whitelist (if unavoidable):** If rich text is absolutely unavoidable, use the *strictest possible* whitelist of allowed HTML tags and attributes when sanitizing input (as described in the previous strategy).  Allow only the bare minimum needed for the desired formatting.
4.  **Consider Alternatives:** Explore alternative formatting approaches that don't involve allowing HTML within the message itself.  For example:
    *   Use separate message keys for different parts of the message that require different styling, and apply the styling in your UI code rather than within the message.
    *   If you need basic formatting like bold or italics, consider using a Markdown-to-HTML converter (with proper sanitization) *outside* of `formatjs`.

**Threats Mitigated:**

*   **Cross-Site Scripting (XSS) (High Severity):** By minimizing or eliminating the use of rich text, you drastically reduce the attack surface for XSS.
*   **HTML Injection (High Severity):** Similar to XSS, this reduces the risk of injecting unwanted HTML.

**Impact:**

*   **XSS:** Significantly reduces the risk. This is a very effective preventative measure.
*   **HTML Injection:** Significantly reduces the risk.

**Currently Implemented:**

*   Example: The majority of localized messages in the application use plain text. Rich text is only used in a few specific components where it's considered necessary.

**Missing Implementation:**

*   Example: The `Help` section uses `formatjs` rich text, but some of the messages could be simplified to use plain text without sacrificing clarity. This should be reviewed and refactored where possible.

## Mitigation Strategy: [Regular Expression Caution (within `formatjs`)](./mitigation_strategies/regular_expression_caution__within__formatjs__.md)

**Mitigation Strategy:** Regular Expression Caution (within `formatjs`)

**Description:**

1.  **Identify Regex Usage:** Identify any instances where you are using regular expressions *within* your `formatjs` message patterns (e.g., for custom formatting or complex pluralization rules).
2.  **Minimize Complexity:** Keep regular expressions as simple as possible. Avoid complex, nested expressions that could be vulnerable to ReDoS (Regular Expression Denial of Service).
3.  **Use Regex Testing Tools:** Use online or offline regular expression testing tools to analyze your expressions for potential ReDoS vulnerabilities. These tools can help identify patterns that could lead to catastrophic backtracking.
4.  **Consider Alternatives:** If a complex regular expression is needed, explore whether the same functionality can be achieved using other `formatjs` features or by pre-processing the data *before* passing it to `formatjs`.
5.  **Input Validation (Pre-Regex):** Even with simple regexes, ensure that you have robust input validation *before* the data reaches the regular expression. This can help prevent unexpected input from triggering vulnerabilities.

**Threats Mitigated:**

*   **Regular Expression Denial of Service (ReDoS) (Medium Severity):** Prevents attackers from crafting input that causes the regular expression engine to consume excessive resources, leading to a denial-of-service condition.

**Impact:**

*   **ReDoS:** Significantly reduces the risk if regular expressions are kept simple and well-tested.

**Currently Implemented:**

*   Example: The project does not currently use any regular expressions within `formatjs` message patterns.

**Missing Implementation:**

*   Example: If any custom formatters or pluralization rules are added in the future that *do* use regular expressions, this mitigation strategy must be carefully applied.

