# Attack Surface Analysis for drapergem/draper

## Attack Surface: [Unsanitized Data Passed to Decorators Leading to XSS](./attack_surfaces/unsanitized_data_passed_to_decorators_leading_to_xss.md)

**Description:** A Cross-Site Scripting (XSS) vulnerability occurs when user-controlled data is passed to a decorator and then rendered in the view without proper sanitization or escaping.

**How Draper Contributes to the Attack Surface:** Decorators are often used to format and present data. If the data passed to the decorator (either during instantiation or within a decorator method) originates from user input and is not sanitized *before* reaching the decorator, the decorator becomes the vehicle for rendering malicious scripts.

**Example:** A user provides a comment containing `<script>alert('XSS')</script>`. This comment is passed to a `CommentDecorator`. The decorator's `body` method simply returns this unsanitized string, which is then rendered in the view, executing the script.

**Impact:**  Execution of arbitrary JavaScript code in the victim's browser, potentially leading to session hijacking, cookie theft, defacement, or redirection to malicious sites.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Input Sanitization:** Sanitize all user-provided data *before* passing it to decorators. Use appropriate escaping mechanisms provided by Rails (e.g., `sanitize`, `ERB::Util.html_escape`).
* **Consider Output Encoding in Decorators:** Even if input is sanitized, ensure decorator methods that generate HTML also use proper encoding to prevent accidental introduction of vulnerabilities.

## Attack Surface: [Vulnerabilities in Decorator Methods Generating HTML](./attack_surfaces/vulnerabilities_in_decorator_methods_generating_html.md)

**Description:**  A decorator method directly constructs HTML strings without proper encoding, leading to potential XSS vulnerabilities if the data used in the HTML comes from an untrusted source.

**How Draper Contributes to the Attack Surface:** Decorators are designed to handle presentation logic, which often involves generating HTML. If these methods concatenate strings or use string interpolation without proper escaping, they become vulnerable.

**Example:** A `UserDecorator` has a `profile_link` method that constructs a link using user-provided `website` data: `"<a href='#{user.website}'>#{user.name}</a>"`. If `user.website` is `javascript:void(0)`, this creates a clickable XSS vector.

**Impact:** Execution of arbitrary JavaScript code in the victim's browser, similar to the previous attack surface.

**Risk Severity:** High

**Mitigation Strategies:**
* **Use Rails Helpers for HTML Generation:** Utilize Rails' built-in helpers like `link_to`, `content_tag`, etc., as they handle escaping by default.
* **Explicitly Escape Data:** If direct HTML generation is necessary, use methods like `ERB::Util.html_escape` to escape dynamic data.
* **Avoid String Interpolation for HTML:** Prefer using content blocks or builders that handle escaping.

