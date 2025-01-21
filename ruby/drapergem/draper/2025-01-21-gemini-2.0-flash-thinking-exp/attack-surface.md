# Attack Surface Analysis for drapergem/draper

## Attack Surface: [Unescaped Output in Decorator Methods Leading to Cross-Site Scripting (XSS)](./attack_surfaces/unescaped_output_in_decorator_methods_leading_to_cross-site_scripting__xss_.md)

*   **Description:** When decorator methods generate output that is directly rendered in views without proper HTML escaping, malicious scripts can be injected and executed in the user's browser.
    *   **How Draper Contributes:** Decorators are often used to format and present data in views. If a decorator method directly returns user-provided data or data derived from it without escaping, Draper facilitates the rendering of this potentially malicious content.
    *   **Example:** A decorator method `formatted_name` might directly return `model.name` which contains `<script>alert('XSS')</script>`. When this method is called in the view, the script will execute.
    *   **Impact:**  Execution of arbitrary JavaScript in the user's browser, potentially leading to session hijacking, cookie theft, redirection to malicious sites, or defacement.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Always use HTML escaping:** Employ Rails' built-in escaping mechanisms (e.g., `h.html_escape`, `h.sanitize`) within decorator methods when rendering data that could originate from user input or external sources.
        *   **Prefer safe output helpers:** Utilize view helpers like `content_tag` with appropriate escaping by default.
        *   **Content Security Policy (CSP):** Implement a strong CSP to mitigate the impact of successful XSS attacks.

## Attack Surface: [Insecure Use of View Helpers with User-Controlled Data](./attack_surfaces/insecure_use_of_view_helpers_with_user-controlled_data.md)

*   **Description:** When decorator methods use view helpers like `link_to` or `image_tag` with user-controlled data for attributes like `href` or `src` without proper sanitization, it can lead to XSS or other vulnerabilities.
    *   **How Draper Contributes:** Decorators often leverage view helpers to generate HTML. If a decorator method constructs a link or image tag using unsanitized user input, Draper is the mechanism through which this potentially malicious HTML is generated and rendered.
    *   **Example:** A decorator method might create a link using `h.link_to("Click here", user_provided_url)`. If `user_provided_url` is `javascript:alert('XSS')`, clicking the link will execute the script.
    *   **Impact:** XSS attacks, phishing attacks (by redirecting to malicious sites), or other unintended actions based on the crafted URL.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Sanitize user input:**  Thoroughly sanitize and validate any user-provided data before using it in view helper arguments within decorators.
        *   **Use URL whitelists:** If possible, restrict the allowed URLs to a predefined list of safe domains.
        *   **Be cautious with `javascript:` URLs:** Avoid using `javascript:` URLs unless absolutely necessary and with extreme caution.

## Attack Surface: [Decorator Initialization with Untrusted Data Leading to Unexpected Behavior or Code Execution](./attack_surfaces/decorator_initialization_with_untrusted_data_leading_to_unexpected_behavior_or_code_execution.md)

*   **Description:** If decorators are initialized directly with user-supplied data without proper validation or sanitization, it could lead to unexpected behavior within the decorator's logic or, in extreme cases, code execution if the decorator dynamically interprets the input.
    *   **How Draper Contributes:** Draper facilitates the instantiation of decorators, and if the application directly passes unsanitized user input during this initialization, Draper becomes the conduit for this potentially malicious data to enter the decorator's scope.
    *   **Example:** A decorator might be initialized with a configuration hash derived from user input. If this hash contains malicious code that the decorator attempts to evaluate, it could lead to code execution.
    *   **Impact:**  Unexpected application behavior, potential for remote code execution (depending on the decorator's logic), denial of service.
    *   **Risk Severity:** Critical (if code execution is possible)
    *   **Mitigation Strategies:**
        *   **Validate and sanitize input:**  Always validate and sanitize any user-provided data before using it to initialize decorators.
        *   **Avoid dynamic interpretation of input:**  Design decorators to avoid dynamically interpreting or executing data passed during initialization.
        *   **Use strong typing and parameter validation:**  Enforce strict types for decorator initialization parameters and validate them thoroughly.

## Attack Surface: [Exposure of Sensitive Information Through Decorator Methods](./attack_surfaces/exposure_of_sensitive_information_through_decorator_methods.md)

*   **Description:** Decorator methods might inadvertently expose sensitive information in views if they directly return sensitive model attributes without proper filtering or masking.
    *   **How Draper Contributes:** Decorators are designed to present model data. If a decorator method directly exposes sensitive data from the model without considering access control or the context of the view, Draper facilitates this exposure.
    *   **Example:** A decorator method `full_credit_card_number` might directly return `model.credit_card_number` without masking or only showing the last few digits.
    *   **Impact:** Unauthorized disclosure of sensitive data, potentially leading to identity theft, financial loss, or privacy breaches.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Implement proper access control:** Ensure that only authorized users can access the views where sensitive information might be displayed.
        *   **Filter and mask sensitive data:**  Within decorator methods, filter or mask sensitive information before rendering it in views (e.g., show only the last four digits of a credit card).
        *   **Consider the context:** Design decorators to be context-aware and only display the necessary level of detail based on the user's permissions and the purpose of the view.

