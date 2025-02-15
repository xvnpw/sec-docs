# Mitigation Strategies Analysis for drapergem/draper

## Mitigation Strategy: [Explicit Method Delegation Control](./mitigation_strategies/explicit_method_delegation_control.md)

*   **Description:**
    1.  **Identify all `delegate_all` calls:** Search the codebase for any instances of `delegate_all` within Draper decorators.
    2.  **Analyze delegated methods:** For each `delegate_all`, examine the associated model and identify *all* public methods.
    3.  **Determine necessary methods:** Decide which of those methods are *absolutely required* for presentation logic in the views.
    4.  **Replace with explicit delegation:** Replace `delegate_all` with `delegate :method1, :method2, ..., to: :association`, listing only the necessary methods.
    5.  **Review `decorates_association`:** Examine all uses of `decorates_association`.
    6.  **Minimize `decorates_association` usage:** If possible, refactor to avoid decorating the association entirely, moving logic to helpers or views.
    7.  **Use `allows` option:** If `decorates_association` is unavoidable, use the `allows` option: `decorates_association :association, allows: [:safe_method1, :safe_method2]`.
    8. **Review associated model methods:** Ensure the associated model itself doesn't expose sensitive methods publicly. Consider making methods private or protected.

*   **Threats Mitigated:**
    *   **Unintentional Method Exposure (High Severity):** Prevents access to methods that might leak sensitive data (e.g., internal IDs, unhashed passwords, API keys) or perform unintended actions (e.g., methods that modify data).
    *   **Privilege Escalation (High Severity):**  If a delegated method allows modification of data or access to resources based on user input, it could be exploited to gain unauthorized privileges.
    *   **Information Disclosure (Medium to High Severity):**  Reduces the risk of exposing internal application logic or data structures through unintentionally delegated methods.

*   **Impact:**
    *   **Unintentional Method Exposure:** Risk significantly reduced (from High to Low).
    *   **Privilege Escalation:** Risk significantly reduced (from High to Low, assuming proper authorization checks within the explicitly delegated methods).
    *   **Information Disclosure:** Risk reduced (from Medium/High to Low/Medium).

*   **Currently Implemented:**
    *   Example: `app/decorators/user_decorator.rb` uses explicit delegation for `:full_name` and `:email`.
    *   Example: `app/decorators/product_decorator.rb` uses `decorates_association :category, allows: [:name]`.

*   **Missing Implementation:**
    *   Example: `app/decorators/order_decorator.rb` still uses `delegate_all` to the `Order` model. This needs to be refactored.
    *   Example: `app/decorators/comment_decorator.rb` uses `decorates_association :user` without the `allows` option.  We need to audit the `User` model and add the `allows` option.

## Mitigation Strategy: [Secure Decorator Method Design](./mitigation_strategies/secure_decorator_method_design.md)

*   **Description:**
    1.  **Review all decorator methods:** Examine each method defined within your Draper decorators.
    2.  **Identify internal logic:** Determine which methods are purely for internal use within the decorator and should *not* be called from views.
    3.  **Use `private`:** Mark those internal methods as `private`.
    4.  **Use `protected`:** If a method needs to be accessible to subclasses, use `protected`.
    5.  **Avoid direct attribute access:** Instead of directly accessing model attributes (e.g., `object.sensitive_field`), create decorator methods that conditionally return the data or a sanitized version.
    6.  **Implement access control:** Within these methods, check user permissions (e.g., using `h.current_user.admin?`) before returning sensitive data.
    7.  **Use descriptive names:** Choose method names that clearly indicate their purpose and avoid generic names that might conflict with model methods.

*   **Threats Mitigated:**
    *   **Sensitive Data Exposure (High Severity):** Prevents direct access to sensitive model attributes from views.
    *   **Unauthorized Actions (High Severity):**  Prevents unintended execution of decorator methods that might perform actions without proper authorization checks.
    *   **Code Injection (Medium Severity):** By controlling how data is accessed and processed, reduces the risk of code injection vulnerabilities if user input is improperly handled.

*   **Impact:**
    *   **Sensitive Data Exposure:** Risk significantly reduced (from High to Low).
    *   **Unauthorized Actions:** Risk significantly reduced (from High to Low).
    *   **Code Injection:** Risk reduced (from Medium to Low).

*   **Currently Implemented:**
    *   Example: `app/decorators/user_decorator.rb` uses `private` for internal helper methods.
    *   Example: `app/decorators/product_decorator.rb` has a `display_price` method that checks user roles before showing the price.

*   **Missing Implementation:**
    *   Example: `app/decorators/order_decorator.rb` directly accesses `object.credit_card_number` in a method. This needs to be refactored to use a conditional method with access control.
    *   Example: Several decorators have methods with generic names like `get_data`. These should be renamed to be more descriptive.

## Mitigation Strategy: [Safe Helper Context (`h`) Usage within Decorators](./mitigation_strategies/safe_helper_context___h___usage_within_decorators.md)

*   **Description:**
    1.  **Identify all uses of `h` within Decorators:** Search your *decorators* for all instances where the helper context (`h`) is used.
    2.  **Analyze helper methods:** For each use of `h`, determine which helper method is being called and its purpose.
    3.  **Sanitize user input:** If any helper method *within the decorator* uses user-provided data, ensure that data is *explicitly sanitized* before being passed to the helper. Use Rails' sanitization methods (e.g., `sanitize`, `strip_tags`).
    4.  **Avoid `h.raw` within Decorators:** Minimize the use of `h.raw` *inside your decorators*. If it's absolutely necessary, double-check that the input is thoroughly sanitized and validated.
    5.  **Use helper options:** Prefer using the built-in options of helpers (e.g., `escape: false` in `link_to` only when absolutely necessary and with trusted data) instead of manual string concatenation and `h.raw` *within the decorator*.
    6.  **Document `h` usage:** Add comments explaining why specific helper methods are used *within the decorator* and how they handle user input.

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) (High Severity):** Prevents malicious scripts from being injected into the output through helpers *called within the decorator*.
    *   **Other Injection Attacks (Medium to High Severity):**  Reduces the risk of other injection vulnerabilities (e.g., SQL injection, command injection) if helpers are misused with unsanitized user input *within the decorator*.
    *   **Unintentional Helper Misuse (Low to Medium Severity):**  Reduces the risk of using helpers in ways that could lead to unexpected behavior or security issues *within the decorator*.

*   **Impact:**
    *   **XSS:** Risk significantly reduced (from High to Low/Medium).
    *   **Other Injection Attacks:** Risk reduced (from Medium/High to Low/Medium).
    *   **Unintentional Helper Misuse:** Risk reduced (from Low/Medium to Low).

*   **Currently Implemented:**
    *   Example: `app/decorators/comment_decorator.rb` sanitizes user-provided comment text before using it in `h.content_tag`.

*   **Missing Implementation:**
    *   Example: `app/decorators/post_decorator.rb` uses `h.link_to` with user-provided data without explicit sanitization *within the decorator*. This needs to be addressed.
    *   Example: `app/decorators/user_decorator.rb` uses `h.raw` in a few places *within the decorator*. These instances need to be carefully reviewed and potentially refactored.

## Mitigation Strategy: [Draper Gem Updates](./mitigation_strategies/draper_gem_updates.md)

*   **Description:**
    1.  **Check for Draper updates:** Regularly check for new releases of the Draper gem.
    2.  **Update dependencies:** Use `bundle update draper` to update to the latest stable version.
    3.  **Monitor security advisories:** Subscribe to security mailing lists or use tools that automatically scan for vulnerabilities in your dependencies, specifically looking for Draper-related issues.

*   **Threats Mitigated:**
    *   **Zero-Day Vulnerabilities in Draper (Unknown Severity):**  Staying up-to-date reduces the window of exposure to newly discovered vulnerabilities in the Draper gem itself.
    *   **Known Vulnerabilities in Draper (High Severity):**  Updating addresses known security flaws that have been patched in newer versions of Draper.

*   **Impact:**
    *   **Zero-Day Vulnerabilities:** Risk reduced (severity depends on the vulnerability).
    *   **Known Vulnerabilities:** Risk significantly reduced (from High to Low).

*   **Currently Implemented:**
    *   Draper gem is currently at version `x.y.z`.

*   **Missing Implementation:**
    *   Automated dependency vulnerability scanning is not currently implemented. This should be added, with a focus on monitoring Draper.

## Mitigation Strategy: [Comprehensive Decorator Testing](./mitigation_strategies/comprehensive_decorator_testing.md)

*   **Description:**
    1.  **Write unit tests:** Create unit tests for each *decorator*, covering all public methods.
    2.  **Test return values:** Verify that *decorator* methods return the expected values, especially when dealing with sensitive data or conditional logic.
    3.  **Test user roles:** Test how *decorators* behave with different user roles and permissions.
    4.  **Test edge cases:** Test *decorator* methods with boundary conditions, null values, and unexpected input types.
    5.  **Test invalid input:**  Intentionally provide invalid or malicious input to try to break the *decorator* and identify vulnerabilities.
    6.  **Integrate with CI/CD:**  Run *decorator* tests automatically as part of your continuous integration/continuous deployment pipeline.

*   **Threats Mitigated:**
    *   **Logic Errors within Decorators (Low to High Severity):**  Testing helps catch logic errors *specific to the decorator* that could lead to security vulnerabilities.
    *   **Unexpected Decorator Behavior (Low to Medium Severity):**  Testing ensures that *decorators* behave as expected under various conditions.
    *   **Input Validation Bypass within Decorators (Medium to High Severity):**  Testing with invalid input can reveal weaknesses in input validation and sanitization *within the decorator*.

*   **Impact:**
    *   **Logic Errors:** Risk reduced (severity depends on the error).
    *   **Unexpected Behavior:** Risk reduced (from Low/Medium to Low).
    *   **Input Validation Bypass:** Risk reduced (from Medium/High to Low/Medium).

*   **Currently Implemented:**
    *   Basic unit tests exist for some decorators (e.g., `UserDecorator`, `ProductDecorator`).

*   **Missing Implementation:**
    *   Many decorators lack comprehensive test coverage, especially for edge cases and user role-based logic. This needs significant improvement.
    *   Tests are not consistently run as part of the CI/CD pipeline. This needs to be integrated.
    *   No specific tests are designed to intentionally inject malicious input into decorator methods. This type of testing should be added.

