# Mitigation Strategies Analysis for hanami/hanami

## Mitigation Strategy: [Explicit and Secure Hanami Configuration](./mitigation_strategies/explicit_and_secure_hanami_configuration.md)

*   **Mitigation Strategy:** Explicit and Secure Hanami Configuration

    *   **Description:**
        1.  **`config/app.rb` Review:** Thoroughly examine Hanami's `config/app.rb` file. This is the central point for configuring application-wide security settings.
        2.  **`force_ssl`:**  Set `config.force_ssl = true` in the `production` environment block within `config/app.rb`. This leverages Hanami's built-in mechanism to enforce HTTPS.
        3.  **`cookies`:**  Within `config/app.rb`, explicitly configure cookie options using Hanami's settings:
            *   `secure: true`
            *   `http_only: true`
            *   `same_site: :lax` or `:strict`
        4.  **`sessions`:** If using Hanami's session management, configure the session store and its options within `config/app.rb`. Choose a secure store (database or properly secured Redis) and set appropriate timeouts.  Use Hanami's configuration API for this.
        5.  **`security` (Hanami::Action):**  Utilize the `security` configuration block within `config/app.rb` (or within individual action configurations) to set security headers.  This uses Hanami's built-in header management:
            *   **CSRF Protection:** Ensure Hanami's built-in CSRF protection is enabled and configured.
            *   **Content Security Policy (CSP):** Define a CSP using Hanami's helpers.
            *   **X-Frame-Options, X-XSS-Protection, X-Content-Type-Options:** Set these headers using Hanami's configuration.
        6.  **Action-Specific Configuration:**  If certain actions require different security settings (e.g., a more restrictive CSP), override the application-wide settings within the action's configuration block.
        7. **`hanami-settings` (if used):** If you are using the `hanami-settings` gem, ensure that security-related settings are defined and validated within your settings class.

    *   **Threats Mitigated:**
        *   **Insecure Defaults (Severity: High):**  Addresses Hanami-specific default configurations.
        *   **Cross-Site Scripting (XSS) (Severity: High):**  CSP and cookie settings, managed through Hanami's configuration.
        *   **Cross-Site Request Forgery (CSRF) (Severity: High):**  Hanami's built-in CSRF protection and `same_site` cookie settings.
        *   **Clickjacking (Severity: Medium):**  `X-Frame-Options` set via Hanami's configuration.
        *   **MIME-Sniffing (Severity: Low):** `X-Content-Type-Options` set via Hanami.
        *   **Session Hijacking (Severity: High):** Secure cookie and Hanami session settings.

    *   **Impact:**
        *   **Insecure Defaults:** Risk reduced from High to Low.
        *   **XSS:** Risk reduced from High to Medium/Low (depending on CSP strictness).
        *   **CSRF:** Risk reduced from High to Low.
        *   **Clickjacking:** Risk reduced from Medium to Low.
        *   **MIME-Sniffing:** Risk reduced from Low to Negligible.
        *   **Session Hijacking:** Risk reduced from High to Medium.

    *   **Currently Implemented:** [**Example:** `config/app.rb` settings for `force_ssl` and basic cookie options.] *Replace with your project's details.*

    *   **Missing Implementation:** [**Example:** CSP is not fully implemented via Hanami's helpers; action-specific security configurations are not used.] *Replace with your project's details.*


## Mitigation Strategy: [Strict Hanami Route Definitions and Constraints](./mitigation_strategies/strict_hanami_route_definitions_and_constraints.md)

*   **Mitigation Strategy:** Strict Hanami Route Definitions and Constraints

    *   **Description:**
        1.  **`config/routes.rb` Precision:**  In Hanami's `config/routes.rb` file, define routes with *extreme* precision. Use explicit HTTP verbs (GET, POST, etc.) and avoid overly broad path definitions.
        2.  **Hanami Constraints:**  Leverage Hanami's routing constraints (both built-in and custom) to restrict access to routes based on various criteria (e.g., request headers, parameters, custom logic).
        3.  **Custom Constraint Classes:** If you create custom constraint classes (implementing `Hanami::Routes::Constraint`), ensure they are thoroughly tested with unit tests to prevent unexpected behavior.
        4.  **`hanami routes` Command:**  Regularly use the `hanami routes` command-line tool to inspect the generated routing table. This helps you visualize and verify your routing logic, ensuring no unintended exposures.
        5. **Route-Specific Middleware:** If you need to apply specific middleware (e.g., for authentication or authorization) to a subset of routes, use Hanami's routing capabilities to apply the middleware only to those routes, rather than globally.

    *   **Threats Mitigated:**
        *   **Unintended Route Exposure (Severity: High):**  Directly addresses Hanami's routing mechanism.
        *   **Authorization Bypass (Severity: High):**  Hanami constraints can be used to enforce authorization rules at the routing level.

    *   **Impact:**
        *   **Unintended Route Exposure:** Risk reduced from High to Low.
        *   **Authorization Bypass:** Risk reduced from High to Medium.

    *   **Currently Implemented:** [**Example:** Basic routes are defined with specific verbs; some built-in constraints are used.] *Replace with your project's details.*

    *   **Missing Implementation:** [**Example:** Custom constraint classes lack unit tests; `hanami routes` is not used regularly.] *Replace with your project's details.*


## Mitigation Strategy: [Hanami Action-Level Security and Error Handling](./mitigation_strategies/hanami_action-level_security_and_error_handling.md)

*   **Mitigation Strategy:** Hanami Action-Level Security and Error Handling

    *   **Description:**
        1.  **`handle_exception`:** Within your Hanami actions, use the `handle_exception` method to gracefully handle exceptions.  This is Hanami's preferred way to manage errors within actions.  Map specific exception types to appropriate HTTP status codes and custom error responses.
        2.  **Secure Exposure:**  Carefully control what data is exposed to the view layer through Hanami's `expose` method.  Only expose the *minimum* necessary data.
        3.  **Authorization within Actions:** Implement authorization checks *within* your Hanami actions, *before* accessing any resources.  Don't rely solely on routing constraints.  Use Hanami's context (e.g., `request.env['warden'].user` if using Warden) to access the authenticated user.
        4. **Repository Pattern (Hanami::Repository):** Leverage Hanami's repository pattern (`Hanami::Repository`) to encapsulate data access logic.  This promotes consistency and makes it easier to implement authorization checks within the repository methods themselves.
        5. **Input Validation (Hanami::Validations):** Use Hanami's built-in validation system (`Hanami::Validations`) to validate all input received by your actions. Define validation rules for each input parameter. This is crucial for preventing various injection attacks.

    *   **Threats Mitigated:**
        *   **Information Disclosure (Severity: High):**  `handle_exception` prevents sensitive error details from leaking.
        *   **Insecure Direct Object References (IDOR) (Severity: High):**  Action-level authorization checks prevent IDOR.
        *   **Authorization Bypass (Severity: High):**  Action-level authorization.
        *   **Various Injection Attacks (Severity: High):** Input validation using `Hanami::Validations`.

    *   **Impact:**
        *   **Information Disclosure:** Risk reduced from High to Low.
        *   **IDOR:** Risk reduced from High to Low.
        *   **Authorization Bypass:** Risk reduced from High to Low.
        *   **Injection Attacks:** Risk reduced significantly, depending on the specific attack and validation rules.

    *   **Currently Implemented:** [**Example:** Basic `handle_exception` usage; some input validation.] *Replace with your project's details.*

    *   **Missing Implementation:** [**Example:** Comprehensive authorization checks are missing in some actions; repository pattern is not consistently used.] *Replace with your project's details.*


## Mitigation Strategy: [Secure Hanami View Layer Practices](./mitigation_strategies/secure_hanami_view_layer_practices.md)

*   **Mitigation Strategy:** Secure Hanami View Layer Practices

    *   **Description:**
        1.  **Hanami Auto-Escaping:** Be aware that Hanami's view layer (using `Hanami::View`) automatically escapes output by default. This is a core feature of the framework.
        2.  **`raw` Helper (with Extreme Caution):**  Use Hanami's `raw` helper *only* when absolutely necessary and *only* after *thoroughly* sanitizing the input using a separate, trusted sanitization library.  The `raw` helper bypasses Hanami's auto-escaping.
        3.  **Hanami View Helpers:**  Utilize Hanami's built-in view helpers (e.g., `form_for`, `link_to`, `image_tag`) whenever possible. These helpers are designed to generate secure HTML and handle escaping correctly.
        4. **Context-Specific Escaping (Hanami::View::Context):** If you need to render content in specific contexts (e.g., HTML attributes, JavaScript), use the appropriate escaping methods provided by Hanami or a dedicated sanitization library, understanding the context in which the data will be rendered.

    *   **Threats Mitigated:**
        *   **Cross-Site Scripting (XSS) (Severity: High):**  Hanami's auto-escaping and view helpers are the primary defense.

    *   **Impact:**
        *   **XSS:** Risk reduced from High to Low (with proper use of Hanami's features and careful use of `raw`).

    *   **Currently Implemented:** [**Example:** Auto-escaping is active; Hanami view helpers are used in most places.] *Replace with your project's details.*

    *   **Missing Implementation:** [**Example:** `raw` helper is used without proper sanitization in a few templates.] *Replace with your project's details.*


