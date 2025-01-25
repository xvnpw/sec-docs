# Mitigation Strategies Analysis for hanami/hanami

## Mitigation Strategy: [Principle of Least Privilege in Routing](./mitigation_strategies/principle_of_least_privilege_in_routing.md)

*   **Description:**
    1.  **Review all `config/routes.rb` definitions.**  Examine each route and action to ensure it is absolutely necessary and serves a legitimate business function within the Hanami application.
    2.  **Refine Hanami route paths to be as specific as possible.** Avoid using overly broad wildcards (e.g., `/*`) in Hanami routes unless absolutely necessary and carefully controlled.
    3.  **Remove or restrict access to Hanami routes that expose internal application logic or debugging endpoints** in production environments, ensuring only necessary Hanami endpoints are publicly accessible.
    4.  **Consider using Hanami namespaces and scopes** to further organize and restrict access to groups of related routes within the Hanami application.
*   **List of Threats Mitigated:**
    *   **Unauthorized Access (High Severity):** Prevents attackers from accessing unintended Hanami application functionalities or data due to overly permissive routes defined in `config/routes.rb`.
    *   **Information Disclosure (Medium Severity):** Reduces the risk of exposing internal Hanami application structure or logic through unnecessarily broad routes defined in Hanami's routing configuration.
*   **Impact:**
    *   **Unauthorized Access:** Significantly reduces risk by limiting accessible Hanami endpoints.
    *   **Information Disclosure:** Moderately reduces risk by obscuring internal Hanami structure through refined routing.
*   **Currently Implemented:** Partially implemented in `config/routes.rb`. Developers define Hanami routes, but a systematic review for least privilege in Hanami routing might be inconsistent.
*   **Missing Implementation:**  Regular Hanami route review process specifically for security, automated Hanami route analysis tools to identify overly permissive routes, and explicit documentation of Hanami route access control policies.

## Mitigation Strategy: [Input Validation in Controllers](./mitigation_strategies/input_validation_in_controllers.md)

*   **Description:**
    1.  **For each Hanami controller action, identify all incoming parameters.** This includes parameters from the Hanami route, query string, and request body processed by Hanami.
    2.  **Use Hanami's parameter validation features (e.g., `params.valid?`, `params[:attribute].required(:str)`) within Hanami controller actions.** Define expected data types, formats, and constraints for each parameter using Hanami's built-in validation mechanisms.
    3.  **Implement error handling for invalid parameters within Hanami controllers.** Return appropriate HTTP error codes (e.g., 400 Bad Request) and informative error messages to the client when Hanami parameter validation fails.
    4.  **Sanitize validated Hanami parameters before using them in application logic.**  While Hanami validation ensures data type and format, sanitization can further protect against injection attacks when processing data within Hanami controllers (e.g., escaping HTML entities).
*   **List of Threats Mitigated:**
    *   **Injection Attacks (SQL Injection, Command Injection, XSS - Medium to High Severity depending on context):** Prevents malicious code injection by ensuring input processed by Hanami controllers conforms to expected formats and is sanitized using Hanami's validation and sanitization practices.
    *   **Data Integrity Issues (Medium Severity):** Ensures data processed by the Hanami application via controllers is valid and consistent, preventing unexpected application behavior within the Hanami framework.
*   **Impact:**
    *   **Injection Attacks:** Significantly reduces risk by preventing malicious input from reaching vulnerable Hanami controller code.
    *   **Data Integrity Issues:** Significantly reduces risk by ensuring data validity within Hanami application flow.
*   **Currently Implemented:** Partially implemented in Hanami controllers. Developers often use Hanami parameter validation, but consistency and thoroughness can vary across actions and controllers within the Hanami application.
*   **Missing Implementation:**  Centralized Hanami parameter validation logic reusable across controllers, automated parameter validation testing specifically for Hanami controllers, and clear guidelines for input validation in Hanami development standards.

## Mitigation Strategy: [Avoid Dynamic Template Paths from User Input](./mitigation_strategies/avoid_dynamic_template_paths_from_user_input.md)

*   **Description:**
    1.  **Review all code that handles template rendering in your Hanami application views.** Identify any instances where Hanami template paths are constructed dynamically based on user input.
    2.  **Refactor code to avoid dynamic Hanami template path construction.** Hardcode Hanami template paths or use a safe mapping mechanism within Hanami views to select templates based on predefined criteria.
    3.  **If dynamic Hanami template selection is absolutely necessary, strictly validate and sanitize user input used to select templates.** Ensure input only allows predefined, safe Hanami template names and prevent path traversal attacks within the Hanami view rendering process.
*   **List of Threats Mitigated:**
    *   **Template Injection (High Severity):** Prevents attackers from injecting arbitrary code into Hanami templates by controlling template paths within the Hanami view rendering system.
    *   **Local File Inclusion (LFI) (Medium to High Severity):** Prevents attackers from including arbitrary local files if Hanami template paths can be manipulated to access files outside the intended Hanami template directory.
*   **Impact:**
    *   **Template Injection:** Significantly reduces risk by preventing control over Hanami template execution.
    *   **Local File Inclusion (LFI):** Significantly reduces risk by preventing access to arbitrary local files through Hanami template manipulation.
*   **Currently Implemented:** Likely implemented by default as dynamic Hanami template paths based on user input are not a common Hanami pattern. However, vigilance is needed to prevent accidental introduction in Hanami views.
*   **Missing Implementation:**  Code review process specifically looking for dynamic Hanami template path construction in views, and developer training to avoid this pattern in Hanami view development.

## Mitigation Strategy: [Use Hanami's ORM Features Securely](./mitigation_strategies/use_hanami's_orm_features_securely.md)

*   **Description:**
    1.  **Utilize Hanami's ORM query builder methods (e.g., `where`, `and`, `or`, `set`) to construct database queries within Hanami repositories.** Avoid string interpolation or concatenation when building queries with user-provided data in Hanami ORM interactions.
    2.  **Leverage parameterized queries provided by Hanami's ORM.** Ensure that user input is passed as parameters to Hanami ORM queries rather than directly embedded in the SQL string when using Hanami's persistence layer.
    3.  **Review all database interactions in your Hanami application code, especially within repositories.** Identify any instances of raw SQL queries or insecure Hanami ORM usage and refactor them to use secure Hanami ORM features.
*   **List of Threats Mitigated:**
    *   **SQL Injection (High Severity):** Prevents SQL injection vulnerabilities by ensuring user input is properly parameterized and not directly interpreted as SQL code when using Hanami's ORM.
*   **Impact:**
    *   **SQL Injection:** Significantly reduces risk by preventing malicious SQL code injection through secure Hanami ORM usage.
*   **Currently Implemented:** Partially implemented. Developers generally use Hanami ORM features, but raw SQL queries or insecure Hanami ORM usage might exist in some parts of the application, especially for complex queries or legacy code within Hanami repositories.
*   **Missing Implementation:**  Code review process focused on secure Hanami ORM usage, automated SQL injection vulnerability scanning specifically for Hanami ORM queries, and developer training on secure database interaction practices using Hanami's ORM.

## Mitigation Strategy: [Secure Default Configurations](./mitigation_strategies/secure_default_configurations.md)

*   **Description:**
    1.  **Review Hanami's default configurations and identify any settings that might have security implications for your Hanami application.** Refer to Hanami documentation for default configuration details.
    2.  **Adjust Hanami default configurations to enhance security, such as setting secure defaults for cookies and sessions within the Hanami framework, and configuring Hanami logging securely.**
    3.  **Document all Hanami configuration changes made for security purposes.** Keep track of modifications to Hanami's default settings.
    4.  **Regularly review and update Hanami configurations to maintain security best practices as the Hanami framework evolves.**
*   **List of Threats Mitigated:**
    *   **Misconfiguration Vulnerabilities (Medium Severity):** Prevents vulnerabilities arising from insecure Hanami default configurations.
    *   **Information Disclosure (Low to Medium Severity):** Reduces the risk of information disclosure through insecure Hanami logging or other misconfigurations within the Hanami framework.
*   **Impact:**
    *   **Misconfiguration Vulnerabilities:** Moderately reduces risk by hardening Hanami default configurations.
    *   **Information Disclosure:** Minimally to Moderately reduces risk by securing Hanami configuration settings.
*   **Currently Implemented:** Partially implemented. Some basic Hanami security configurations might be applied, but a comprehensive review and hardening of Hanami default configurations might be missing.
*   **Missing Implementation:**  Security audit of default Hanami configurations, documented secure Hanami configuration guidelines, and regular Hanami configuration review process.

