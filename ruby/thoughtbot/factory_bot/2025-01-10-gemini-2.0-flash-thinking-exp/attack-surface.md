# Attack Surface Analysis for thoughtbot/factory_bot

## Attack Surface: [Exposure of Sensitive Test Data](./attack_surfaces/exposure_of_sensitive_test_data.md)

* **Exposure of Sensitive Test Data**
    * Description:  Sensitive information used in test factories is unintentionally exposed.
    * How `factory_bot` Contributes: Factories are the source of the generated test data, including potentially sensitive information.
    * Example: A factory for creating user accounts hardcodes a default password like "password123" or uses real API keys for testing integrations. This data might end up in test logs, database dumps, or version control.
    * Impact: Compromise of credentials, exposure of personally identifiable information (PII), access to internal systems or third-party services via leaked API keys.
    * Risk Severity: High
    * Mitigation Strategies:
        * Avoid hardcoding sensitive data directly in factory definitions.
        * Utilize environment variables or secure configuration mechanisms to manage sensitive test data.
        * Employ data masking or anonymization techniques for sensitive fields in factories.
        * Regularly review factory definitions for inadvertently included sensitive information.
        * Ensure test logs and database backups are securely managed and not publicly accessible.

## Attack Surface: [Injection Vulnerabilities via Generated Data](./attack_surfaces/injection_vulnerabilities_via_generated_data.md)

* **Injection Vulnerabilities via Generated Data**
    * Description: Data generated by factories, when used in the application under test, triggers injection vulnerabilities.
    * How `factory_bot` Contributes: Factories create the input data that the application processes, and if this data contains malicious payloads, it can exploit vulnerabilities.
    * Example: A factory for creating blog posts generates a title containing a malicious JavaScript payload (`<script>alert('XSS')</script>`) that is not properly sanitized by the application, leading to a Cross-Site Scripting (XSS) vulnerability. Another example is a factory generating data that leads to SQL injection if the application doesn't use parameterized queries.
    * Impact:  Cross-site scripting (XSS), SQL injection, command injection, leading to data breaches, unauthorized access, or even remote code execution.
    * Risk Severity: Critical
    * Mitigation Strategies:
        * Ensure the application's input validation and sanitization mechanisms are robust and cover a wide range of potentially malicious inputs, including those generated by factories.
        * Employ parameterized queries or prepared statements to prevent SQL injection.
        * Utilize output encoding techniques to mitigate XSS vulnerabilities.
        * Regularly review factory definitions to ensure they don't generate data that could be easily exploited.

## Attack Surface: [Configuration and Secret Management in Factory Definitions](./attack_surfaces/configuration_and_secret_management_in_factory_definitions.md)

* **Configuration and Secret Management in Factory Definitions**
    * Description: Sensitive configuration details or secrets are directly embedded within factory definitions.
    * How `factory_bot` Contributes: Factories can be used to create objects that require configuration or secrets, and developers might mistakenly hardcode these values directly in the factory.
    * Example: A factory for creating an integration with a third-party service includes the API key directly as a string in the factory definition. This exposes the API key in the codebase.
    * Impact: Exposure of sensitive credentials, potential for unauthorized access to external services or internal resources.
    * Risk Severity: High
    * Mitigation Strategies:
        * Avoid hardcoding any secrets or sensitive configuration within factory definitions.
        * Utilize environment variables or secure configuration management tools to provide necessary configuration values to factories.
        * Employ techniques like `after(:build)` or `after(:create)` callbacks in factories to fetch or generate dynamic secrets when needed.

