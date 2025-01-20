# Attack Surface Analysis for getsentry/sentry-php

## Attack Surface: [Exposed DSN (Data Source Name)](./attack_surfaces/exposed_dsn__data_source_name_.md)

*   **Description:** The DSN, containing the Sentry project's public and secret keys, is unintentionally revealed.
    *   **How Sentry-PHP Contributes:** The DSN is a crucial configuration parameter **required by `sentry-php`** to send error reports. If not handled securely, it can be exposed.
    *   **Example:** The DSN is hardcoded in a publicly accessible configuration file committed to a public repository or included in client-side JavaScript.
    *   **Impact:** Attackers can send arbitrary error reports to the Sentry project, potentially flooding it with noise, injecting malicious data, or associating malicious events with the legitimate project. This can hinder legitimate error tracking and potentially mask real issues.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   Securely store the DSN: Utilize environment variables, secure configuration management tools (like HashiCorp Vault), or key management systems. Avoid hardcoding the DSN in application code or publicly accessible files.
        *   Restrict access to configuration files: Implement proper access controls on configuration files to prevent unauthorized access.
        *   Regularly audit configuration: Review configuration settings to ensure the DSN is not inadvertently exposed.

## Attack Surface: [Logging of Sensitive Data](./attack_surfaces/logging_of_sensitive_data.md)

*   **Description:** Sensitive information (e.g., passwords, API keys, personal data) is unintentionally included in error reports sent to Sentry.
    *   **How Sentry-PHP Contributes:** `sentry-php` captures context data, including variables and request information, which might inadvertently contain sensitive data if not properly filtered.
    *   **Example:** An exception is thrown while processing user input containing a password, and the password variable is included in the captured context data sent to Sentry.
    *   **Impact:** Exposure of sensitive data within the Sentry project, potentially leading to data breaches, identity theft, or further attacks if the Sentry project is compromised.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   Sanitize and filter data: Implement mechanisms to sanitize and filter sensitive data before it's included in error reports. Use Sentry's data scrubbing features or custom data processors.
        *   Avoid capturing unnecessary context: Configure `sentry-php` to capture only the necessary context data. Be mindful of the default data capture settings.
        *   Regularly review captured data: Periodically review the data being sent to Sentry to identify and address any instances of sensitive data being logged.

