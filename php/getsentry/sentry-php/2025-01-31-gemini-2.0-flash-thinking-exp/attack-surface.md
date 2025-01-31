# Attack Surface Analysis for getsentry/sentry-php

## Attack Surface: [Exposure of Sentry DSN (Data Source Name)](./attack_surfaces/exposure_of_sentry_dsn__data_source_name_.md)

*   **Description:** Accidental or intentional disclosure of the Sentry DSN, which contains sensitive project credentials required for `sentry-php` to communicate with the Sentry service.
*   **Sentry-PHP Contribution:** `sentry-php` *requires* the DSN to be configured for operation. The library's functionality directly depends on this secret, making its exposure a critical issue.
*   **Example:** Hardcoding the DSN directly into PHP code files that are then committed to a public version control repository. An attacker finds the DSN in the public repository.
*   **Impact:**  **Critical**. Full compromise of Sentry project data integrity and confidentiality. Attackers can send arbitrary error reports, potentially inject malicious data, pollute legitimate error tracking, and gain insights into project configuration. In some cases, depending on Sentry project settings and permissions, they might even be able to access existing error data.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Environment Variables (Mandatory):**  **Always** store the DSN as an environment variable, never hardcode it in application code or configuration files within the codebase.
    *   **Secure Configuration Management:** Utilize secure configuration management systems (e.g., HashiCorp Vault, AWS Secrets Manager) to manage and inject the DSN at runtime.
    *   **Strict Access Control:** Implement stringent access control to environments and systems where the DSN is configured and stored.
    *   **Secret Scanning and Prevention:** Employ automated secret scanning tools in CI/CD pipelines and developer workstations to prevent accidental DSN commits to version control.
    *   **Regular Security Audits:** Conduct regular security audits of codebase, configurations, and deployment processes to identify and remediate potential DSN exposure points.

## Attack Surface: [Data Leakage through Captured Error Data](./attack_surfaces/data_leakage_through_captured_error_data.md)

*   **Description:** `sentry-php`, by design, captures and transmits application data during error conditions. Misconfiguration or insufficient data scrubbing can lead to the unintentional leakage of sensitive information to the Sentry service.
*   **Sentry-PHP Contribution:** `sentry-php`'s core function is to capture and send error context.  The library's default behavior and configuration options directly influence what data is captured and transmitted. Inadequate default scrubbing or misconfigured scrubbing rules directly contribute to this attack surface.
*   **Example:** An application processes user credit card numbers. If an exception occurs while processing a transaction and the credit card number is present in the exception message, request parameters, or application state captured by `sentry-php` (and not properly scrubbed), this sensitive data will be sent to Sentry.
*   **Impact:** **High**. Exposure of Personally Identifiable Information (PII), financial data, API keys, passwords, or other confidential business data to individuals with access to the Sentry project. This can lead to privacy violations, compliance breaches (GDPR, PCI DSS, etc.), reputational damage, and potential legal repercussions.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Robust Data Scrubbing (Crucial):** Implement comprehensive data scrubbing rules within `sentry-php` configuration. Utilize Sentry's built-in data scrubbing features and define custom scrubbing rules to aggressively remove sensitive data patterns (e.g., credit card numbers, social security numbers, API keys, passwords, email addresses where appropriate).
    *   **Context Filtering and Minimization:**  Carefully configure the context data captured by `sentry-php`. Minimize the amount of context data collected to only what is strictly necessary for debugging. Avoid capturing entire request bodies or user sessions by default.
    *   **Error Message Sanitization:** Train developers to write error messages that are informative for debugging but avoid including sensitive data directly in the message itself.
    *   **Regular Review of Scrubbing Rules:** Periodically review and update data scrubbing rules to ensure they remain effective and cover newly identified sensitive data patterns.
    *   **Principle of Least Privilege (Sentry Access):** Restrict access to the Sentry project to only authorized personnel who require access for legitimate error monitoring and debugging purposes.

