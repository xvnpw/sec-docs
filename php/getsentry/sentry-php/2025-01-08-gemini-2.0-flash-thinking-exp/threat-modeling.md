# Threat Model Analysis for getsentry/sentry-php

## Threat: [Accidental Capture of Sensitive Data in Error Reports](./threats/accidental_capture_of_sensitive_data_in_error_reports.md)

* **Threat:** Accidental Capture of Sensitive Data in Error Reports
    * **Description:** An attacker gaining access to the Sentry project (through compromised credentials or insider access) could view sensitive data like passwords, API keys, or personally identifiable information (PII) that was unintentionally included in error reports due to insufficient data scrubbing during Sentry-PHP configuration. This directly involves how Sentry-PHP captures and transmits data.
    * **Impact:** Exposure of sensitive credentials could lead to account compromise or unauthorized access to other systems. Exposure of PII could result in privacy violations and legal repercussions.
    * **Affected Component:**  `EventHandler` (specifically the data capturing logic within event processors and the `before_send` hook if not properly implemented).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Implement robust data scrubbing using Sentry-PHP's configuration options (e.g., `options.data_scrubbing.fields`).
        * Utilize the `before_send` hook to inspect and modify event data before it is sent to Sentry, ensuring sensitive information is removed or masked.
        * Educate developers on the importance of avoiding logging sensitive data in the application.
        * Regularly review the data being captured by Sentry to identify and address any unintentional data leaks.

## Threat: [Exposure of the DSN (Data Source Name)](./threats/exposure_of_the_dsn__data_source_name_.md)

* **Threat:** Exposure of the DSN (Data Source Name)
    * **Description:** An attacker discovering the DSN (which contains the project's public and secret keys) could use it to send malicious or fabricated error reports to the Sentry project, potentially polluting the error data, causing confusion, or masking genuine issues. The DSN is a core configuration element of Sentry-PHP.
    * **Impact:**  Pollution of error data makes it difficult to identify and resolve real issues. Malicious reports could be used to test for vulnerabilities or cause confusion.
    * **Affected Component:** `Client` (the component responsible for sending events to Sentry, which uses the DSN for authentication).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Store the DSN securely, preferably in environment variables or a dedicated configuration file with restricted access.
        * Avoid hardcoding the DSN directly in application code, especially in client-side scripts.
        * Implement proper access controls on configuration files and environment variable storage.
        * Regularly rotate Sentry project keys if a compromise is suspected.
        * Consider using server-side only initialization of Sentry where feasible.

