# Attack Surface Analysis for google/sanitizers

## Attack Surface: [Performance Degradation and Denial of Service (DoS)](./attack_surfaces/performance_degradation_and_denial_of_service__dos_.md)

*   **Description:**  Malicious or unintentional exploitation of the significant performance overhead introduced by sanitizers, leading to application slowdown or complete unavailability in production environments.
*   **How Sanitizers Contribute to Attack Surface:** Sanitizers instrument code with extensive runtime checks, dramatically increasing CPU and memory usage.  If accidentally or maliciously enabled in production, this overhead becomes a direct attack vector.
*   **Example:** AddressSanitizer is unintentionally left enabled in a production web application. An attacker sends a flood of requests. The increased processing time per request due to sanitizer checks exhausts server resources, causing the application to become unresponsive and deny service to legitimate users.
*   **Impact:** Application unavailability, service disruption, financial loss, reputational damage, complete system outage.
*   **Risk Severity:** **High** (when sanitizers are unintentionally enabled in production environments).
*   **Mitigation Strategies:**
    *   **Absolutely disable sanitizers in production builds.** Employ strict build configurations and pipelines to ensure sanitizer runtime libraries are excluded from production deployments.
    *   **Implement robust build verification processes** to prevent accidental inclusion of sanitizer components in production.
    *   **Performance test production-like deployments *without* sanitizers** to establish baseline performance and detect unexpected slowdowns that might indicate accidental sanitizer activation.
    *   **Monitor production application performance closely** and set up alerts for significant performance degradation, which could signal unintentional sanitizer activation or DoS attempts.

## Attack Surface: [Information Disclosure through Sanitizer Error Messages in Production](./attack_surfaces/information_disclosure_through_sanitizer_error_messages_in_production.md)

*   **Description:** Sensitive internal application details, including code structure, memory layout, and potential vulnerabilities, are leaked through verbose sanitizer error messages exposed in production environments.
*   **How Sanitizers Contribute to Attack Surface:** Sanitizers generate detailed error reports (stack traces, memory addresses, file paths, function names) upon detecting issues. If these reports are not properly managed and are exposed in production, they become a source of sensitive information leakage.
*   **Example:** A production application, mistakenly built with AddressSanitizer and verbose error logging, encounters a memory error. The detailed sanitizer error message, including stack traces revealing internal function names and code paths, is displayed to users through a generic error page or logged in publicly accessible logs.
*   **Impact:** Exposure of internal application architecture and potential vulnerabilities, aiding attackers in targeted attacks, potential compromise of sensitive data revealed in stack traces or memory dumps.
*   **Risk Severity:** **High** (if detailed sanitizer error messages are exposed in production environments and reveal sensitive application internals).
*   **Mitigation Strategies:**
    *   **Configure error reporting in production to be minimal and non-verbose.**  Prevent detailed error messages, especially sanitizer outputs, from being directly displayed to users or written to publicly accessible logs.
    *   **Implement custom error handling** to catch sanitizer errors and log only essential information securely, avoiding exposure of sensitive details in production logs.
    *   **Securely store error logs** and restrict access to authorized personnel only. Regularly review logs for any accidental information leakage.
    *   **Thoroughly test error handling in production-like environments** to ensure sensitive sanitizer outputs are not inadvertently exposed.

