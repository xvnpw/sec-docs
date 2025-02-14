# Threat Model Analysis for filp/whoops

## Threat: [Sensitive Data Exposure via Request Parameters](./threats/sensitive_data_exposure_via_request_parameters.md)

*   **Description:** An attacker intentionally crafts malicious requests, or intercepts legitimate requests, to include sensitive data (e.g., session tokens, API keys, passwords) in URL parameters or POST data.  If an error occurs, `whoops` *directly* displays these parameters in the error report. The attacker triggers an error to view the `whoops` output.
*   **Impact:**
    *   **Critical:** Account takeover, unauthorized API access, data breaches, session hijacking.
*   **Whoops Component Affected:**
    *   `PrettyPageHandler`: The main handler rendering the error page.
    *   Specifically, methods collecting and displaying request data: `getRequestData()`, and related functions for GET, POST, Cookie, and Header information.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Production Disable:**  Completely disable `whoops` in production. This is the *primary* mitigation.
    *   **Request Parameter Blacklisting/Whitelisting:** Configure `whoops` to filter sensitive parameters. Use a whitelist (preferred) or blacklist. Example: `handler->blacklist('request', ['password', 'token', 'api_key']);` (Syntax may vary).
    *   **Never Pass Sensitive Data in GET Requests:** Enforce a policy against passing sensitive information in URL parameters.

## Threat: [Source Code Disclosure](./threats/source_code_disclosure.md)

*   **Description:** An attacker triggers an error, causing `whoops` to *directly* display source code snippets. The attacker examines these snippets to understand application logic, file structure, and potential vulnerabilities.
*   **Impact:**
    *   **High:** Facilitates further attacks by revealing application logic, potential vulnerabilities, and internal file paths. May expose comments with sensitive information.
*   **Whoops Component Affected:**
    *   `PrettyPageHandler`: Code rendering the stack trace and source code snippets.
    *   `Frame`: Represents a stack trace frame and contains the source code snippet. `getFileContents()` and related methods are relevant.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Production Disable:** Completely disable `whoops` in production.
    *   **Remove Sensitive Comments:** Ensure source code comments do not contain sensitive information.

## Threat: [Environment Variable Leakage](./threats/environment_variable_leakage.md)

*   **Description:** An attacker triggers an error, and `whoops`, if configured to do so, *directly* displays the server's environment variables, potentially revealing database credentials, API keys, or secret keys.
*   **Impact:**
    *   **Critical:** Can lead to complete system compromise, database access, and unauthorized access to external services.
*   **Whoops Component Affected:**
    *   `PrettyPageHandler`: The section displaying environment variables.
    *   `Inspector`: Collects information about the environment.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Production Disable:** Completely disable `whoops` in production.
    *   **Environment Variable Filtering:** Configure `whoops` to *never* display environment variables, or blacklist sensitive ones. Example: `handler->blacklist('env', '*');` (to blacklist all).

## Threat: [Misconfiguration Leading to Exposure in Production](./threats/misconfiguration_leading_to_exposure_in_production.md)

*   **Description:** A developer accidentally leaves `whoops` enabled in production due to incorrect settings, a misconfigured deployment, or failure to test the production configuration. This makes all other `whoops` threats active in production.
*   **Impact:**
    *   **Critical:** Exposes all information discussed in previous threats (sensitive data, source code, environment variables) to any user who triggers an error.
*   **Whoops Component Affected:**
    *   The entire `whoops` library.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Automated Deployment Checks:** Implement checks in the CI/CD pipeline to verify `whoops` is disabled in production builds.
    *   **Configuration Management:** Use a robust system for consistent settings across environments.
    *   **Testing in Production-Like Environment:** Thoroughly test in a staging environment mirroring production.
    *   **Code Reviews:** Include checks for `whoops` configuration in code reviews.
    *   **Documentation and Training:** Ensure developers understand the risks.

