# Attack Surface Analysis for bettererrors/better_errors

## Attack Surface: [Source Code Disclosure](./attack_surfaces/source_code_disclosure.md)

*   **Description:** Exposure of the application's underlying source code to unauthorized users.
    *   **How `better_errors` Contributes:** Displays code snippets directly in the browser when an error occurs.
    *   **Example:** An error in a database query displays the SQL query, including table and column names, and potentially the `WHERE` clause logic.
    *   **Impact:** Attackers gain insight into application logic, database structure, authentication mechanisms, and potential vulnerabilities.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Development:** Ensure `better_errors` is *only* in the `development` group in your Gemfile. Use conditional loading based on environment variables (e.g., `RAILS_ENV`).
        *   **Deployment:** Double-check deployment scripts to prevent accidental inclusion in production builds. Automate this check.
        *   **Operations:** Regularly audit deployed environments to confirm `better_errors` is not present.

## Attack Surface: [Sensitive Data Exposure (via Local Variables)](./attack_surfaces/sensitive_data_exposure__via_local_variables_.md)

*   **Description:** Revelation of sensitive data stored in local variables at the point of an error.
    *   **How `better_errors` Contributes:** Allows inspection of local variable values within the error context.
    *   **Example:** An error during user authentication displays the (potentially unhashed) password entered by the user, or a session token.
    *   **Impact:** Direct exposure of user credentials, session data, API keys, or other confidential information.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Development:** Avoid storing sensitive data directly in local variables, especially in error-prone code. Use secure storage mechanisms. Sanitize or redact sensitive data before storing it in variables.
        *   **Deployment:** Prevent deployment of `better_errors` to production.

## Attack Surface: [Remote Code Execution (RCE)](./attack_surfaces/remote_code_execution__rce_.md)

*   **Description:** Ability for an attacker to execute arbitrary code on the server.
    *   **How `better_errors` Contributes:** Provides a web-based REPL (Ruby console) allowing code execution in the error context.
    *   **Example:** An attacker triggers an error and uses the REPL to execute `system('rm -rf /')` or to access and exfiltrate data from the database.
    *   **Impact:** Complete server compromise, data theft, data destruction, and potential lateral movement within the network.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Development:** Never deploy `better_errors` to production. The REPL functionality is inherently dangerous.
        *   **Deployment:** Prevent deployment of `better_errors` to production.

## Attack Surface: [Environment Variable Exposure (Indirect)](./attack_surfaces/environment_variable_exposure__indirect_.md)

*   **Description:** Indirect exposure of environment variables through their use in code displayed by `better_errors`.
    *   **How `better_errors` Contributes:** If environment variables are used in code that triggers an error, their values *might* be revealed through variable inspection or code snippets.
    *   **Example:** An error in a database connection routine displays the database connection string, which was read from an environment variable.
    *   **Impact:** Exposure of sensitive credentials (database passwords, API keys, secret keys), leading to potential system compromise.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Development:** Avoid directly embedding environment variables in code where they might be exposed. Use configuration objects or helper methods. Never hardcode sensitive values.
        *   **Deployment:** Never deploy `better_errors` to production.

## Attack Surface: [HTTP Request Data Exposure](./attack_surfaces/http_request_data_exposure.md)

*   **Description:** Disclosure of details about the incoming HTTP request that triggered the error.
    *   **How `better_errors` Contributes:** Displays request headers, parameters, and cookies.
    *   **Example:** An error during a form submission displays the submitted form data (potentially including sensitive user input) and the user's cookies (potentially including session IDs).
    *   **Impact:** Exposure of user input, session tokens, and other potentially sensitive data transmitted in the request.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Development:** Never deploy `better_errors` to production.  Be mindful of what data is included in HTTP requests and consider using HTTPS to encrypt the entire communication.
        * **Development:** If you need to inspect request data in development, consider redacting or masking sensitive information before displaying it.

