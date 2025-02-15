# Threat Model Analysis for bettererrors/better_errors

## Threat: [Threat: Sensitive Information Exposure via Error Pages](./threats/threat_sensitive_information_exposure_via_error_pages.md)

*   **Description:** An attacker triggers an error in the application, causing `better_errors` to display its detailed error page.  This page contains sensitive information such as source code snippets, local variable values (potentially including secrets), request parameters, environment variables, and database queries. The attacker directly views this information within the `better_errors` interface.
*   **Impact:**
    *   Exposure of database credentials, API keys, internal IP addresses, server file paths, and other configuration details.
    *   Revelation of application logic, source code, and internal data structures.
    *   Facilitation of further attacks by providing the attacker with valuable reconnaissance information.
*   **Affected Component:**
    *   `BetterErrors::Middleware`: The main middleware that intercepts exceptions and renders the error page.
    *   `BetterErrors::ErrorPage`: The class responsible for generating the HTML error page content.
    *   Various template files (`.erb`) within `better_errors` that display specific information (e.g., stack trace, local variables, request details).
*   **Risk Severity:** Critical (in production), High (in improperly secured development/staging).
*   **Mitigation Strategies:**
    *   **Disable in Production:** Ensure `better_errors` is *only* included in the `development` group of the `Gemfile` and is *never* deployed to production.
    *   **IP Whitelisting:** Use `BetterErrors.allowed_ip_addresses` to restrict access to trusted IPs in development/staging.
    *   **Environment Variable Review:** Avoid storing sensitive data directly in environment variables. Use a secrets management solution.
    *   **Parameter Filtering:** Use Rails' parameter filtering to prevent sensitive data from appearing in request parameters displayed by `better_errors`.
    *   **Custom Error Handling:** Implement custom error handling for specific sensitive operations to prevent detailed information from leaking even in development.

## Threat: [Threat: Arbitrary Code Execution via REPL](./threats/threat_arbitrary_code_execution_via_repl.md)

*   **Description:** An attacker gains access to the `better_errors` error page and utilizes the built-in REPL to execute arbitrary Ruby code within the context of the running application.  This allows the attacker to directly interact with the application's internals, potentially modifying data, accessing the file system, or executing system commands.
*   **Impact:**
    *   Complete compromise of the application server.
    *   Data theft, modification, or destruction.
    *   Installation of malware or other malicious software.
    *   Potential for lateral movement to other systems.
*   **Affected Component:**
    *   `BetterErrors::Middleware`: Handles the routing to the REPL.
    *   `BetterErrors::REPL`: The class that implements the REPL functionality.
    *   `BetterErrors::StackFrame`: Provides access to the stack frame data used by the REPL.
    *   The `binding` object, which is made available within the REPL, providing access to the application's context.
*   **Risk Severity:** Critical (in production), High (in improperly secured development/staging).
*   **Mitigation Strategies:**
    *   **Disable in Production:** The REPL should *never* be accessible in a production environment.
    *   **Strict IP Whitelisting:** Use `BetterErrors.allowed_ip_addresses` to *very strictly* limit access to the REPL to only trusted development machines.
    *   **Authentication (If Necessary):** If IP whitelisting is insufficient, implement custom authentication (e.g., a middleware) to protect access to the `better_errors` routes, including the REPL.
    *   **Disable REPL Feature (If Possible):** Consider forking the gem and removing the REPL functionality for an extra layer of security if it's not essential.

## Threat: [Threat:  Information Disclosure via Variable Inspection](./threats/threat__information_disclosure_via_variable_inspection.md)

* **Description:** An attacker, with access to the `better_errors` interface, can inspect the values of local and instance variables displayed on the error page. This direct access to variable values can reveal sensitive data or internal application logic that happens to be stored in those variables at the point of the error.
* **Impact:**
    * Leakage of sensitive data present in local or instance variables.
    * Exposure of internal application logic and data structures.
    * Increased understanding of the application, aiding in further vulnerability discovery.
* **Affected Component:**
    * `BetterErrors::StackFrame`: Provides access to the local and instance variables.
    * `BetterErrors::ErrorPage`: Renders the variable values in the HTML output.
    * The template files (`.erb`) responsible for displaying the variable sections.
* **Risk Severity:** High (in improperly secured development/staging), Critical (if present in production).
* **Mitigation Strategies:**
    * **Disable in Production:** The primary mitigation.
    * **Code Review:** Regularly review code to ensure sensitive data is not inadvertently stored in variables that might be exposed.
    * **IP Whitelisting:** Restrict access to the `better_errors` interface.

