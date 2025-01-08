# Attack Surface Analysis for drupal/core

## Attack Surface: [SQL Injection via Improper Database API Usage](./attack_surfaces/sql_injection_via_improper_database_api_usage.md)

*   **Description:**  Occurs when user-provided data is incorporated into SQL queries without proper sanitization or parameterization, allowing attackers to inject malicious SQL code.
    *   **How Core Contributes:** Drupal Core's Database API, while designed to prevent SQL injection, can be misused if developers don't properly sanitize user-provided data when building queries, especially when using `db_query()` with direct string concatenation or when constructing dynamic queries without sufficient care.
    *   **Example:** Using `db_query("SELECT * FROM users WHERE name = '" . $_GET['username'] . "'")` instead of using placeholders and arguments.
    *   **Impact:**  Allows attackers to read, modify, or delete arbitrary data in the database, potentially leading to complete compromise of the application and its data.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**  Always use Drupal's prepared statements and placeholders (e.g., `db_query('SELECT * FROM users WHERE name = :name', [':name' => $_GET['username']])`).
        *   **Developers:** Avoid direct string concatenation when building database queries with user input.
        *   **Developers:**  Utilize Drupal's Entity API for data manipulation where possible, as it provides built-in protection against SQL injection.

## Attack Surface: [Path Traversal via File Handling Vulnerabilities](./attack_surfaces/path_traversal_via_file_handling_vulnerabilities.md)

*   **Description:**  Allows attackers to access files and directories outside of the intended webroot by manipulating file paths provided as input.
    *   **How Core Contributes:** Vulnerabilities can arise in core modules or custom code that handles file uploads, downloads, or includes, if input validation and sanitization of file paths are insufficient.
    *   **Example:** A script that uses user-provided input to construct a file path without proper validation, like `include($_GET['file']);`, potentially allowing access to sensitive system files.
    *   **Impact:**  Can lead to information disclosure, access to sensitive configuration files, or even remote code execution if combined with other vulnerabilities.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**  Thoroughly validate and sanitize all user-provided file paths.
        *   **Developers:**  Use Drupal's file handling APIs (e.g., `file_save_data()`, `file_url()`) which provide built-in security measures.
        *   **Developers:**  Avoid directly including or accessing files based on user input without strict validation against a whitelist of allowed paths.

## Attack Surface: [Cross-Site Scripting (XSS) via Render Array Manipulation](./attack_surfaces/cross-site_scripting__xss__via_render_array_manipulation.md)

*   **Description:**  Occurs when vulnerabilities exist in how Drupal core processes and renders render arrays, allowing attackers to inject malicious scripts that execute in the victim's browser.
    *   **How Core Contributes:** Drupal's rendering system relies on render arrays to build HTML output. Incorrectly structured or manipulated render arrays, especially those containing user-provided data, can bypass sanitization and lead to XSS.
    *   **Example:**  A render array that directly includes unsanitized user input in a `#markup` property.
    *   **Impact:**  Allows attackers to execute arbitrary JavaScript in the context of the user's session, potentially leading to session hijacking, data theft, or defacement.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**  Always ensure proper escaping of user-provided data within render arrays, especially in `#markup`, `#plain_text`, and `#prefix`/`#suffix` properties.
        *   **Developers:** Utilize the `#type` and `#attributes` properties correctly to leverage Drupal's built-in sanitization for standard HTML elements.
        *   **Developers:** Be cautious when using custom render array callbacks and ensure they handle user input securely.

## Attack Surface: [Authentication Bypass via Logic Flaws](./attack_surfaces/authentication_bypass_via_logic_flaws.md)

*   **Description:**  Vulnerabilities in Drupal core's authentication or authorization logic that allow attackers to bypass security checks and gain unauthorized access.
    *   **How Core Contributes:**  Flaws in the core user management system, permission checking mechanisms, or session handling can create opportunities for authentication bypass.
    *   **Example:** A vulnerability in a core module's access checking function that can be manipulated to grant access to unauthorized users.
    *   **Impact:**  Allows attackers to gain access to sensitive data, modify configurations, or perform actions as another user or administrator.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**  Thoroughly review and test all custom access control logic and ensure it aligns with Drupal's permission system.
        *   **Drupal Security Team & Community:**  Vigilant security audits and timely patching of core vulnerabilities are crucial.
        *   **Administrators:** Keep Drupal core updated to the latest stable version to benefit from security fixes.

## Attack Surface: [Remote Code Execution (RCE) via Deserialization Vulnerabilities (Less Common in Core, More in Contrib/Custom)](./attack_surfaces/remote_code_execution__rce__via_deserialization_vulnerabilities__less_common_in_core__more_in_contri_6b658602.md)

*   **Description:**  Occurs when the application deserializes untrusted data, allowing attackers to inject malicious code that is then executed by the server.
    *   **How Core Contributes:** While less common directly in core due to security practices, vulnerabilities could potentially arise in specific core subsystems that handle serialization if not implemented with extreme care. This is more frequently a risk in contributed modules or custom code.
    *   **Example:**  Exploiting a vulnerability in a core caching mechanism that deserializes data without proper validation.
    *   **Impact:**  Allows attackers to execute arbitrary code on the server, leading to complete system compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**  Avoid deserializing untrusted data whenever possible.
        *   **Developers:**  If deserialization is necessary, use secure serialization formats and implement strict validation of the data being deserialized.
        *   **Drupal Security Team & Community:**  Vigilance in identifying and patching any potential deserialization vulnerabilities in core.

