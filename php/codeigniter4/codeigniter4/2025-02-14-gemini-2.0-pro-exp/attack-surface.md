# Attack Surface Analysis for codeigniter4/codeigniter4

## Attack Surface: [.env File Exposure](./attack_surfaces/_env_file_exposure.md)

*   **Description:**  The `.env` file contains sensitive configuration data.  Direct exposure allows attackers to gain access to these secrets.
*   **How CodeIgniter 4 Contributes:** CI4 *recommends* using `.env` files for configuration, making proper handling essential. The framework relies on the developer/administrator to secure this file.
*   **Example:**  A misconfigured web server serves the `.env` file directly (e.g., `https://example.com/.env`).
*   **Impact:**  Complete compromise of the application and connected services.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Developer:**  Ensure `.env` is *never* committed to version control. Place `.env` *outside* the web root if possible.
    *   **System Administrator:**  Configure the web server to explicitly deny access to `.env` files. Consider server-level environment variables.

## Attack Surface: [CI_ENVIRONMENT Set to development in Production](./attack_surfaces/ci_environment_set_to_development_in_production.md)

*   **Description:**  Setting `CI_ENVIRONMENT` to `development` in production exposes detailed error messages and sensitive information.
*   **How CodeIgniter 4 Contributes:** CI4 uses `CI_ENVIRONMENT` to control error reporting and debugging behavior. The framework's behavior changes significantly based on this setting.
*   **Example:**  An attacker triggers an error, and the application displays a detailed stack trace revealing internal file paths.
*   **Impact:**  Information disclosure, aiding attackers in reconnaissance.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **Developer:**  Always set `CI_ENVIRONMENT` to `production` in the `.env` file on production servers.
    *   **System Administrator:**  Set `CI_ENVIRONMENT` at the server level to override application settings.

## Attack Surface: [Overly Permissive Routing](./attack_surfaces/overly_permissive_routing.md)

*   **Description:**  Broad route definitions (e.g., `(:any)`) without validation in the controller expose unintended functionality.
*   **How CodeIgniter 4 Contributes:** CI4's routing system is flexible, allowing for wildcard-based routes. This flexibility, if misused, creates vulnerabilities.
*   **Example:**  `$routes->get('admin/(:any)', 'Admin::$1');` without authentication allows access to any `Admin` controller method.
*   **Impact:**  Unauthorized access to sensitive functionality, potential privilege escalation.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **Developer:**  Define specific routes for each controller and method. Avoid wildcards. Use filters for authentication and authorization *before* controller execution.

## Attack Surface: [Unvalidated Controller Input (leading to SQLi)](./attack_surfaces/unvalidated_controller_input__leading_to_sqli_.md)

*   **Description:** Controller methods using unvalidated user data are vulnerable to SQL injection.
*   **How CodeIgniter 4 Contributes:** While CI4 provides tools (Query Builder, Validation library), it's the *developer's responsibility* to use them. The framework doesn't automatically prevent SQLi.
*   **Example:** `$builder->where("username = '" . $this->request->getPost('username') . "'");` bypasses escaping.
*   **Impact:** Database compromise, data theft, modification, or deletion.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Always use parameterized queries or the Query Builder's escaping: `$builder->where('username', $this->request->getPost('username'));`.

## Attack Surface: [Misconfigured File Uploads](./attack_surfaces/misconfigured_file_uploads.md)

*   **Description:**  Improper file upload handling allows attackers to upload malicious files (e.g., PHP scripts).
*   **How CodeIgniter 4 Contributes:** CI4 provides the `UploadedFile` class and Validation, but incorrect usage leads to vulnerabilities. The framework doesn't inherently prevent all upload attacks.
*   **Example:**  Allowing uploads without validating file types, enabling execution of uploaded PHP scripts.
*   **Impact:**  Remote code execution (RCE), complete server compromise.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Developer:**  Use CI4's Validation to strictly validate file types (MIME types), sizes, and names. Store uploads *outside* the web root. Rename files. Prevent direct execution of uploaded files.
    * **System Administrator:** Configure webserver to not execute scripts in upload directory.

## Attack Surface: [Database Query Builder Misuse (leading to SQLi)](./attack_surfaces/database_query_builder_misuse__leading_to_sqli_.md)

*   **Description:**  Incorrect use of the Query Builder (e.g., concatenating user input) can still lead to SQLi.
*   **How CodeIgniter 4 Contributes:** The Query Builder is designed to be secure, but it relies on the developer using it *correctly*.
*   **Example:**  Directly concatenating user input into a `where` clause.
*   **Impact:**  Database compromise, data theft, modification, or deletion.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Developer:**  Always use parameterized queries or the Query Builder's built-in escaping mechanisms.

## Attack Surface: [Auto-routing (Legacy) enabled](./attack_surfaces/auto-routing__legacy__enabled.md)

*   **Description:** Auto-routing automatically maps URL segments to controller methods, potentially exposing unintended methods.
*   **How CodeIgniter 4 Contributes:** CI4 *has* this feature (though it's legacy and disabled by default). Enabling it creates a direct risk.
*   **Example:** `/MyController/privateMethod` might directly call `privateMethod`.
*   **Impact:** Unauthorized access to controller methods.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Disable auto-routing. Explicitly define routes in `app/Config/Routes.php`.

