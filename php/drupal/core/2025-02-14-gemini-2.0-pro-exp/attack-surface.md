# Attack Surface Analysis for drupal/core

## Attack Surface: [1. Database Abstraction Layer (DBAL) Bypassing](./attack_surfaces/1__database_abstraction_layer__dbal__bypassing.md)

*   *Description:*  Improper use of dynamic SQL queries, bypassing the protection offered by Drupal's DBAL, leading to SQL injection.
    *   *Core Contribution:* While Drupal's DBAL *aims* to prevent SQL injection, the core `db_query()` function, *if misused*, allows developers to execute raw SQL, potentially including unsanitized user input.  This is a direct core function that, while discouraged for general use, presents a direct pathway to SQLi if not handled with extreme care.  The *existence* of this function, and its potential for misuse, is the core contribution.
    *   *Example:* A developer uses `db_query("SELECT * FROM users WHERE name = '" . $_GET['name'] . "'")` instead of using the query builder or placeholders.
    *   *Impact:*  SQL injection, leading to data leakage, modification, deletion, or even complete database compromise.
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   **Developer:**  *Never* use direct string concatenation within SQL queries passed to `db_query()`.  *Always* use the query builder API (`db_select()`, `db_insert()`, `db_update()`, `db_delete()`) for constructing queries. If `db_query()` *must* be used, employ placeholders (`:placeholder`) and ensure *all* values are properly escaped using the database connection's escaping function.  Code reviews *must* flag any use of `db_query()` for close scrutiny.
        *   **User/Admin:**  No direct mitigation at the user/admin level *for this specific core issue*, as it's a development-level vulnerability.  Rely on developers to follow best practices.

## Attack Surface: [2. Entity Access Bypass (Core Access Control Mechanisms)](./attack_surfaces/2__entity_access_bypass__core_access_control_mechanisms_.md)

*   *Description:*  Unauthorized access to entities due to flaws in *core* access control logic or misconfiguration of *core* access control features.
    *   *Core Contribution:* Drupal core provides the fundamental entity access system (permissions, roles, node access grants).  Vulnerabilities can arise from bugs within *core's* implementation of these features, or from misconfigurations of *core* settings by site administrators. This is distinct from custom module access bypasses.  The core's complexity and the potential for misconfiguration of its built-in features are the key contributions.
    *   *Example:* A bug in Drupal core's node access grant system allows users with a specific role combination to bypass intended access restrictions. Or, a site administrator incorrectly configures the "Administer permissions" permission, granting it to an untrusted role.
    *   *Impact:*  Data leakage, unauthorized modification or deletion of content, privilege escalation.
    *   *Risk Severity:* **High to Critical** (depending on the sensitivity of the exposed data and the nature of the bypass).
    *   *Mitigation Strategies:*
        *   **Developer:**  When extending core access control, thoroughly understand the core mechanisms and ensure custom logic integrates correctly *without* bypassing core checks.  Rely on core's access checking functions (e.g., `$entity->access()`).
        *   **User/Admin:**  Regularly review and audit user roles and permissions, paying *very close attention* to core permissions.  Carefully configure node access modules provided by core.  Understand the implications of different access control settings.  Apply security updates promptly, as they often address core access control issues.  Limit the number of users with administrative privileges.

## Attack Surface: [3. REST/JSON:API Misconfiguration (Core Modules)](./attack_surfaces/3__restjsonapi_misconfiguration__core_modules_.md)

*   *Description:*  Unauthorized access to data or functionality exposed via Drupal's *core* RESTful Web Services or JSON:API modules due to misconfiguration.
    *   *Core Contribution:* These are *core* modules that, when enabled, expose Drupal entities and data via APIs.  The vulnerability arises from misconfiguration of *core's* settings for these modules, or from bugs within the *core* modules themselves.  The core modules' existence and their default configurations (which may not be secure in all contexts) are the key contributions.
    *   *Example:*  The core REST API is enabled without proper authentication or authorization, allowing anonymous users to access user data or create content via API calls.  A core REST resource exposes sensitive fields without proper access control checks *within the core module*.
    *   *Impact:*  Data leakage, unauthorized modification or deletion of data, denial of service.
    *   *Risk Severity:* **High to Critical** (depending on the exposed data and functionality).
    *   *Mitigation Strategies:*
        *   **Developer:**  If extending these core modules, ensure custom resources implement proper access control and validation, adhering to core's security guidelines.
        *   **User/Admin:**  *Disable* the core REST and JSON:API modules if they are not *absolutely* needed.  If they *are* needed, *carefully* review and configure their settings, ensuring that *only* authorized users have access to the necessary resources.  Implement authentication mechanisms (e.g., OAuth, Basic Auth, API keys) for *all* API endpoints provided by these core modules.  Regularly audit API access logs. Apply security updates promptly.

## Attack Surface: [4. File System Vulnerabilities (Core Stream Wrappers and Permissions)](./attack_surfaces/4__file_system_vulnerabilities__core_stream_wrappers_and_permissions_.md)

*   *Description:* Exploitation of insecure file handling practices or misconfigured file permissions, specifically related to core's file system handling.
    *   *Core Contribution:* Drupal core defines the stream wrappers (`public://`, `private://`, `temporary://`) and provides the fundamental file handling functions. Vulnerabilities can arise from bugs in *core's* implementation of these features, or from misconfiguration of *core* file system permissions (e.g., the `sites/default/files` directory). The core's file system abstraction and the default permission settings are the key contributions.
    *   *Example:* A vulnerability in core's handling of `private://` files allows unauthorized access to files stored in the private file system. Or, the `sites/default/files` directory, as managed by core, has overly permissive write permissions set by the site administrator, allowing an attacker to modify existing files.
    *   *Impact:* File disclosure, file modification, denial of service, and potentially remote code execution (if executable files can be uploaded and executed).
    *   *Risk Severity:* **High to Critical**
    *   *Mitigation Strategies:*
        *   **Developer:** When working with files, use Drupal's file API functions (e.g., `file_save_upload()`, `file_managed_file_save_upload()`) and adhere to secure coding practices for file handling.
        *   **User/Admin:** Ensure that Drupal's *recommended* file system permissions are *correctly* configured, paying *very close attention* to the permissions of the `sites/default/files` directory and its subdirectories. Regularly review file upload settings and restrict allowed file types *within Drupal's core configuration*. Use a separate, secured directory for private files (`private://`) and ensure its permissions are correctly set. Apply security updates promptly.

