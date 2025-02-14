# Mitigation Strategies Analysis for drupal/core

## Mitigation Strategy: [Leverage Drupal's Form API and Render API Rigorously](./mitigation_strategies/leverage_drupal's_form_api_and_render_api_rigorously.md)

*   **Mitigation Strategy:** Utilize Drupal's Form API and Render API for all form building and content output.

*   **Description:**
    1.  **Form Building (Form API):**  Use the Form API's structured arrays (`#type`, `#title`, `#required`, etc.) for *all* form creation. Avoid manual HTML construction.
    2.  **Form Processing (Form API):** Employ Form API validation (`#element_validate`) and submit handlers. Sanitize input within these handlers using Drupal core functions like `\Drupal\Component\Utility\Html::escape()` and `\Drupal\Component\Utility\Xss::filter()`.
    3.  **Output Rendering (Render API):** Use render arrays for *all* content output. Define output structure with keys like `#markup`, `#theme`, `#allowed_tags`. Avoid direct HTML printing.
    4.  **Twig Templates (Core Integration):** Within Twig templates, use Drupal core's functions and filters (e.g., `{{ content.field_name }}`, `{{ url('route_name') }}`).  Minimize use of the `|raw` filter, and only after *verifying* input safety.

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) - Severity: High:** Prevents injection of malicious JavaScript.
    *   **HTML Injection - Severity: High:** Prevents injection of arbitrary HTML.
    *   **Other Injection Attacks - Severity: Medium:** Reduces risk by enforcing proper escaping.

*   **Impact:**
    *   **XSS:** Risk significantly reduced (near elimination with correct implementation).
    *   **HTML Injection:** Risk significantly reduced (near elimination with correct implementation).
    *   **Other Injection Attacks:** Risk moderately reduced.

*   **Currently Implemented:**
    *   Core `user` module forms (login, registration) use the Form API.
    *   Core `node` module content display uses the Render API.
    *   Basic Twig templates use core functions.

*   **Missing Implementation:** (Examples - would be specific to your project)
    *   *Any* custom module or theme that manually constructs HTML forms or outputs content without using the Form API or Render API.

## Mitigation Strategy: [Utilize Drupal's Text Formats and Filters (Core System)](./mitigation_strategies/utilize_drupal's_text_formats_and_filters__core_system_.md)

*   **Mitigation Strategy:** Configure and enforce appropriate text formats and filters for user-generated content *using Drupal's core system*.

*   **Description:**
    1.  **Access Core Configuration:** Use the Drupal admin interface (`Configuration > Content authoring > Text formats and editors`).
    2.  **Restrict "Full HTML":**  Assign "Full HTML" *only* to trusted administrator roles.
    3.  **Configure "Restricted/Basic HTML":** Customize these core formats to allow *only* a safe subset of HTML tags and attributes. Disallow dangerous tags (`<script>`, `<object>`, etc.) and attributes (`onload`, `onerror`).
    4.  **Assign Formats to Fields (Core Functionality):** When creating content types and fields, assign the appropriate *core* text format to each field.
    5.  **Regular Review (Within Core):** Periodically review and update the *core* text format configurations.

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) - Severity: High:** Limits malicious JavaScript injection.
    *   **HTML Injection - Severity: High:** Restricts allowed HTML.
    *   **Malicious File Uploads (Indirectly) - Severity: Medium:** Prevents embedding of malicious files via restricted tags.

*   **Impact:**
    *   **XSS:** Risk significantly reduced.
    *   **HTML Injection:** Risk significantly reduced.
    *   **Malicious File Uploads:** Risk moderately reduced.

*   **Currently Implemented:**
    *   "Restricted HTML" is the default for core comment fields.
    *   "Basic HTML" is used for core body fields in "Article".
    *   "Full HTML" is restricted to the "Administrator" role.

*   **Missing Implementation:** (Examples - would be specific to your project)
    *   Any situation where a custom module or content type bypasses the core text format system.

## Mitigation Strategy: [Employ Drupal's `\Drupal\Component\Utility\Html::escape()` and Related Functions (Core Utility)](./mitigation_strategies/employ_drupal's__drupalcomponentutilityhtmlescape____and_related_functions__core_utility_.md)

*   **Mitigation Strategy:** Use Drupal *core's* helper functions for escaping when *absolutely necessary* to handle raw HTML outside of the Render API.

*   **Description:**
    1.  **Identify Risky Code:** Find code that directly manipulates HTML strings or outputs content outside the Render/Form APIs.
    2.  **Use `Html::escape()` (Core):** For general HTML escaping, use `\Drupal\Component\Utility\Html::escape()`.
    3.  **Use `Xss::filter()` (Core):** For more complex filtering with a limited set of allowed tags, use `\Drupal\Component\Utility\Xss::filter()`.
    4.  **Use `UrlHelper::filterBadProtocol()` (Core):** For URLs, use `\Drupal\Component\Utility\UrlHelper::filterBadProtocol()`.
    5.  **Context-Specific Escaping (Core Awareness):** Be mindful of the output context (HTML, attributes, JavaScript, CSS) and use the appropriate core escaping function.

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) - Severity: High:** Escapes special characters.
    *   **HTML Injection - Severity: High:** Sanitizes user input.
    *   **URL Manipulation - Severity: Medium:** Filters bad URL protocols.

*   **Impact:**
    *   **XSS:** Risk significantly reduced (when used correctly).
    *   **HTML Injection:** Risk significantly reduced (when used correctly).
    *   **URL Manipulation:** Risk moderately reduced.

*   **Currently Implemented:**
    *   Used in some core modules where direct HTML manipulation is unavoidable.

*   **Missing Implementation:** (Examples - would be specific to your project)
    *   Any custom code that directly outputs HTML without using these core functions *when the Render API cannot be used*.

## Mitigation Strategy: [Strict Adherence to Drupal's Permission System (Core)](./mitigation_strategies/strict_adherence_to_drupal's_permission_system__core_.md)

*   **Mitigation Strategy:** Define granular permissions and regularly audit user roles and permissions *using Drupal's core permission system*.

*   **Description:**
    1.  **Define Custom Permissions (Core API):** For custom modules, define specific permissions in the module's `.permissions.yml` file.  Use the `permission_callbacks` key for dynamic permissions.
    2.  **Assign Permissions to Roles (Core UI):** Use the Drupal core UI to create/modify user roles and assign the appropriate *core-defined* permissions.
    3.  **Regular Audit (Core UI):** Periodically review user roles and permissions *within the core UI*.
    4.  **Test Permissions (Core Functionality):** Test permission configurations using Drupal's user system.

*   **Threats Mitigated:**
    *   **Unauthorized Access - Severity: High:** Prevents unauthorized access.
    *   **Privilege Escalation - Severity: High:** Prevents gaining higher privileges.
    *   **Information Disclosure - Severity: Medium to High:** Prevents unauthorized viewing of information.

*   **Impact:**
    *   **Unauthorized Access:** Risk significantly reduced.
    *   **Privilege Escalation:** Risk significantly reduced.
    *   **Information Disclosure:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Basic permissions are defined for core modules.
    *   Core user roles ("Administrator," "Authenticated User") are configured.

*   **Missing Implementation:** (Examples - would be specific to your project)
    *   Custom modules that don't define permissions in `.permissions.yml` or rely on overly broad core permissions.

## Mitigation Strategy: [Use of Entity Access API (Core)](./mitigation_strategies/use_of_entity_access_api__core_.md)

*   **Mitigation Strategy:** *Always* use the core Entity Access API (`$entity->access()`) to check user permissions before entity operations.

*   **Description:**
    1.  **Identify Entity Operations:** Locate code interacting with core content entities (nodes, users, taxonomy terms, files).
    2.  **Use `$entity->access()` (Core API):** *Before* any operation (view, create, update, delete), use `$entity->access('operation_name')`.
    3.  **Handle Access Denied (Core Logic):** If `$entity->access()` returns `FALSE`, handle the denial appropriately (error message, redirect).
    4.  **Consider Access Control Handlers (Core Extension):** For complex logic, define custom *core* access control handlers for your entities.
    5.  **Do Not Bypass (Core Principle):** Never bypass the Entity Access API.

*   **Threats Mitigated:**
    *   **Unauthorized Access - Severity: High:** Prevents unauthorized entity access.
    *   **Privilege Escalation - Severity: High:** Prevents unauthorized operations.
    *   **Information Disclosure - Severity: Medium to High:** Prevents unauthorized viewing of entity data.

*   **Impact:**
    *   **Unauthorized Access:** Risk significantly reduced.
    *   **Privilege Escalation:** Risk significantly reduced.
    *   **Information Disclosure:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Used consistently in core modules (e.g., `node`, `user`).

*   **Missing Implementation:** (Examples - would be specific to your project)
    *   Any custom code that interacts with core entities without using `$entity->access()`.

## Mitigation Strategy: [Route Access Checks with _Custom_ Requirements (Core Routing)](./mitigation_strategies/route_access_checks_with__custom__requirements__core_routing_.md)

*   **Mitigation Strategy:** Use appropriate route access checks and define custom access checkers (within the core system) for complex logic.

*   **Description:**
    1.  **Review Route Definitions:** Examine `.routing.yml` files.
    2.  **Use Built-in Checks (Core):** For simple access, use core checks like `_permission`, `_role`, `_user_is_logged_in`.
    3.  **Define Custom Access Checkers (Core Services):** For complex logic, create custom access checkers as services implementing `\Drupal\Core\Routing\Access\AccessInterface`.
    4.  **Implement `access()` Method (Core Interface):** Implement the `access()` method to return an `\Drupal\Core\Access\AccessResult`.
    5.  **Reference in Route Definition (Core YAML):** Use the `_custom_access` key in `.routing.yml` to reference your custom checker.
    6.  **Test (Core Functionality):** Thoroughly test route access.

*   **Threats Mitigated:**
    *   **Unauthorized Access - Severity: High:** Prevents unauthorized route access.
    *   **Privilege Escalation - Severity: High:** Prevents accessing routes requiring higher privileges.

*   **Impact:**
    *   **Unauthorized Access:** Risk significantly reduced.
    *   **Privilege Escalation:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Basic checks (`_permission`, `_role`) are used in core.

*   **Missing Implementation:** (Examples - would be specific to your project)
    *   Custom modules that don't use appropriate core route access checks or don't define custom checkers when needed.

## Mitigation Strategy: [Validate File Uploads (Using Core File API)](./mitigation_strategies/validate_file_uploads__using_core_file_api_.md)

*   **Mitigation Strategy:** Rigorously validate all file uploads *using Drupal's core file validation system*.

*   **Description:**
    1.  **Use Drupal's File Validation (Core API):** When using the Form API, use the `#upload_validators` property.
    2.  **Check File Extension (Core Validation):** Validate against a whitelist of allowed extensions.
    3.  **Check MIME Type (Core Validation):** Use Drupal's `file_validate_mime_type()` function.
    4.  **Check File Size (Core Validation):** Use Drupal's `file_validate_size()` function.
    5.  **Rename Files (Core Functions):** Use Drupal's file system functions to generate unique file names.
    6.  **Restrict Access (Core File API):** Use Drupal's file access control.
    7. **Use Drupal's managed file system (Core API):** Use file field and related APIs.

*   **Threats Mitigated:**
    *   **Malicious File Upload - Severity: High:** Prevents malicious file execution.
    *   **Cross-Site Scripting (XSS) - Severity: High:** Prevents XSS via uploaded files.
    *   **Denial-of-Service (DoS) - Severity: Medium:** Prevents excessively large file uploads.

*   **Impact:**
    *   **Malicious File Upload:** Risk significantly reduced.
    *   **XSS:** Risk significantly reduced.
    *   **DoS:** Risk moderately reduced.

*   **Currently Implemented:**
    *   Basic extension and size validation in core.

*   **Missing Implementation:** (Examples - would be specific to your project)
    *   Custom modules that handle file uploads without using the core `#upload_validators` or related core functions.

