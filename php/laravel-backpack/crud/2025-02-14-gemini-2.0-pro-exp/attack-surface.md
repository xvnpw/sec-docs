# Attack Surface Analysis for laravel-backpack/crud

## Attack Surface: [Unauthorized CRUD Operations (Bypassing Permissions)](./attack_surfaces/unauthorized_crud_operations__bypassing_permissions_.md)

*Description:* Attackers gain access to create, read, update, or delete data they shouldn't be able to, circumventing the intended authorization system.
*How CRUD Contributes:* This is the *fundamental* attack surface of any CRUD system. Backpack's permission system, while built on Laravel's, is implemented through Backpack-specific configurations (CRUD controllers, setup methods, etc.). Misconfiguration of these Backpack-specific elements is the direct cause.
*Example:* An attacker modifies the URL from `/admin/products/1/edit` (which they can access) to `/admin/users/1/edit` (which they shouldn't), and successfully edits a user's details due to a missing or flawed policy check on the `User` model *within Backpack's controller logic*.
*Impact:* Data breaches, data modification, data deletion, privilege escalation.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Strict Policy/Gate Enforcement (Backpack-Specific):** Implement robust Laravel Policies or Gates for *every* CRUD operation on *every* model, specifically tailored to how Backpack interacts with these models. Ensure these policies are correctly referenced within Backpack's CRUD controllers.
    *   **Route Model Binding Validation (within Policies):** Use Laravel's route model binding, and *within the policy*, explicitly check if the *currently authenticated user* (as understood by Backpack) is allowed to access the bound model instance.
    *   **Explicit `setup()` Method Configuration:** Within each CRUD controller's `setup()` method (and related operation-specific setup methods like `setupCreateOperation()`, `setupUpdateOperation()`), explicitly define allowed fields, operations, and filters. *Never* rely on implicit defaults or assumptions. This is a *direct* Backpack configuration point.
    *   **Regular Audits of Backpack Configuration:** Regularly review and audit the Backpack-specific configuration (CRUD controllers, policies, routes) to ensure the permission system is functioning as intended and that no gaps have been introduced *specifically within Backpack's implementation*.

## Attack Surface: [File Upload Vulnerabilities (Malicious File Upload - via CRUD Fields)](./attack_surfaces/file_upload_vulnerabilities__malicious_file_upload_-_via_crud_fields_.md)

*Description:* Attackers upload malicious files (e.g., PHP scripts, executables) through Backpack's file upload fields, leading to remote code execution.
*How CRUD Contributes:* Backpack's `upload` and `upload_multiple` field types, *directly provided by the CRUD package*, are the entry point for this attack. The vulnerability arises from how Backpack handles these fields and their configuration.
*Example:* An attacker uses a Backpack CRUD form with an `upload` field to upload a file named `malicious.php` disguised as a `.jpg`. Insufficient server-side validation *within Backpack's handling of the uploaded file* allows the file to be saved and subsequently executed.
*Impact:* Remote code execution (RCE), complete server compromise.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Strict Server-Side File Type Validation (within Backpack's Logic):** *Never* rely on client-side validation or the file extension. Within the code that handles Backpack's `upload` field processing (likely in a custom request class or within the controller), use server-side libraries (e.g., PHP's `finfo`, a dedicated package) to determine the *actual* file type based on content. This validation must happen *before* Backpack saves the file.
    *   **File Name Sanitization (Backpack-Specific):** Within Backpack's file handling logic, sanitize uploaded file names to prevent directory traversal. Consider generating random file names and storing the original name separately, managed *by Backpack*.
    *   **Restricted Upload Directory (Configured for Backpack):** Configure Backpack (through its configuration files or within the CRUD controller) to upload files to a directory outside the web root, if possible. If not, configure the web server to *deny* execution of files within the Backpack-configured upload directory.
    *   **File Size Limits (Enforced by Backpack):** Enforce strict file size limits *within Backpack's configuration or controller logic* to prevent denial-of-service.

## Attack Surface: [Custom Action Vulnerabilities (Unauthorized Action Execution - via CRUD Buttons)](./attack_surfaces/custom_action_vulnerabilities__unauthorized_action_execution_-_via_crud_buttons_.md)

*Description:* Attackers trigger custom actions (defined through Backpack buttons) that they are not authorized to execute, leading to unintended consequences.
*How CRUD Contributes:* Backpack's button and action system, a *core feature of the CRUD interface*, is the direct mechanism for this attack. The vulnerability stems from insufficient authorization checks *within the actions triggered by these Backpack buttons*.
*Example:* A custom Backpack button labeled "Approve Order" is added to a CRUD list view. An attacker, who shouldn't have approval rights, discovers the route associated with this button (e.g., `/admin/orders/1/approve`) and directly accesses it, bypassing the button's visibility checks and successfully approving the order due to a missing authorization check *within the action's code*.
*Impact:* Data modification, data loss, denial of service, privilege escalation (depending on the action).
*Risk Severity:* **High** (can be Critical depending on the action)
*Mitigation Strategies:*
    *   **Explicit Authorization Checks (within Action Logic):** *Every* custom action triggered by a Backpack button *must* have its own explicit authorization checks, completely independent of the main CRUD operations and button visibility. Use Laravel Policies or Gates *within the action's code* to enforce these checks.
    *   **CSRF Protection (for Backpack Actions):** Ensure that custom actions triggered by Backpack buttons that modify data are protected against CSRF. Use Laravel's built-in CSRF protection, ensuring it's correctly integrated with Backpack's button and action system.
    *   **Input Validation (within Action Logic):** Validate any input received by the custom action (triggered by the Backpack button) to prevent unexpected behavior or vulnerabilities. This validation should occur *within the action's code*.

