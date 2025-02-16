# Attack Surface Analysis for rails/rails

## Attack Surface: [Mass Assignment (Strong Parameters Bypass)](./attack_surfaces/mass_assignment__strong_parameters_bypass_.md)

*   **Description:** Attackers manipulate input parameters to modify model attributes they shouldn't have access to, bypassing intended security controls.
*   **How Rails Contributes:** Rails' `ActiveRecord` models and the ease of mass-updating attributes create this vulnerability if not carefully managed. Strong Parameters are Rails' *primary* defense, and bypassing them is a Rails-specific attack.
*   **Example:** An attacker adds `&user[admin]=true` to a form submission for updating their profile, potentially gaining administrative privileges if the `admin` attribute isn't protected by Strong Parameters.
*   **Impact:** Unauthorized data modification, privilege escalation, complete account takeover.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strictly Enforce Strong Parameters:** Use `params.require(:model).permit(:attr1, :attr2, ...)` in *every* controller action that updates model attributes. Never use `params` directly for mass assignment.
    *   **Avoid Bypass Methods:** Do not use `update_attribute`, `update_column`, or `assign_attributes` without proper whitelisting. These methods bypass Strong Parameters.
    *   **Code Review:** Regularly review code for any direct manipulation of the `params` hash before model updates.
    *   **Automated Tools:** Use static analysis tools (e.g., Brakeman) to detect potential mass assignment vulnerabilities.

## Attack Surface: [Unscoped Queries (Information Leakage / Data Manipulation)](./attack_surfaces/unscoped_queries__information_leakage__data_manipulation_.md)

*   **Description:** Queries that don't properly restrict the scope of data being accessed can leak sensitive information or allow attackers to manipulate data belonging to other users or the system.
*   **How Rails Contributes:** Rails' `ActiveRecord` makes it easy to query data, but developers must be explicit about scoping to avoid unintended access.  The ORM's convenience can lead to overlooking scoping requirements. Default scopes, a Rails feature, can also contribute if not carefully considered.
*   **Example:** A developer uses `Comment.find(params[:id])` to retrieve a comment without verifying that it belongs to the current user or a publicly accessible resource. An attacker could access comments from other users by manipulating the `id` parameter.
*   **Impact:** Information disclosure, unauthorized data access, data modification.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Contextual Scoping:** Always scope queries to the current user or relevant context. Use `current_user.comments.find(params[:id])` instead of `Comment.find(params[:id])`.    
    *   **Association Scoping:** Use associations to naturally scope queries (e.g., `@post.comments.find(params[:id])`).
    *   **Review Default Scopes:** Carefully consider the implications of default scopes and ensure they don't inadvertently expose data.
    *   **Authorization Libraries:** Use authorization libraries (e.g., Pundit, CanCanCan) to enforce access control rules consistently.

## Attack Surface: [Route Globbing and Parameter Injection](./attack_surfaces/route_globbing_and_parameter_injection.md)

*   **Description:** Overly permissive routes that use wildcards or unconstrained parameters can allow attackers to access unintended controller actions or pass malicious input.
*   **How Rails Contributes:** Rails' routing system, specifically its allowance of globbing (`*`) and dynamic segments (`:id` without constraints), directly enables this attack vector if misused.
*   **Example:** A route like `get '/files/*path', to: 'files#show'` could allow an attacker to access arbitrary files on the server if `params[:path]` is used directly in a file system operation without sanitization.
*   **Impact:** Arbitrary file access, remote code execution (in extreme cases), denial of service.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Restrictive Routes:** Avoid using wildcards (`*`) in routes whenever possible. Use specific route constraints (e.g., regular expressions) to limit the allowed parameter values.
    *   **Parameter Validation:** Validate and sanitize *all* parameters, especially those used in dynamic rendering, redirection, or file system operations.
    *   **Whitelist Actions:** Explicitly define which controller actions are intended to be publicly accessible.

## Attack Surface: [Secret Key Base Compromise](./attack_surfaces/secret_key_base_compromise.md)

*   **Description:** If the application's `secret_key_base` is compromised, attackers can forge cookies, potentially leading to session hijacking and unauthorized access.
*   **How Rails Contributes:** Rails *requires* and *uses* the `secret_key_base` for signing and encrypting cookies and other sensitive data.  The framework's reliance on this single key is the core of the vulnerability.
*   **Example:** An attacker finds the `secret_key_base` in a leaked configuration file or through a vulnerability that exposes environment variables. They can then generate valid session cookies for any user.
*   **Impact:** Session hijacking, unauthorized access to user accounts, data breach.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strong Key:** Use a long, randomly generated `secret_key_base`.
    *   **Secure Storage:** Store the `secret_key_base` securely, *outside* of the application's codebase. Use environment variables or a dedicated secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager).
    *   **Key Rotation:** Rotate the `secret_key_base` periodically.
    *   **Never Commit:** Never commit the `secret_key_base` to version control.
    *   **Environment Separation:** Use different secret keys for development, testing, and production environments.

## Attack Surface: [Dynamic Render Calls (Local File Inclusion)](./attack_surfaces/dynamic_render_calls__local_file_inclusion_.md)

*   **Description:** Using user-supplied input to determine which template or partial to render can lead to local file inclusion (LFI) vulnerabilities, allowing attackers to read arbitrary files on the server.
*   **How Rails Contributes:** Rails' `render` method, specifically its ability to accept a variable as the template path, is the direct enabler of this vulnerability.
*   **Example:** `render params[:template]` is extremely dangerous. An attacker could set `params[:template]` to `../../../../etc/passwd` to attempt to read the system's password file.
*   **Impact:** Arbitrary file disclosure, information leakage, potentially remote code execution (depending on the server configuration).
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Avoid Dynamic Rendering:** Avoid using user input to determine which template or partial to render.
    *   **Whitelist Templates:** If dynamic rendering is absolutely necessary, use a strict whitelist of allowed template paths.
    *   **Sanitize Input:** If user input *must* be used (strongly discouraged), sanitize it thoroughly to remove any potentially dangerous characters (e.g., `../`, `/`).

