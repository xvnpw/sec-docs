# Attack Surface Analysis for kataras/iris

## Attack Surface: [Path Parameter Injection](./attack_surfaces/path_parameter_injection.md)

*   **Description:** Attackers manipulate path parameters in URLs to access unauthorized resources or bypass security checks.
*   **Iris Contribution:** Iris's routing system heavily relies on path parameters defined within route patterns (e.g., `/user/{id}`). If developers don't properly validate and sanitize these parameters, they become injection points directly facilitated by Iris's routing mechanism.
*   **Example:** A route `/files/{filename}` intended to serve files from a specific directory. If `filename` is not validated, an attacker could use `../sensitive.txt` to access files outside the intended directory, exploiting Iris's path parameter handling.
*   **Impact:** Unauthorized access to sensitive data, information disclosure, potential command execution if parameters are used in system calls.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:**  Validate all path parameters against expected formats and allowed values *within Iris handler functions*. Use regular expressions or whitelists to ensure parameters conform to requirements *before processing them in Iris handlers*.
    *   **Sanitization:** Sanitize path parameters to remove or escape potentially harmful characters *within Iris handlers* before using them in file paths, database queries, or system commands. Utilize Go's standard library functions like `filepath.Clean` carefully within Iris handlers.
    *   **Principle of Least Privilege:** Grant the application only the necessary permissions to access resources. Avoid directly using path parameters to construct file paths *in Iris handlers* without rigorous validation and sandboxing.

## Attack Surface: [Middleware Bypass](./attack_surfaces/middleware_bypass.md)

*   **Description:** Attackers find ways to bypass middleware, causing security checks or processing steps to be skipped.
*   **Iris Contribution:**  Middleware in Iris is a core feature for request processing. Flaws in middleware logic or reliance on easily manipulated conditions *within Iris middleware implementations* can lead to bypasses, directly impacting the security enforced by Iris middleware.
*   **Example:** Middleware designed to authenticate users for paths starting with `/admin`. If the middleware only checks for `/admin` prefix and an attacker requests `/admin/../sensitive-endpoint`, they might bypass the middleware if path normalization is not handled correctly *within the Iris middleware or routing configuration*. This bypass is directly related to how Iris middleware is applied and how path matching is performed.
*   **Impact:**  Bypass of authentication, authorization, input validation, or other security measures implemented in middleware, leading to unauthorized access or actions.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Robust Middleware Logic:** Ensure middleware logic is robust and not easily bypassed. Avoid relying solely on simple path prefixes or easily manipulated headers *in Iris middleware*.
    *   **Consistent Path Handling:** Standardize path handling within middleware and routing *in Iris configurations and middleware implementations* to prevent inconsistencies that could lead to bypasses (e.g., always normalize paths using `filepath.Clean` consistently in Iris middleware and handlers).
    *   **Middleware Testing:** Thoroughly test middleware *within the Iris application context* to ensure it functions as expected and cannot be bypassed under various conditions.
    *   **Chain of Responsibility:** Design middleware chains to be independent and not rely on assumptions about previous middleware execution that could be manipulated *within the Iris middleware chain configuration*.

## Attack Surface: [Session Fixation](./attack_surfaces/session_fixation.md)

*   **Description:** Attackers force a known session ID onto a user, allowing them to hijack the user's session after successful login.
*   **Iris Contribution:** If Iris applications use default session management *provided by Iris* without proper security measures, they can be vulnerable to session fixation. This is directly related to the security of Iris's session management features and default configurations.
*   **Example:** An attacker obtains a valid session ID. They then send a link to a victim containing this session ID in the URL or cookie. If the application doesn't regenerate the session ID upon successful login *using Iris's session management*, the victim might log in using the attacker's pre-set session ID, allowing the attacker to hijack the session.
*   **Impact:** Session hijacking, unauthorized access to user accounts and data.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Session ID Regeneration:** Always regenerate the session ID upon successful user login to invalidate any pre-existing session IDs. *Configure Iris session management to regenerate session IDs on login.*
    *   **Secure Session ID Generation:** Use cryptographically secure random number generators for session ID creation to make them unpredictable. *Iris's session management should ideally use secure random ID generation by default, but developers should verify this and potentially customize if needed.*
    *   **HttpOnly and Secure Cookies:** Set the `HttpOnly` and `Secure` flags for session cookies to prevent client-side JavaScript access and ensure cookies are only transmitted over HTTPS. *Configure Iris session management to set these cookie flags.*
    *   **Session Timeout:** Implement appropriate session timeouts to limit the lifespan of sessions and reduce the window of opportunity for session hijacking. *Configure session timeouts within Iris's session management settings*.

## Attack Surface: [Template Injection (If Templates Used)](./attack_surfaces/template_injection__if_templates_used_.md)

*   **Description:** Attackers inject malicious code into templates, which is then executed by the template engine, leading to code execution or information disclosure.
*   **Iris Contribution:** If Iris applications use template engines (like `html/template` or others) and dynamically construct templates with user-provided data without proper escaping, template injection vulnerabilities can occur. This is relevant when using Iris's template rendering features and integrating template engines.
*   **Example:** A web application displays user comments. If comments are rendered using a template engine *integrated with Iris* without proper escaping and a user submits a comment containing template directives (e.g., `{{.Execute "os/exec" "command"}}`), the template engine might execute the injected command on the server *when processed by Iris's template rendering*.
*   **Impact:** Remote code execution, information disclosure, server compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Context-Aware Output Encoding/Escaping:** Always escape user-provided data before embedding it into templates *when using Iris's template rendering*. Use template engine's built-in escaping mechanisms that are context-aware (e.g., HTML escaping, JavaScript escaping) *within Iris template rendering logic*.
    *   **Avoid Dynamic Template Construction:** Minimize or avoid dynamically constructing templates from user input *when using Iris templates*. If necessary, carefully sanitize and validate user input before incorporating it into templates *rendered by Iris*.
    *   **Template Security Review:** Regularly review templates for potential injection vulnerabilities, especially when handling user-generated content *in Iris applications using templates*.
    *   **Principle of Least Privilege (Template Engine):** If possible, configure the template engine to operate in a restricted environment with limited access to system resources *when integrated with Iris*.

## Attack Surface: [Directory Traversal via Static Files](./attack_surfaces/directory_traversal_via_static_files.md)

*   **Description:** Attackers exploit vulnerabilities in static file serving to access files outside the intended static file directory, potentially gaining access to sensitive system files.
*   **Iris Contribution:** Iris's `iris.StaticWeb` and similar functions are used to serve static files. Misconfiguration or improper path handling *when using Iris's static file serving features* can lead to directory traversal.
*   **Example:** An application serves static files from a directory `/public` using `iris.StaticWeb("/public", "./public")`. If the static file handler doesn't properly sanitize requested paths *within Iris's static file serving implementation*, an attacker could request `/public/../../../../etc/passwd` to access the system's password file.
*   **Impact:** Unauthorized access to sensitive files, information disclosure, potential system compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Static File Configuration:** Carefully configure static file serving paths *in Iris using `iris.StaticWeb` or similar functions* and ensure they are restricted to the intended directories.
    *   **Path Sanitization:** Sanitize requested file paths to prevent directory traversal attempts. *Iris's `StaticWeb` should ideally handle path sanitization, but developers should verify and potentially add extra sanitization in custom handlers if needed.* Use functions like `filepath.Clean` and ensure paths stay within the allowed static file directory *when implementing custom static file serving logic in Iris*.
    *   **Principle of Least Privilege (File System Access):**  Grant the application only the necessary file system permissions to serve static files. Avoid serving static files from the root directory or directories containing sensitive data *when configuring Iris static file serving*.
    *   **Regular Security Audits:** Regularly audit static file serving configurations *in Iris applications* to ensure they are secure and prevent directory traversal vulnerabilities.

