# Threat Model Analysis for kataras/iris

## Threat: [Path Traversal via Parameter Manipulation](./threats/path_traversal_via_parameter_manipulation.md)

**Description:** An attacker manipulates route parameters (e.g., file paths) to access files or resources outside the intended scope by exploiting how Iris handles and passes parameters to route handlers. They might modify the parameter to include ".." sequences to navigate the file system.

**Impact:** Unauthorized access to sensitive files, configuration data, or even execution of arbitrary code if uploaded files are accessible.

**Affected Iris Component:** Route Handlers processing path parameters, `Context.Params`, potentially `iris.StaticWeb`'s default behavior if not carefully configured.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement strict input validation and sanitization for all route parameters used to access files within route handlers.
* Use whitelisting of allowed file paths or patterns instead of blacklisting in route handlers.
* Avoid directly using user-provided input from `Context.Params` to construct file paths.
* When using `iris.StaticWeb`, carefully configure the root directory and ensure proper path sanitization.

## Threat: [Bypassing Security Middleware due to Ordering](./threats/bypassing_security_middleware_due_to_ordering.md)

**Description:** An attacker crafts requests that exploit the order of middleware execution within the Iris application. If security middleware (e.g., authentication, authorization) is registered *after* a vulnerable handler, it might be bypassed due to Iris's middleware execution pipeline.

**Impact:** Unauthorized access to protected resources, execution of privileged actions without proper authentication or authorization.

**Affected Iris Component:** Middleware registration (`app.Use(...)`, `app.Done(...)`), Iris's Middleware execution pipeline.

**Risk Severity:** High

**Mitigation Strategies:**
* Ensure security middleware is registered *before* any handlers that require protection using `app.Use(...)`.
* Follow a principle of least privilege when defining middleware order.
* Thoroughly test the middleware chain to confirm the intended execution order within the Iris application.

## Threat: [Insecure Session Management Configuration](./threats/insecure_session_management_configuration.md)

**Description:** An attacker exploits weak or default session management configurations provided by Iris, such as predictable session IDs, insecure storage if defaults are used, or lack of proper timeouts. This can lead to session hijacking or fixation.

**Impact:** Unauthorized access to user accounts, impersonation, ability to perform actions on behalf of legitimate users.

**Affected Iris Component:** Session Management (`sessions.New(...)`, `Context.Session()`), Iris's Session configuration options.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Configure strong session settings using Iris's session configuration options, including using cryptographically secure random session IDs.
* Utilize secure session storage mechanisms (e.g., Redis, database) instead of Iris's default in-memory storage in production.
* Implement appropriate session timeouts and idle timeouts using Iris's session configuration.
* Regenerate session IDs after successful authentication using Iris's session management features to prevent session fixation.
* Use the `Secure` and `HttpOnly` flags for session cookies as provided by Iris's session management.

## Threat: [Cross-Site Request Forgery (CSRF) Vulnerability due to Lack of Built-in Protection](./threats/cross-site_request_forgery__csrf__vulnerability_due_to_lack_of_built-in_protection.md)

**Description:** An attacker tricks a user's browser into making unwanted requests to the Iris application while the user is authenticated. Iris itself does not provide built-in CSRF protection, making applications vulnerable if developers don't implement it using Iris's features or external libraries.

**Impact:** Unauthorized actions performed on behalf of a legitimate user, such as changing passwords, making purchases, or modifying data.

**Affected Iris Component:** Absence of built-in CSRF protection within the core Iris framework, requiring manual implementation in Route Handlers or Middleware.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement CSRF protection using synchronizer tokens (e.g., using Iris middleware or third-party libraries compatible with Iris's request handling).
* Utilize Iris's `Context` to access and validate CSRF tokens.

## Threat: [WebSocket Injection](./threats/websocket_injection.md)

**Description:** An attacker sends malicious data through a WebSocket connection handled by Iris that is not properly validated or sanitized by the Iris application's WebSocket handlers. This can lead to cross-site scripting (XSS) on other connected clients or other unintended consequences.

**Impact:** Execution of arbitrary JavaScript in other users' browsers, potential session hijacking or data theft.

**Affected Iris Component:** WebSocket handling (`websocket.New(...)`, `Conn.Read(...)`, `Conn.Write(...)`), Input validation within Iris's WebSocket handlers.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement strict input validation and sanitization for all data received via WebSocket connections handled by Iris.
* Encode output data before sending it to clients using Iris's WebSocket connection methods to prevent XSS.
* Consider using a secure WebSocket subprotocol with Iris.

## Threat: [Path Traversal via Static File Serving Misconfiguration](./threats/path_traversal_via_static_file_serving_misconfiguration.md)

**Description:** An attacker crafts requests to access files outside the intended static file directory due to misconfiguration of Iris's `iris.StaticWeb(...)` functionality.

**Impact:** Unauthorized access to sensitive files stored on the server.

**Affected Iris Component:** `iris.StaticWeb(...)`, Iris's static file serving logic.

**Risk Severity:** High

**Mitigation Strategies:**
* Carefully configure the root directory for static file serving when using `iris.StaticWeb(...)`.
* Avoid serving sensitive files from the directory served by `iris.StaticWeb(...)`.
* Ensure that user-provided input is not used to construct file paths for serving static content through `iris.StaticWeb(...)`.

## Threat: [Reliance on Unmaintained or Vulnerable Iris Versions](./threats/reliance_on_unmaintained_or_vulnerable_iris_versions.md)

**Description:** Using an outdated or unmaintained version of the Iris framework directly exposes the application to known vulnerabilities within the framework that have been patched in later releases.

**Impact:** Exploitation of known vulnerabilities within Iris leading to various security breaches.

**Affected Iris Component:** The entire Iris framework codebase.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Keep the Iris framework updated to the latest stable version.
* Regularly review security advisories and patch notes for Iris releases.
* Use Go's dependency management tools to track and update the Iris dependency.

