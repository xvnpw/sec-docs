# Threat Model Analysis for revel/revel

## Threat: [Parameter Tampering via Reflection Abuse](./threats/parameter_tampering_via_reflection_abuse.md)

*   **Threat:** Parameter Tampering via Reflection Abuse

    *   **Description:** An attacker crafts a malicious HTTP request with manipulated parameters (names, types, or values) that are not expected by the application.  Due to Revel's heavy reliance on reflection for parameter binding, the attacker can potentially:
        *   Call unintended controller actions or methods.
        *   Bypass input validation *if* that validation is insufficient *after* Revel's binding.
        *   Inject data of unexpected types, leading to crashes or unexpected behavior.
        *   Manipulate internal state variables if they are directly exposed through parameter binding.

    *   **Impact:**
        *   Unauthorized access to data or functionality.
        *   Data corruption or modification.
        *   Application crashes (Denial of Service).
        *   Potential for remote code execution (in extreme cases, if combined with other vulnerabilities).

    *   **Affected Component:**
        *   `revel.Controller.Params`: The primary component responsible for handling request parameters.
        *   Reflection mechanism used within `Params.Bind` and related functions.
        *   Controller actions that receive parameters.

    *   **Risk Severity:** Critical

    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Implement comprehensive input validation *within* controller actions, *after* Revel has bound the parameters.  Use Revel's `Validation` framework extensively. Validate data types, lengths, ranges, and formats.
        *   **Whitelisting:** Define a whitelist of expected parameters and reject any others.
        *   **Type Safety:** Use strong, specific Go types (e.g., `int`, `string`, custom structs) instead of generic types (e.g., `interface{}`) whenever possible.
        *   **Avoid Direct Binding to Sensitive Structures:** Do not bind request parameters directly to sensitive data structures without thorough validation and sanitization.
        *   **Limit Parameter Complexity:** Restrict the size and nesting depth of parameters to prevent resource exhaustion.

## Threat: [Verbose Error Messages in Production](./threats/verbose_error_messages_in_production.md)

*   **Threat:** Verbose Error Messages in Production

    *   **Description:** An attacker triggers an error in the application, and Revel, if configured in development mode (`revel.DevMode = true`), returns a detailed error message, including a stack trace, source code snippets, and potentially sensitive environment variables.

    *   **Impact:**
        *   Information disclosure: Reveals internal application structure, code logic, and potentially sensitive data (database credentials, API keys, etc.).
        *   Facilitates further attacks by providing attackers with valuable information.

    *   **Affected Component:**
        *   `revel.DevMode`: The global setting that controls development mode.
        *   Revel's error handling mechanism.

    *   **Risk Severity:** Critical

    *   **Mitigation Strategies:**
        *   **Disable Development Mode in Production:** Ensure `revel.RunMode` is set to `"prod"` in the production environment.  This is the *most crucial* mitigation.
        *   **Custom Error Pages:** Implement custom error handling to display generic, user-friendly error messages in production, while logging detailed error information for debugging purposes.
        *   **Environment Variable Security:** Avoid storing sensitive information directly in environment variables that might be exposed in error messages. Use a secure configuration management system.

## Threat: [Template Injection](./threats/template_injection.md)

*   **Threat:** Template Injection

    *   **Description:** An attacker provides input that is used to dynamically construct a template (e.g., choosing a template name or including a template snippet).  This allows the attacker to inject arbitrary template code, which can then be executed by Revel's templating engine.

    *   **Impact:**
        *   Remote code execution (RCE) on the server.
        *   Complete server compromise.
        *   Data theft or modification.

    *   **Affected Component:**
        *   Revel's templating engine (by default, Go's `html/template`).
        *   Controller actions that dynamically generate templates based on user input.

    *   **Risk Severity:** Critical

    *   **Mitigation Strategies:**
        *   **Avoid Dynamic Template Selection:** Do not use user input to determine which template to render.
        *   **Whitelist Template Names:** If dynamic template selection is unavoidable, use a strict whitelist of allowed template names.
        *   **No User-Supplied Template Code:** Never allow users to directly input template code.
        *   **Sanitize Input:** Sanitize any user input used within template logic, even though auto-escaping handles most XSS cases.

## Threat: [Exposure of Internal Files](./threats/exposure_of_internal_files.md)

*   **Threat:** Exposure of Internal Files

    *   **Description:** Incorrect configuration of Revel's static file serving allows attackers to access files outside the intended public directory, potentially including source code, configuration files, or other sensitive resources.

    *   **Impact:**
        *   Information disclosure: Reveals internal application structure, code, and potentially sensitive data.
        *   Facilitates further attacks.

    *   **Affected Component:**
        *   `revel.Config`: Configuration related to static file serving.
        *   `static.Serve` function (and related configuration).

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Restrict Static File Serving:** Carefully configure `static.Serve` to only expose the necessary public assets (e.g., CSS, JavaScript, images).
        *   **Avoid Serving Sensitive Directories:** Do not serve files from directories that contain sensitive information.
        *   **Use a Web Server:** Use a web server (e.g., Nginx, Apache) in front of Revel to handle static file serving for improved performance and security.

