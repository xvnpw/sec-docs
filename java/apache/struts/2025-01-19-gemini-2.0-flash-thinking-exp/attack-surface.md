# Attack Surface Analysis for apache/struts

## Attack Surface: [OGNL Expression Injection](./attack_surfaces/ognl_expression_injection.md)

**Description:** Attackers inject malicious Object-Graph Navigation Language (OGNL) expressions into input fields or URLs. When Struts processes these expressions, the malicious code is executed on the server.

**How Struts Contributes:** Struts extensively uses OGNL for data access and manipulation, particularly when binding request parameters to action properties. If input is not properly sanitized before being evaluated as an OGNL expression, it becomes a major vulnerability.

**Example:** A URL like `http://example.com/index.action?name=%24%7b%23context%5b%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%5d.addHeader%28%27Exploit%27%2c%27Executed%27%29%7d` could execute code on the server.

**Impact:** Remote Code Execution (RCE), allowing attackers to gain full control of the server, steal data, install malware, or disrupt services.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Upgrade Struts to the latest stable version.
* Thoroughly sanitize and validate all user input on the server-side before using it in OGNL expressions. Avoid direct usage.
* Configure parameter interceptors with explicit allow/deny lists.
* Disable Dynamic Method Invocation (DMI) if not necessary.
* Configure `SecurityMemberAccess` to restrict access to sensitive methods and properties within OGNL expressions.

## Attack Surface: [Action Mapping Manipulation](./attack_surfaces/action_mapping_manipulation.md)

**Description:** Attackers manipulate the action name or namespace in the request URL to access unintended actions or bypass security checks.

**How Struts Contributes:** Struts relies on action mappings defined in configuration files (struts.xml) to route requests. If these mappings are not carefully designed or if the framework allows for easy manipulation, vulnerabilities can arise.

**Example:** An attacker might change the URL from `/secure/profile.action` to `/admin/sensitiveAction.action` if the mapping and authorization are not properly configured.

**Impact:** Unauthorized access to sensitive functionalities, bypassing authentication and authorization mechanisms, potentially leading to data breaches or privilege escalation.

**Risk Severity:** High

**Mitigation Strategies:**
* Securely design action mappings and namespaces, protecting sensitive actions with appropriate constraints.
* Use wildcard mappings cautiously.
* Implement robust authorization checks within action classes.
* Apply the principle of least privilege for actions.

## Attack Surface: [Result Manipulation (including Server-Side Template Injection - SSTI)](./attack_surfaces/result_manipulation__including_server-side_template_injection_-_ssti_.md)

**Description:** Attackers manipulate the result type or parameters to force the application to render responses in an unintended way, potentially leading to code execution if a vulnerable template engine is used.

**How Struts Contributes:** Struts uses result types (e.g., `dispatcher`, `freemarker`, `velocity`) to determine how the response is rendered. If the result type or its parameters can be controlled by the attacker, it can be exploited.

**Example:** An attacker might manipulate the result type to use a vulnerable FreeMarker template and inject malicious code within the template.

**Impact:** Server-Side Template Injection (SSTI) leading to Remote Code Execution, information disclosure, or denial of service.

**Risk Severity:** Critical (if SSTI is possible)

**Mitigation Strategies:**
* Avoid user-controlled result types or template selections.
* Securely configure and update template engines like FreeMarker or Velocity. Sanitize data before passing it to them.
* Implement a strong Content Security Policy (CSP).
* Rigorously validate result parameters if they are dynamically generated.

## Attack Surface: [Interceptor Vulnerabilities](./attack_surfaces/interceptor_vulnerabilities.md)

**Description:** Vulnerabilities exist within custom or even default Struts interceptors, allowing attackers to bypass security checks or exploit flaws in the interceptor logic.

**How Struts Contributes:** Interceptors are a core part of the Struts request processing pipeline. If interceptors are not implemented securely, they can become attack vectors.

**Example:** A poorly written custom interceptor might fail to properly sanitize input, leading to vulnerabilities later in the request processing.

**Impact:** Bypassing security checks, unauthorized access, data manipulation, or even code execution depending on the interceptor's functionality.

**Risk Severity:** High

**Mitigation Strategies:**
* Thoroughly review and test custom interceptors for potential vulnerabilities, following secure coding practices.
* Understand the functionality of default interceptors and configure them appropriately. Remove or disable unnecessary ones.
* Perform input validation early in the request processing within interceptors.
* Conduct regular security audits of interceptor configurations and implementations.

## Attack Surface: [File Upload Vulnerabilities](./attack_surfaces/file_upload_vulnerabilities.md)

**Description:** Flaws in the file upload mechanism allow attackers to upload malicious files (e.g., web shells) or overwrite existing files, leading to code execution or data breaches.

**How Struts Contributes:** Struts provides built-in support for file uploads. If not configured securely, this functionality can be exploited.

**Example:** An attacker uploads a PHP web shell disguised as an image file, which can then be accessed to execute commands on the server.

**Impact:** Remote Code Execution, data breaches, defacement of the application.

**Risk Severity:** High

**Mitigation Strategies:**
* Strictly validate file types based on content (magic numbers), not just extensions.
* Sanitize uploaded file names to prevent path traversal.
* Enforce reasonable file size limits.
* Store uploaded files securely outside the web root or in a location with restricted execution permissions.
* Consider using anti-virus scanning for uploaded files.

