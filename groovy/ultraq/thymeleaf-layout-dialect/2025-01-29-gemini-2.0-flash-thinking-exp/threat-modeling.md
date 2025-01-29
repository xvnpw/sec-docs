# Threat Model Analysis for ultraq/thymeleaf-layout-dialect

## Threat: [Template Injection via `layout:decorate` and `layout:fragment`](./threats/template_injection_via__layoutdecorate__and__layoutfragment_.md)

*   **Description:** An attacker could manipulate user-controlled input that is used to construct template paths in `layout:decorate` or `layout:fragment` attributes. By injecting malicious path segments (e.g., `../`, absolute paths) or template names, the attacker can force the application to include arbitrary templates or files from the server's filesystem. This could be achieved by directly manipulating URL parameters, form data, or other input channels that influence the template path resolution.
*   **Impact:**
    *   Confidentiality Breach: Access to sensitive files, configuration data, or application source code residing on the server.
    *   Potential Server-Side Template Injection (SSTI): In specific scenarios, if the included templates are further processed with user-controlled data, it could lead to SSTI, potentially enabling remote code execution.
*   **Affected Component:**
    *   `layout:decorate` attribute processing
    *   `layout:fragment` attribute processing
    *   Template path resolution mechanism within the dialect
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Implement robust input validation and sanitization for all user inputs that could influence template paths used in `layout:decorate` and `layout:fragment`.
    *   **Path Whitelisting:** Define a whitelist of allowed template paths or directories. Validate user-provided paths against this whitelist.
    *   **Secure Path Resolution:** Utilize secure path handling functions to prevent path traversal attempts. Ensure resolved paths are confined to the intended template directory.
    *   **Principle of Least Privilege:** Run the application with minimal file system permissions to limit the scope of potential path traversal attacks.

