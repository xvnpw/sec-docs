# Threat Model Analysis for grails/grails

## Threat: [Data Binding Manipulation (Mass Assignment)](./threats/data_binding_manipulation__mass_assignment_.md)

*   **Description:** An attacker crafts a malicious HTTP request to include additional parameters not intended for modification.  For example, adding `isAdmin=true` to a user profile update form. If Grails doesn't restrict bindable parameters, the attacker can elevate privileges or modify sensitive data.
    *   **Impact:** Unauthorized data modification, privilege escalation, potential account takeover, data corruption.
    *   **Affected Grails Component:** Data Binding mechanism (`params` object handling, domain/command object binding), Controllers.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Command Objects:** Use Command Objects to define *exactly* which properties are allowed to be bound. This is the recommended best practice.
        *   **`params.bindData()` with Whitelisting:** Use `params.bindData(domainObject, [includes: ['name', 'email']])` to explicitly allow only specific properties.  *Never* bind the entire `params` object unfiltered.
        *   **`@BindUsing` Annotation:** Use `@BindUsing` on domain class properties for custom binding control.
        *   **Input Validation:** Implement robust input validation *in addition to* data binding restrictions.

## Threat: [GSP Expression Language Injection (RCE)](./threats/gsp_expression_language_injection__rce_.md)

*   **Description:** An attacker injects malicious Groovy code into a GSP template. This happens if user data is rendered without proper escaping (e.g., `<%= userInput %>` instead of `${userInput}`). Even with escaping, dynamic tag attribute construction can be vulnerable.  The injected code could execute arbitrary commands on the server.
    *   **Impact:** Remote Code Execution (RCE), complete server compromise, data theft, data destruction.
    *   **Affected Grails Component:** GSP rendering engine, Controllers (if dynamically generating GSP content), Tag Libraries (if misused).
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Default Escaping:** Always use the default GSP escaping (`${...}`) for user-supplied data.
        *   **Avoid `<%= ... %>`:** Minimize `<%= ... %>`. If necessary, *thoroughly* sanitize user input before inclusion.
        *   **Safe Tag Attribute Construction:** Avoid dynamic tag attribute construction using string concatenation with user input. Use built-in tag libraries.
        *   **Content Security Policy (CSP):** A well-configured CSP can provide an additional layer of defense.

## Threat: [Unsafe Deserialization](./threats/unsafe_deserialization.md)

*   **Description:** An attacker sends a crafted serialized object to a Grails endpoint that deserializes it without validation. If the application uses Java serialization (or other vulnerable formats) and the classpath contains "gadget" classes, the attacker can achieve Remote Code Execution (RCE).
    *   **Impact:** Remote Code Execution (RCE), complete server compromise.
    *   **Affected Grails Component:** Any component that deserializes data from untrusted sources (controllers, services).
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Avoid Deserialization of Untrusted Data:** The best defense. Use alternative formats like JSON if possible.
        *   **Whitelisting:** If necessary, implement strict whitelisting of allowed classes for deserialization.
        *   **Safe Deserialization Libraries:** Use libraries designed for safe deserialization.
        *   **Keep Libraries Updated:** Ensure all serialization-related libraries (including the Java runtime) are up to date.

## Threat: [Improper Handling of File Uploads (Grails Specific)](./threats/improper_handling_of_file_uploads__grails_specific_.md)

* **Description:** An attacker uploads a malicious file (e.g., a Groovy script or a file with a manipulated extension) that is then processed or executed by the Grails application. Path traversal attacks are also possible if filenames are not sanitized.
    * **Impact:** Remote Code Execution (RCE), file system access, data corruption, denial of service.
    * **Affected Grails Component:** Controllers handling uploads, services processing files, GSP templates interacting with uploaded files.
    * **Risk Severity:** High to Critical.
    * **Mitigation Strategies:**
        - **Store Outside Web Root:** Store uploaded files outside the web root.
        - **Strict File Type Validation:** Validate file types using server-side checks based on content, not just headers or extensions.
        - **File Size Limits:** Enforce strict file size limits.
        - **Filename Sanitization:** Rename files to prevent path traversal. Use random filenames.
        - **Sandboxed Processing:** Process uploaded files in a sandboxed environment.
        - **Antivirus Scanning:** Scan uploaded files for malware.
        - **Avoid Direct Execution:** Never directly execute or interpret uploaded files.

