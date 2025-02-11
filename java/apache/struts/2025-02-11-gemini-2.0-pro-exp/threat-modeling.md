# Threat Model Analysis for apache/struts

## Threat: [Threat: Remote Code Execution (RCE) via OGNL Injection](./threats/threat_remote_code_execution__rce__via_ognl_injection.md)

*   **Description:** An attacker crafts a malicious HTTP request containing a specially crafted OGNL expression. This expression is injected into a vulnerable Struts action parameter.  When Struts processes this parameter, the malicious OGNL expression is evaluated, allowing the attacker to execute arbitrary code on the server. This often involves exploiting weaknesses in how Struts handles type conversions or validates user input before using it in OGNL.
*   **Impact:** Complete system compromise. The attacker gains full control over the server, allowing them to steal data, install malware, modify the application, or use the server for further attacks.
*   **Affected Struts Component:**
    *   OGNL evaluation engine.
    *   Action parameters processing.
    *   Interceptors that handle parameter population (e.g., `params` interceptor).
    *   Result types that utilize OGNL (e.g., `redirectAction`, `chain`).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Update Struts:** Immediately apply the latest security patches for Struts. This is the *primary* defense.
    *   **Strict Input Validation:** Implement rigorous, whitelist-based validation of *all* input parameters. Validate type, length, format, and allowed characters. Do *not* rely solely on Struts' built-in validation.
    *   **OGNL Hardening:** Avoid direct evaluation of user-supplied data in OGNL expressions. If OGNL must be used, sanitize and escape input appropriately. Consider using a safer alternative if possible.
    *   **Disable Dynamic Method Invocation:** If not strictly required, disable dynamic method invocation (`struts.enable.DynamicMethodInvocation` set to `false` in `struts.xml`).
    *   **Web Application Firewall (WAF):** Use a WAF with rules specifically designed to detect and block OGNL injection attempts.  (Note: This is a supplementary defense, not a replacement for patching.)
    *   **Security Audits:** Conduct regular security audits and penetration tests that specifically target OGNL injection vulnerabilities.

## Threat: [Threat: Remote Code Execution (RCE) via File Upload Vulnerability](./threats/threat_remote_code_execution__rce__via_file_upload_vulnerability.md)

*   **Description:** An attacker uploads a malicious file (e.g., a JSP file containing malicious code) by exploiting a vulnerability in Struts' file upload handling. This can involve bypassing file extension restrictions, uploading files to unintended directories (path traversal), or exploiting vulnerabilities in underlying libraries like the Jakarta Multipart parser. The attacker then accesses the uploaded file through the web server, triggering the execution of the malicious code.
*   **Impact:** Complete system compromise, similar to OGNL injection. The attacker gains control over the server.
*   **Affected Struts Component:**
    *   `FileUploadInterceptor`.
    *   Jakarta Multipart parser (historically, though often patched in later Struts versions).
    *   Configuration related to file upload directories and allowed extensions.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Update Struts:** Apply the latest security patches.
    *   **Strict File Upload Validation:**
        *   **Whitelist File Types:**  Allow only specific, necessary file types (MIME types). Verify the *actual* file content, not just the extension.
        *   **Limit File Size:** Enforce a strict maximum file size.
        *   **Sanitize File Names:**  Prevent path traversal by sanitizing file names.  Rename uploaded files to prevent overwriting.
        *   **Content Scanning:** Scan uploaded files for malicious content using a virus scanner or similar tool.
    *   **Secure File Storage:** Store uploaded files *outside* the web root if possible. If stored within the web root, ensure they are *not* directly executable (configure the web server appropriately).
    *   **Disable File Uploads:** If file uploads are not essential, disable the functionality entirely.

## Threat: [Threat: Denial of Service (DoS) via Parameter Manipulation](./threats/threat_denial_of_service__dos__via_parameter_manipulation.md)

*   **Description:** An attacker sends a specially crafted request with parameters designed to consume excessive server resources (CPU, memory, or threads). This could involve very large parameter values, deeply nested OGNL expressions, or other techniques that exploit weaknesses in Struts' parameter processing.
*   **Impact:** Application unavailability. Legitimate users are unable to access the application.
*   **Affected Struts Component:**
    *   Parameter processing components (similar to OGNL injection).
    *   OGNL evaluation engine (if complex expressions are involved).
    *   Interceptors involved in parameter handling.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:** Implement strict limits on the size and complexity of input parameters.
    *   **Resource Limits:** Configure the application server and operating system to enforce resource limits (e.g., maximum memory per request, maximum request processing time).
    *   **Rate Limiting:** Implement rate limiting to prevent attackers from flooding the application with requests.
    *   **Monitoring:** Monitor server resource usage to detect potential DoS attacks.

## Threat: [General Mitigation Strategy (Applies to All Threats):](./threats/general_mitigation_strategy__applies_to_all_threats_.md)

*   **Regular Security Audits and Penetration Testing:** Conduct frequent security assessments, including code reviews and penetration tests, to identify and address vulnerabilities proactively.  These tests should specifically target Struts-related weaknesses.

