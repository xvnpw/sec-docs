# Attack Surface Analysis for apache/struts

## Attack Surface: [1. OGNL Injection (Remote Code Execution)](./attack_surfaces/1__ognl_injection__remote_code_execution_.md)

*   **Description:** Attackers inject malicious OGNL (Object-Graph Navigation Language) expressions into user-supplied input. These expressions are then evaluated by the Struts framework, leading to arbitrary code execution on the server.
*   **How Struts Contributes:** Struts' core functionality relies heavily on OGNL for data binding, expression evaluation, and tag library functionality.  Insufficient validation of user input *before* it's used within OGNL expressions is the fundamental vulnerability. Struts tags (e.g., `s:a`, `s:form`, `s:textfield`) and result types (especially `redirect` and `redirectAction`) are common injection points.
*   **Example:** An attacker submits a crafted URL parameter like `?param=${(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}`. This OGNL expression bypasses security restrictions, executes the `id` command (adapting to Windows or Linux), and sends the output to the response.
*   **Impact:** Complete server compromise. The attacker gains the ability to execute arbitrary commands, access sensitive data, modify files, and potentially pivot to other systems.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict OGNL Whitelisting:** Employ `SecurityMemberAccess` and related Struts configuration options to *strictly* whitelist allowed OGNL expressions. Avoid dynamic OGNL expressions that incorporate user input. Favor direct property access (e.g., `user.name`) over constructing expressions from user input.
    *   **Input Validation (Framework Level):** Utilize Struts' built-in validation framework (Validators) to enforce rigorous input validation *before* any data reaches OGNL evaluation. Define precise allowed patterns, lengths, and data types for all user-supplied input.
    *   **Immediate Security Patching:** Apply the latest Struts security patches *immediately* upon release. This is the most crucial ongoing mitigation, as new OGNL injection vulnerabilities are frequently discovered.
    *   **Disable Unnecessary Features:** If features like dynamic method invocation (DMI) are not strictly required, disable them to reduce the attack surface.
    *   **Web Application Firewall (WAF) (Supplementary):** A WAF can help detect and block common OGNL injection patterns, providing an additional layer of defense. However, it should *not* be relied upon as the sole protection.

## Attack Surface: [2. Class Loading Manipulation (Remote Code Execution)](./attack_surfaces/2__class_loading_manipulation__remote_code_execution_.md)

*   **Description:** Attackers manipulate request parameters to force Struts to load and instantiate arbitrary Java classes. This can lead to the execution of malicious code contained within those classes.
*   **How Struts Contributes:** Struts' architecture relies heavily on Java reflection and class loading to map request parameters to action properties and methods. Vulnerabilities arise when attackers can control which classes are loaded and instantiated. The Parameters Interceptor is a key component involved in this process.
*   **Example:** An attacker might attempt to manipulate a parameter named `class` (or a similar parameter used internally by Struts or a plugin) to point to a malicious class that they have managed to place on the server's classpath (e.g., through a separate file upload vulnerability or a compromised dependency).
*   **Impact:** Complete server compromise, similar to OGNL injection. The attacker can execute arbitrary code with the privileges of the application server.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Parameter Filtering:** Implement a strict whitelist of allowed request parameters and their expected data types. Reject any unexpected or unknown parameters.
    *   **`excludedClasses` and `excludedPackageNames`:** Utilize Struts' configuration options (`excludedClasses` and `excludedPackageNames` in `struts.xml`) to explicitly blacklist sensitive classes and packages, preventing them from being loaded via parameter manipulation.
    *   **Disable Dynamic Method Invocation (DMI):** If DMI is not absolutely essential, disable it. DMI allows action methods to be called based on request parameters, increasing the attack surface.
    *   **Plugin Security:** Keep all Struts plugins up-to-date with the latest security patches. Carefully evaluate the security implications of any third-party plugins before using them.
    *   **Immediate Security Patching:** Apply the latest Struts security patches promptly.

## Attack Surface: [3. File Upload Vulnerabilities (Leading to Remote Code Execution)](./attack_surfaces/3__file_upload_vulnerabilities__leading_to_remote_code_execution_.md)

*   **Description:**  Attackers exploit weaknesses in Struts' file upload handling mechanisms to upload malicious files (e.g., web shells) that can then be executed on the server.
*   **How Struts Contributes:** Struts provides built-in file upload functionality, primarily through the `fileUpload` interceptor. Misconfigurations or vulnerabilities within this interceptor, or in the application's handling of uploaded files, create the attack vector.
*   **Example:** An attacker uploads a JSP file containing malicious code (a web shell) to a directory that is accessible by the web server. They can then access this file via a URL, causing the server to execute the embedded code.
*   **Impact:** Remote Code Execution (RCE), leading to complete server compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict File Upload Limits:** Configure the `fileUpload` interceptor with strict limits on:
        *   `maximumSize`: The maximum allowed file size.
        *   `allowedTypes`: Allowed MIME types (but *do not* rely on this alone for security).
        *   `allowedExtensions`: Allowed file extensions (but *do not* rely on this alone for security).
    *   **Content-Based File Type Validation:**  *Do not* rely solely on file extensions or MIME types provided by the client. Use content-based file type detection (e.g., checking file headers or using a library like Apache Tika) to verify the *actual* file type.
    *   **Secure Upload Directory:** Store uploaded files *outside* the web root, in a dedicated directory with restricted access permissions. Prevent direct web access to this directory.
    *   **Rename Uploaded Files:** Rename uploaded files to randomly generated names (e.g., using UUIDs) to prevent attackers from guessing file names and accessing them directly.
    *   **Virus Scanning:** Integrate a virus scanner into the file upload process to detect and block known malicious files.

## Attack Surface: [4. Cross-Site Scripting (XSS) - Struts-Specific Considerations](./attack_surfaces/4__cross-site_scripting__xss__-_struts-specific_considerations.md)

*   **Description:** Attackers inject malicious JavaScript code into the application, which is then executed in the browsers of other users. While XSS is a general web vulnerability, Struts' output handling can introduce specific risks.
*   **How Struts Contributes:** If Struts tags are used to display user-supplied data without proper escaping, XSS is possible. This is particularly relevant if the `escape` attribute is not used or is set to `false`. Struts tags are the direct contributor.
*   **Example:** A user enters `<script>alert('XSS')</script>` into a form field. If this value is later displayed using a Struts tag like `<s:property value="userInput" />` *without* `escape="true"`, the JavaScript code will be executed in the browser.
*   **Impact:** The attacker can steal user cookies, redirect users to malicious websites, deface the application, or perform other actions in the context of the victim's browser.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Consistent Escaping:** *Always* use the `escape` attribute (or `escapeXml`, `escapeJavaScript`, etc., as appropriate) in Struts tags when displaying user-supplied data. Make escaping the default behavior.
    *   **Content Security Policy (CSP):** Implement a strong CSP to mitigate the impact of XSS vulnerabilities, even if they exist. CSP restricts the sources from which scripts can be loaded.
    *   **Input Validation:** While input validation is not a primary defense against XSS, it can help reduce the risk by rejecting obviously malicious input.
    *   **Output Encoding:** Ensure consistent and correct output encoding (e.g., UTF-8) to prevent encoding-related XSS vulnerabilities.

