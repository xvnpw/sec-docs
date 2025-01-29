# Attack Surface Analysis for apache/struts

## Attack Surface: [1. OGNL Injection](./attack_surfaces/1__ognl_injection.md)

*   **Description:** Exploiting vulnerabilities in the Object-Graph Navigation Language (OGNL) engine, a core component of Struts, to achieve Remote Code Execution (RCE) or unauthorized data access.
*   **Struts Contribution:** Struts' architecture deeply integrates OGNL for data binding, expression evaluation in JSP tags, and action configuration. This tight integration makes applications inherently vulnerable if user input reaches OGNL expressions without proper sanitization. Struts framework itself has suffered from numerous OGNL injection vulnerabilities.
*   **Example:** An attacker crafts a malicious HTTP parameter that is processed by Struts' OGNL engine. This parameter, when evaluated, executes arbitrary Java code on the server. A classic example is exploiting vulnerabilities like CVE-2017-5638 (Struts-Shock) by sending a crafted `Content-Type` header.
*   **Impact:** Remote Code Execution (RCE), complete server compromise, data breach, denial of service.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Upgrade Struts Version:**  Immediately upgrade to the latest stable and patched version of Struts. Focus on versions that explicitly address known OGNL injection vulnerabilities.
    *   **Input Sanitization and Validation:**  Strictly validate and sanitize all user inputs *before* they are processed by Struts and potentially used in OGNL expressions. Use allow-lists and robust input validation techniques.
    *   **Minimize OGNL Usage with User Input:**  Redesign application logic to minimize or eliminate the use of user-controlled input directly within OGNL expressions.
    *   **Web Application Firewall (WAF):** Deploy and configure a WAF to detect and block common OGNL injection attack patterns.
    *   **Content Security Policy (CSP):** While not directly preventing OGNL injection, CSP can help mitigate some post-exploitation scenarios.

## Attack Surface: [2. HTTP Parameter Manipulation & Injection via Struts Data Binding](./attack_surfaces/2__http_parameter_manipulation_&_injection_via_struts_data_binding.md)

*   **Description:** Attackers manipulate HTTP parameters, leveraging Struts' data binding mechanism, to inject malicious payloads or alter application flow in unintended ways, leading to command injection, path traversal, or other vulnerabilities.
*   **Struts Contribution:** Struts' core functionality involves automatically mapping HTTP parameters to action properties. This data binding, while convenient, becomes a vulnerability if applications don't rigorously validate these bound properties before using them in sensitive operations. Struts actions are designed to directly consume and process HTTP parameters.
*   **Example:**
    *   **Command Injection via Struts Action:** An action takes a parameter `reportName` and uses it in `Runtime.getRuntime().exec("generate_report.sh " + reportName)`. An attacker injects `reportName="report1.txt; rm -rf /"` to execute a malicious command on the server.
    *   **Path Traversal via Struts Parameter:** An action uses a parameter `template` to load templates: `FileInputStream("templates/" + template + ".ftl")`. An attacker sets `template=../../../../etc/passwd` to access sensitive files outside the intended template directory.
*   **Impact:** Remote Code Execution, Local File Inclusion, Path Traversal, Data Breach, Denial of Service, depending on the injection type and application context.
*   **Risk Severity:** **High** to **Critical** (depending on the specific vulnerability and application's use of parameters)
*   **Mitigation Strategies:**
    *   **Strict Input Validation and Sanitization:** Implement robust input validation and sanitization for all action properties that are bound to HTTP parameters. Validate data type, format, and range. Use allow-lists where possible.
    *   **Secure Coding Practices in Actions:**  Avoid directly using bound parameters in system commands, file paths, or other sensitive operations within Struts actions. Use secure APIs and libraries for these tasks.
    *   **Principle of Least Privilege:** Run the web application with the minimum necessary privileges to limit the impact of successful command injection or other exploits.
    *   **Parameter Tampering Protection:** Consider implementing mechanisms to detect and prevent parameter tampering for sensitive parameters.

## Attack Surface: [3. File Upload Vulnerabilities in Struts File Handling](./attack_surfaces/3__file_upload_vulnerabilities_in_struts_file_handling.md)

*   **Description:** Exploiting weaknesses in Struts' file upload handling to upload malicious files, bypass security controls, or cause denial of service. This is amplified by Struts' built-in file upload features if not secured properly.
*   **Struts Contribution:** Struts provides interceptors and action properties specifically designed for file uploads, simplifying file handling. However, if developers rely solely on Struts' basic features without implementing additional security measures, applications become vulnerable.
*   **Example:**
    *   **Unrestricted JSP Upload via Struts:** An attacker uploads a JSP file containing a web shell through a Struts file upload action. They then access this JSP file directly via the web server to gain remote control of the server.
    *   **Path Traversal Filename in Struts Upload:** An attacker crafts a filename like `../../../../evil.jsp` during upload. If Struts or the application doesn't sanitize filenames properly, this can lead to writing files outside the intended upload directory.
*   **Impact:** Remote Code Execution, Web Shell Upload, Data Breach, Denial of Service, System Instability.
*   **Risk Severity:** **High** to **Critical** (depending on the vulnerability and application's file processing)
*   **Mitigation Strategies:**
    *   **File Type Validation (Strict Allow-list):**  Implement strict file type validation based on both file extension and content (magic bytes). Use an allow-list of permitted file types.
    *   **Filename Sanitization:**  Thoroughly sanitize uploaded filenames to prevent path traversal attacks. Remove or replace characters like `..`, `/`, and `\`.
    *   **File Size Limits:**  Enforce strict limits on the maximum file size to prevent denial of service attacks.
    *   **Dedicated and Secure Upload Directory:** Store uploaded files in a dedicated directory *outside* the web application's document root, with restricted execution permissions.
    *   **Antivirus and Malware Scanning:**  Integrate antivirus or malware scanning of uploaded files before they are processed or stored.

## Attack Surface: [4. Insecure Deserialization Vulnerabilities Related to Struts Components](./attack_surfaces/4__insecure_deserialization_vulnerabilities_related_to_struts_components.md)

*   **Description:** Exploiting insecure deserialization vulnerabilities, particularly those that have historically affected Struts components or libraries used by Struts, to achieve Remote Code Execution.
*   **Struts Contribution:** Older versions of Struts and applications using specific Struts features (or older dependencies like XStream or OGNL versions used by Struts) might be vulnerable to insecure deserialization. Struts' architecture and historical dependency choices have contributed to this attack surface.
*   **Example:** An attacker sends a crafted serialized Java object to the application, potentially as part of a session or request parameter. If the application (or a Struts component) deserializes this object using a vulnerable library (e.g., vulnerable XStream versions previously used with Struts), it can lead to arbitrary code execution during the deserialization process.
*   **Impact:** Remote Code Execution, complete server compromise.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Avoid Deserializing Untrusted Data:**  Minimize or eliminate deserialization of data from untrusted sources, especially HTTP requests and session objects.
    *   **Upgrade Struts and Dependencies:**  Ensure you are using the latest patched versions of Struts and all its dependencies, particularly libraries known to have deserialization vulnerabilities (like XStream, OGNL).
    *   **Object Input Filtering (if deserialization is unavoidable):** If deserialization is absolutely necessary, implement object input filtering to restrict the classes that can be deserialized, preventing the instantiation of dangerous classes.
    *   **Consider Alternative Serialization Formats:**  If possible, switch to safer serialization formats like JSON or Protocol Buffers, which are less prone to deserialization vulnerabilities compared to Java serialization.

## Attack Surface: [5. Vulnerable Struts Version and Outdated Dependencies](./attack_surfaces/5__vulnerable_struts_version_and_outdated_dependencies.md)

*   **Description:** Running applications on outdated and vulnerable versions of the Apache Struts framework itself, or using vulnerable versions of libraries that Struts depends on. This is a direct and critical attack surface introduced by the choice of using Struts and failing to maintain it.
*   **Struts Contribution:**  Struts has a history of critical vulnerabilities, and using older versions directly exposes applications to these known exploits.  Furthermore, Struts relies on numerous third-party libraries, and vulnerabilities in these dependencies also become attack vectors for Struts applications.
*   **Example:** Running a Struts 2 application on a version prior to 2.3.32 or 2.5.10, making it vulnerable to the widely exploited Struts-Shock vulnerability (CVE-2017-5638). Attackers can easily find and exploit such known vulnerabilities in publicly facing applications.
*   **Impact:** Remote Code Execution, Data Breach, complete server compromise, trivial exploitation of well-documented vulnerabilities.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Continuous Struts Version Monitoring:**  Actively monitor for new Struts releases and security advisories. Subscribe to Struts security mailing lists and check the official Apache Struts website regularly.
    *   **Immediate Patching and Upgrading:**  Establish a process for promptly applying security patches and upgrading to the latest stable Struts version as soon as updates are released.
    *   **Dependency Scanning and Management:**  Use dependency scanning tools (SCA - Software Composition Analysis) to identify vulnerable dependencies of Struts. Regularly update these dependencies to their secure versions.
    *   **Automated Vulnerability Scanning:**  Integrate automated vulnerability scanning into your CI/CD pipeline to continuously check for known vulnerabilities in Struts and its dependencies.

