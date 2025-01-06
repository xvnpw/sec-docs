# Threat Model Analysis for apache/struts

## Threat: [OGNL Injection via HTTP Parameters](./threats/ognl_injection_via_http_parameters.md)

**Description:** Attackers craft malicious HTTP requests containing specially crafted OGNL expressions within parameters. Struts, when processing these parameters, evaluates the OGNL expression, leading to arbitrary code execution on the server. This can be achieved through GET or POST requests.

**Impact:** Full compromise of the server, including reading sensitive data, modifying files, installing malware, and potentially pivoting to other systems on the network.

**Risk Severity:** Critical

## Threat: [OGNL Injection via HTTP Headers](./threats/ognl_injection_via_http_headers.md)

**Description:** Similar to parameter injection, attackers inject malicious OGNL expressions into HTTP headers that are processed by Struts. This can occur if the application or custom interceptors process header values using OGNL.

**Impact:** Same as OGNL injection via parameters: full server compromise.

**Risk Severity:** Critical

## Threat: [File Upload Vulnerabilities leading to Remote Code Execution](./threats/file_upload_vulnerabilities_leading_to_remote_code_execution.md)

**Description:** Attackers upload malicious files (e.g., JSP, WAR) through Struts' file upload functionality due to insufficient validation of file types, names, or content. If these files are placed in an accessible location within the web application, they can be executed by the server.

**Impact:** Remote code execution, allowing attackers to gain control of the server.

**Risk Severity:** Critical

## Threat: [Forced Double Evaluation of OGNL Expressions](./threats/forced_double_evaluation_of_ognl_expressions.md)

**Description:** Attackers exploit scenarios where Struts evaluates OGNL expressions multiple times due to specific configurations or coding patterns. This can be used to bypass security checks or trigger unintended actions by manipulating the evaluation context.

**Impact:** Can lead to remote code execution or privilege escalation, depending on the specific context of the double evaluation.

**Risk Severity:** High

## Threat: [File Upload Vulnerabilities leading to Path Traversal](./threats/file_upload_vulnerabilities_leading_to_path_traversal.md)

**Description:** Attackers manipulate file names during the upload process to include path traversal sequences (e.g., `../../`) to overwrite critical system files or place uploaded files in unintended locations.

**Impact:** Overwriting critical files can lead to denial of service or system compromise. Placing files in unintended locations might expose sensitive information or facilitate further attacks.

**Risk Severity:** High

## Threat: [Exploiting Dynamic Method Invocation (DMI) (if enabled)](./threats/exploiting_dynamic_method_invocation__dmi___if_enabled_.md)

**Description:** If DMI is enabled (which is often disabled by default in newer versions), attackers can directly call methods on Struts actions by manipulating URL parameters. This can bypass intended execution flows and potentially lead to arbitrary code execution if not strictly controlled.

**Impact:** Remote code execution.

**Risk Severity:** Critical

