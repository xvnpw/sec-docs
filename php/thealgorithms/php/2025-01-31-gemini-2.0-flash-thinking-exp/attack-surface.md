# Attack Surface Analysis for thealgorithms/php

## Attack Surface: [Unsafe Deserialization](./attack_surfaces/unsafe_deserialization.md)

*   **Description:** Exploiting PHP's `unserialize()` function to achieve Remote Code Execution (RCE) by providing maliciously crafted serialized data.
*   **PHP Contribution:** PHP's built-in `unserialize()` function is inherently vulnerable when used on untrusted data. It allows object instantiation and execution of magic methods during deserialization, creating a direct path to RCE if attacker-controlled serialized data is processed.
*   **Example:** An attacker sends a crafted serialized PHP object in a cookie or POST parameter. If the application uses `unserialize($_COOKIE['data'])` without proper validation, the malicious object is deserialized, and its embedded code is executed on the server.
*   **Impact:** Remote Code Execution (RCE), complete server compromise, data breaches, and service disruption.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strongly avoid using `unserialize()` on untrusted data.** Prefer safer data formats like JSON and `json_decode()`.
    *   If `unserialize()` is absolutely necessary, implement robust input validation, signature verification, and object whitelisting before deserialization. Consider using safer alternatives like `igbinary_unserialize` with input validation.

## Attack Surface: [File Inclusion Vulnerabilities (Local File Inclusion - LFI & Remote File Inclusion - RFI)](./attack_surfaces/file_inclusion_vulnerabilities__local_file_inclusion_-_lfi_&_remote_file_inclusion_-_rfi_.md)

*   **Description:** Exploiting PHP's file inclusion functions (`include`, `require`, `include_once`, `require_once`) to include and execute arbitrary files, either from the local filesystem (LFI) or from remote URLs (RFI).
*   **PHP Contribution:** PHP's design allows dynamic file inclusion using functions like `include` and `require`. If the file path argument to these functions is derived from user input without proper sanitization, attackers can manipulate the path to include unintended files.
*   **Example:** An application uses `include($_GET['file']);` to include template files. An attacker can manipulate the `file` parameter to access sensitive local files like `/etc/passwd` (LFI) by using path traversal techniques (e.g., `../../../../etc/passwd`). If `allow_url_include` is enabled, they could also include and execute code from a remote server (RFI) by providing a URL.
*   **Impact:**
    *   **RFI:** Remote Code Execution (RCE), full server compromise.
    *   **LFI:** Information disclosure (reading sensitive files), potentially Local Code Execution (if combined with other vulnerabilities like file upload or log poisoning).
*   **Risk Severity:** **Critical** (RFI), **High** (LFI)
*   **Mitigation Strategies:**
    *   **Avoid dynamic file inclusion based on user input whenever possible.**
    *   If dynamic inclusion is necessary, use a strict whitelist of allowed files or paths.
    *   Sanitize and validate user input rigorously to prevent path traversal attacks. Remove characters like `../`, `./`, and ensure paths are relative to a safe base directory.
    *   **Disable `allow_url_include` in PHP configuration to prevent RFI vulnerabilities.** This is a crucial security hardening step.

## Attack Surface: [Remote Code Execution (RCE) via Vulnerable PHP Functions](./attack_surfaces/remote_code_execution__rce__via_vulnerable_php_functions.md)

*   **Description:** Exploiting dangerous PHP functions that allow direct execution of system commands or arbitrary PHP code when used with user-controlled input.
*   **PHP Contribution:** PHP provides powerful but dangerous functions like `eval()`, `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, and `proc_open()`. These functions, if used carelessly with unsanitized user input, become direct vectors for attackers to execute arbitrary code on the server.
*   **Example:** An application uses `eval($_POST['code']);` to dynamically execute code provided by the user. An attacker can send malicious PHP code in the `code` parameter, which will be directly executed by the `eval()` function, leading to RCE. Similarly, using `system("command " . $_GET['input']);` without sanitization allows command injection.
*   **Impact:** Remote Code Execution (RCE), complete server compromise, data breaches, and service disruption.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Absolutely avoid using dangerous functions like `eval()`, `system()`, `exec()`, etc., especially with user-provided input.**  These functions should be considered extremely risky and avoided in most web application development scenarios.
    *   If system commands are absolutely necessary, use safer alternatives like `proc_open()` with extremely strict input validation and sanitization. Parameterize commands whenever possible to avoid direct string concatenation of user input into shell commands.
    *   Explore alternative approaches that do not require executing arbitrary code or system commands. Refactor application logic to avoid reliance on these dangerous functions.

