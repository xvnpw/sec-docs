# Attack Surface Analysis for rsyslog/liblognorm

## Attack Surface: [Rulebase Manipulation/Injection](./attack_surfaces/rulebase_manipulationinjection.md)

*   **Description:** Unauthorized modification or injection of rules into the `liblognorm` rulebase, allowing attackers to control log parsing and normalization.
*   **How liblognorm Contributes:** `liblognorm`'s core functionality relies on user-defined rulebases. The library itself provides the mechanism for loading and applying these rules, making the rulebase a central point of control.
*   **Example:** An attacker gains write access to the rulebase file and adds a rule that replaces all instances of "CRITICAL" with "INFO" in log messages, effectively masking critical security events.
*   **Impact:**
    *   Masking of malicious activity.
    *   Denial of service (DoS) through resource-intensive rules.
    *   Extraction of sensitive data.
    *   Triggering of incorrect alerts or actions.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **File Permissions:** Implement strict file system permissions on rulebase files, allowing read-only access to the user running the `liblognorm` process and write access only to authorized administrators.
    *   **Integrity Checks:** Use checksums (e.g., SHA-256) or digital signatures to verify the integrity of rulebase files before loading them. Reject any file that fails the integrity check.
    *   **Secure Configuration Management:** Employ a secure configuration management system (e.g., Ansible, Chef, Puppet) to deploy and manage rulebases, ensuring consistent and controlled updates.
    *   **Auditing:** Enable detailed audit logging of all changes to rulebase files, including who made the changes and when.
    *   **Input Validation (if applicable):** If any part of the rulebase is *influenced* by user input (even indirectly), implement *extremely* strict input validation and sanitization. Prefer a parameterized approach over direct string construction. *Never* allow direct user control over rulebase content.
    *   **Principle of Least Privilege:** Run the process using `liblognorm` with the *minimum* necessary privileges. Avoid running as root.

## Attack Surface: [Parsing Vulnerabilities (Buffer/Integer Overflows)](./attack_surfaces/parsing_vulnerabilities__bufferinteger_overflows_.md)

*   **Description:** Exploitation of vulnerabilities in `liblognorm`'s parsing engine, specifically buffer overflows or integer overflows, potentially leading to code execution or denial of service.
*   **How liblognorm Contributes:** `liblognorm` is responsible for parsing both the rulebase and the incoming log messages. This parsing process, especially when dealing with potentially malformed input, is inherently vulnerable to memory corruption issues.
*   **Example:** An attacker crafts a specially designed log message with an extremely long field that exceeds the buffer allocated by `liblognorm` during parsing, leading to a crash or potentially code execution.
*   **Impact:**
    *   Denial of service (DoS).
    *   Remote code execution (RCE).
    *   System instability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Update Regularly:** Keep `liblognorm` updated to the latest version to benefit from security patches and improvements.
    *   **Memory Safety Tools:** During development and testing, use memory safety tools like AddressSanitizer (ASan), Valgrind, and fuzzing frameworks to detect and fix memory-related vulnerabilities.
    *   **Code Review:** Conduct thorough code reviews of `liblognorm`'s parsing and string handling code, focusing on potential buffer and integer overflow vulnerabilities.
    *   **Input Validation (Pre-liblognorm):** Before passing data to `liblognorm`, perform robust input validation. This includes:
        *   **Length Limits:** Enforce strict length limits on log messages and individual fields.
        *   **Character Restrictions:** Restrict the allowed character set to what is expected for the log format.
    * **Fuzz Testing:** Use fuzz testing tools to send a wide variety of malformed and unexpected inputs to liblognorm to identify potential parsing issues.

