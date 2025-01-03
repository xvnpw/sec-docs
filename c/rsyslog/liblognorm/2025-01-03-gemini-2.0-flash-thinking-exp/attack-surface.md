# Attack Surface Analysis for rsyslog/liblognorm

## Attack Surface: [Malicious Log Message Injection](./attack_surfaces/malicious_log_message_injection.md)

- **Description:**  An attacker crafts malicious log messages that, when processed by `liblognorm`, exploit vulnerabilities in its parsing logic.
- **How Liblognorm Contributes:** Liblognorm's core function is to parse and normalize log messages based on defined rules. If these rules or the underlying parsing engine have vulnerabilities, specially crafted input can trigger unintended behavior.
- **Example:** An attacker sends a log message containing an excessively long string or a specific sequence of characters that causes a buffer overflow or excessive resource consumption within `liblognorm` during parsing.
- **Impact:** Denial of Service (DoS), potential crashes of the application using `liblognorm`, or in severe cases, remote code execution if vulnerabilities in the parsing logic are exploitable.
- **Risk Severity:** High to Critical.
- **Mitigation Strategies:**
    - Implement strict input validation *before* passing log messages to `liblognorm`. Sanitize or reject messages that don't conform to expected formats or contain suspicious patterns.
    - Stay updated with the latest versions of `liblognorm` to benefit from bug fixes and security patches.
    - Consider using a sandboxed environment for `liblognorm` processing if feasible, to limit the impact of potential exploits.

## Attack Surface: [Exploitation of Rule Definition Vulnerabilities](./attack_surfaces/exploitation_of_rule_definition_vulnerabilities.md)

- **Description:** Attackers exploit vulnerabilities related to how `liblognorm` rules are defined, loaded, or processed.
- **How Liblognorm Contributes:** `liblognorm` relies on external rule files to understand the structure of log messages. If these rules are writable by untrusted users or loaded from untrusted sources, attackers can inject malicious rules.
- **Example:** An attacker modifies a rule file to misinterpret certain log messages, causing them to be dropped or incorrectly parsed, potentially hiding malicious activity. Alternatively, a malicious rule with a complex regular expression could be injected, leading to ReDoS (Regular Expression Denial of Service).
- **Impact:**  Incorrect log interpretation, masking of security events, Denial of Service due to ReDoS.
- **Risk Severity:** High.
- **Mitigation Strategies:**
    - Secure the storage and access permissions for `liblognorm` rule files. Ensure only trusted users can modify them.
    - Implement integrity checks for rule files to detect unauthorized modifications.
    - Carefully review and test all rule files before deployment, paying attention to the complexity and potential for ReDoS in regular expressions.
    - Load rule files from trusted and controlled sources only.

