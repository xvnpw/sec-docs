# Attack Surface Analysis for realm/jazzy

## Attack Surface: [Information Disclosure of Internal APIs](./attack_surfaces/information_disclosure_of_internal_apis.md)

*   **Description:** Exposure of internal, non-public APIs that were not intended for external use.  These APIs may have weaker security controls.
    *   **How Jazzy Contributes:** Jazzy can generate documentation for internal APIs if not configured correctly (e.g., using `--min-acl internal` or `--min-acl private`). This is a *direct* contribution of Jazzy to the attack surface.
    *   **Example:** An internal API endpoint `/admin/deleteUser` is documented, revealing its existence and parameters. An attacker could attempt to call this endpoint directly.
    *   **Impact:** Unauthorized access to sensitive data, modification of data, or disruption of service.
    *   **Risk Severity:** **High** to **Critical** (depending on the sensitivity of the exposed API).
    *   **Mitigation Strategies:**
        *   **Strict ACL Control:** Use `--min-acl public` (the default) in Jazzy configuration.
        *   **Code Annotations:** Use appropriate access control modifiers (e.g., `private`, `internal`) in the source code.
        *   **Documentation Review:** Manually review generated documentation.
        *   **Separate Documentation Builds:** Generate internal documentation separately and keep it private.

## Attack Surface: [Example Code with Sensitive Data](./attack_surfaces/example_code_with_sensitive_data.md)

*   **Description:** Inclusion of hardcoded credentials, API keys, or other sensitive data within example code snippets.
    *   **How Jazzy Contributes:** Jazzy directly includes example code snippets from the source code in the generated documentation. This is a *direct* action of Jazzy.
    *   **Example:** An example code snippet showing API usage includes a hardcoded API key.
    *   **Impact:** Direct exposure of sensitive credentials, leading to unauthorized access.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Never Hardcode Credentials:** Avoid hardcoding credentials in the source code, *especially* in examples.
        *   **Use Placeholders:** Use placeholder values (e.g., `YOUR_API_KEY`) in example code.
        *   **Automated Scanning:** Use tools to scan for potential secrets in documentation and code.
        *   **Code Review:** Thoroughly review all example code before documentation generation.

