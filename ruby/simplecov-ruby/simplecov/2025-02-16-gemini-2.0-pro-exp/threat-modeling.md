# Threat Model Analysis for simplecov-ruby/simplecov

## Threat: [T4: Sensitive Data Exposure in Reports](./threats/t4_sensitive_data_exposure_in_reports.md)

*   **Threat:** T4: Sensitive Data Exposure in Reports

    *   **Description:** The application's code or tests contain hardcoded secrets (API keys, passwords, etc.). These secrets are present in code paths that are *executed* during test runs. Because SimpleCov displays the executed source code lines in its HTML reports, these secrets are revealed to anyone with access to the reports. This is a *direct* consequence of SimpleCov showing executed code, although the root cause is the presence of secrets in the code.
    *   **Impact:** The attacker gains access to sensitive credentials, potentially allowing them to compromise other systems or data. This is a severe impact.
    *   **Affected SimpleCov Component:** `SimpleCov::SourceFile`. This component is responsible for displaying the source code, including any sensitive data present in executed lines. The `SimpleCov::Formatter::HTMLFormatter` then renders this information in the HTML report.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Secrets Management:** *Never* hardcode secrets in the codebase. Use environment variables, configuration files (stored securely outside the code repository), or dedicated secrets management solutions (e.g., HashiCorp Vault, AWS Secrets Manager, environment-specific configuration).
        *   **Code Review:** Thoroughly review code (both application code *and* test code) for any hardcoded secrets. This should be a mandatory part of the code review process.
        *   **Static Analysis:** Use static analysis tools (e.g., linters with security plugins, dedicated secret scanning tools) to automatically detect and flag hardcoded secrets. Examples include `trufflehog`, `gitleaks`, and linters configured to detect patterns associated with secrets.
        *   **Pre-commit Hooks:** Implement pre-commit hooks that run static analysis tools to prevent secrets from being committed to the repository.

