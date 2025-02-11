# Mitigation Strategies Analysis for jenkinsci/pipeline-model-definition-plugin

## Mitigation Strategy: [Strict `Jenkinsfile` Source Control](./mitigation_strategies/strict__jenkinsfile__source_control.md)

**Description:**
1.  **Establish a Git Repository:**  The `Jenkinsfile` (which defines the Declarative Pipeline) *must* be stored in a Git repository.
2.  **Branching Model:** Use a branching model (e.g., Gitflow) with feature branches and pull requests for merging to the `main` branch.
3.  **Branch Protection:** Configure branch protection on `main`:
    *   Require pull request reviews.
    *   Require status checks (builds, tests).
    *   Restrict direct pushes.
4.  **Code Reviews:** *Mandatory* code reviews for *all* `Jenkinsfile` changes, specifically checking for:
    *   Code injection in Groovy.
    *   Secret exposure.
    *   `script` block misuse.
    *   Parameter misuse.
    *   `when` condition logic.
5.  **Commit Signing (Recommended):** Developers sign commits (GPG/SSH).
6.  **Regular Access Audits:**  Review repository access and permissions.

*   **Threats Mitigated:**
    *   **Code Injection (Severity: Critical):** Prevents direct injection of malicious Groovy code into the `Jenkinsfile`.
    *   **Unauthorized Changes (Severity: High):** Ensures all `Jenkinsfile` changes are reviewed/approved.
    *   **Compromised Developer Accounts (Severity: High):** Limits the impact of compromised accounts on the `Jenkinsfile`.

*   **Impact:**
    *   **Code Injection:** Risk significantly reduced (Critical to Low/Medium).
    *   **Unauthorized Changes:** Risk significantly reduced (High to Low).
    *   **Compromised Accounts:** Impact mitigated.

*   **Currently Implemented:**
    *   *Example:* "Implemented for `infrastructure-pipelines` repo. Branch protection on `main`, one reviewer required, CI checks enforced. Code reviews mandatory."

*   **Missing Implementation:**
    *   *Example:* "Commit signing not implemented. Access audits ad-hoc. `application-pipelines` repo lacks branch protection."

## Mitigation Strategy: [Parameter Sanitization and Validation (within the Pipeline)](./mitigation_strategies/parameter_sanitization_and_validation__within_the_pipeline_.md)

**Description:**
1.  **Identify All Parameters:** List all parameters the pipeline accepts.
2.  **Define Expected Types:** Determine data type and constraints for each parameter.
3.  **Implement Validation (in Groovy):**
    *   **String:** Use regular expressions (e.g., `^[a-zA-Z0-9]+$`).
    *   **Integer:** Parse as integer, use `try-catch`.
    *   **Boolean:** Accept "true"/"false" (case-insensitive).
    *   **Choice:** Define allowed values.
    *   **Avoid Direct Interpolation:** *Never* directly embed parameters in shell/Groovy without escaping/sanitization.
4.  **Safe `params` Object Use:** Access via `params`, be aware of types, use type-safe methods.
5.  **Reject Invalid Input:** Fail build or use a safe default.
6.  **Input Sanitization (Groovy):** If input is used as code (HTML, SQL), sanitize it (HTML escaping, URL encoding, etc., using Groovy libraries).

*   **Threats Mitigated:**
    *   **Code Injection (Severity: Critical):** Prevents injecting malicious code via pipeline parameters.
    *   **Cross-Site Scripting (XSS) (Severity: High):** Mitigates XSS if input is displayed (relevant for `input` step).
    *   **Unexpected Behavior (Severity: Medium):** Prevents unexpected behavior from invalid input.

*   **Impact:**
    *   **Code Injection:** Risk significantly reduced (Critical to Low/Medium).
    *   **XSS:** Risk significantly reduced (High to Low).
    *   **Unexpected Behavior:** Risk reduced (Medium to Low).

*   **Currently Implemented:**
    *   *Example:* "Basic validation in `deploy-application` pipeline using regex, but not consistent."

*   **Missing Implementation:**
    *   *Example:* "Comprehensive validation missing in `build-image` pipeline. XSS sanitization missing for `input` steps."

## Mitigation Strategy: [Limit the Use of `script` Blocks](./mitigation_strategies/limit_the_use_of__script__blocks.md)

**Description:**
1.  **Prefer Declarative Directives:** Use built-in directives (`agent`, `stages`, `steps`, `post`, etc.) over `script` blocks.
2.  **Minimize `script` Block Code:** If unavoidable, keep `script` blocks short and simple.
3.  **Justify and Review:** Every `script` block *must* be justified in a comment and thoroughly reviewed, assessing:
    *   Could it be a Declarative directive?
    *   Security implications of the code.
    *   Code injection potential.
4.  **Isolate `script` Blocks:** If interacting with sensitive data, isolate in a separate stage, use `withCredentials`.

*   **Threats Mitigated:**
    *   **Code Injection (Severity: Critical):** Reduces the attack surface for Groovy code injection.
    *   **Increased Complexity (Severity: Medium):** Makes the pipeline easier to understand, reducing vulnerability likelihood.

*   **Impact:**
    *   **Code Injection:** Risk reduced (Critical to Medium/High).
    *   **Increased Complexity:** Complexity reduced.

*   **Currently Implemented:**
    *   *Example:* "Team encouraged to use Declarative directives, but no formal policy. Older pipelines use many `script` blocks."

*   **Missing Implementation:**
    *   *Example:* "Formal review process for `script` blocks missing. No automated check for excessive use."

## Mitigation Strategy: [Secure Secret Management (within the Pipeline)](./mitigation_strategies/secure_secret_management__within_the_pipeline_.md)

**Description:**
1.  **Jenkins Credentials Plugin:** *All* secrets (passwords, API keys, etc.) *must* be stored using the Jenkins Credentials plugin. *Never* hardcode.
2.  **Appropriate Credential Type:** Use the correct type (Secret text, Username with password, etc.).
3.  **`withCredentials` Binding:** Use `withCredentials` to bind secrets to environment variables *only within the stage they are needed*.
4.  **Avoid Echoing:** Do *not* print secret environment variables.
5.  **Mask Passwords (Global Setting):** Enable "Mask Passwords" in Jenkins global configuration.
6.  **Regular Rotation:** Rotate secrets and update Jenkins credentials.
7. **Least Privilege:** Grant access to credentials only to the pipelines and users that require them.

*   **Threats Mitigated:**
    *   **Secret Exposure (Severity: Critical):** Prevents exposure in `Jenkinsfile`, logs, or environment.
    *   **Credential Theft (Severity: High):** Reduces impact by limiting scope and rotating secrets.

*   **Impact:**
    *   **Secret Exposure:** Risk significantly reduced (Critical to Low).
    *   **Credential Theft:** Impact reduced.

*   **Currently Implemented:**
    *   *Example:* "Credentials plugin used. `withCredentials` mostly used, but inconsistencies exist."

*   **Missing Implementation:**
    *   *Example:* "Secret rotation not automated. 'Mask Passwords' not enabled. Older pipelines may have hardcoded secrets."

## Mitigation Strategy: [Controlled Shared Library Usage (with Declarative)](./mitigation_strategies/controlled_shared_library_usage__with_declarative_.md)

**Description:**
1.  **Secure Shared Library Repo:** Separate, secure Git repo, same controls as `Jenkinsfile` repo.
2.  **Version Control:** Semantic versioning. Pipelines specify the *exact* version (e.g., `@Library('my-lib@1.2.3') _`).
3.  **Code Reviews:** Rigorous code reviews for shared libraries, focusing on security.
4.  **Dependency Management:** Scan for vulnerabilities in dependencies (OWASP Dependency-Check, Snyk).
5.  **Restrict Access:** Limit which pipelines can load specific libraries.
6.  **Testing:** Thorough unit/integration tests for shared libraries.
7. **Secure Loading:** Ensure libraries are loaded from a trusted source and integrity is verified.

*   **Threats Mitigated:**
    *   **Code Injection (Severity: Critical):** Prevents malicious code via compromised shared libraries.
    *   **Dependency Vulnerabilities (Severity: High):** Reduces risk from vulnerable dependencies.
    *   **Unauthorized Code Execution (Severity: High):** Prevents unauthorized pipelines from using privileged libraries.

*   **Impact:**
    *   **Code Injection:** Risk significantly reduced (Critical to Low/Medium).
    *   **Dependency Vulnerabilities:** Risk reduced (High to Medium/Low).
    *   **Unauthorized Code Execution:** Risk reduced (High to Low).

*   **Currently Implemented:**
    *   *Example:* "Shared libraries in separate Git repo, code reviews required. Versioning used, but not always enforced."

*   **Missing Implementation:**
    *   *Example:* "Dependency scanning not automated. Access controls for libraries not configured. Limited testing."

## Mitigation Strategy: [Simple and Secure `when` Conditions](./mitigation_strategies/simple_and_secure__when__conditions.md)

**Description:**
1.  **Prefer Built-in Conditions:** Use built-in `when` conditions (`branch`, `environment`, etc.) over custom Groovy.
2.  **Keep it Simple:** Avoid complex, nested `when` conditions. Refactor to shared library functions if needed (with security).
3.  **Avoid Untrusted Input:** Do *not* use user input directly in `when` conditions, especially `expression`. Validate/sanitize first.
4.  **Thorough Testing:** Test `when` conditions extensively with various inputs.
5.  **Code Review Focus:** Reviews *must* examine `when` conditions for logic errors, bypasses, injection.

*   **Threats Mitigated:**
    *   **Logic Errors/Bypasses (Severity: Medium/High):** Prevents unintended stage execution/skipping.
    *   **Code Injection (Severity: Critical):** Reduces risk if input is used in `when` (especially `expression`).

*   **Impact:**
    *   **Logic Errors/Bypasses:** Risk reduced (Medium/High to Low).
    *   **Code Injection:** Risk reduced (Critical to Low/Medium).

*   **Currently Implemented:**
    *   *Example:* "No specific guidelines on `when` condition complexity."

*   **Missing Implementation:**
    *   *Example:* "Code reviews don't consistently focus on `when` security. No automated check for complex/vulnerable conditions."

## Mitigation Strategy: [Secure `input` Step Configuration (within the Pipeline)](./mitigation_strategies/secure__input__step_configuration__within_the_pipeline_.md)

**Description:**
1.  **Sanitize Input (Groovy):** *Always* sanitize user input from `input` *before* using it where it could be interpreted as code.
    *   **HTML Escaping:** Use `StringEscapeUtils` or similar for web display.
    *   **URL Encoding:** For URLs.
    *   **Shell Escaping:** For shell commands (avoid direct interpolation; use parameters).
2.  **Restrict Input Types:** Use specific types (`choice`, `booleanParam`, `password`) over `string`.
3.  **Validate Input (Groovy):** Implement validation rules, even with sanitization.
4.  **Limit Input Scope:** Use `input` only in specific stages where necessary.
5.  **Avoid Sensitive Data:** Do *not* use `input` for secrets. Use Credentials plugin.
6. **Timeout:** Set a reasonable timeout for the `input` step.

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) (Severity: High):** Prevents injecting JavaScript via `input`.
    *   **Code Injection (Severity: Critical):** Prevents injecting code (e.g., shell) via `input`.
    *   **Denial of Service (DoS) (Severity: Medium):** Timeout prevents indefinite blocking.

*   **Impact:**
    *   **XSS:** Risk significantly reduced (High to Low).
    *   **Code Injection:** Risk significantly reduced (Critical to Low/Medium).
    *   **DoS:** Risk reduced (Medium to Low).

*   **Currently Implemented:**
    *   *Example:* "`input` used in a few pipelines, but sanitization inconsistent."

*   **Missing Implementation:**
    *   *Example:* "No HTML escaping or sanitization for `input` data. Validation is basic."

