# Mitigation Strategies Analysis for jordansissel/fpm

## Mitigation Strategy: [Pin Dependencies (as used by `fpm`)](./mitigation_strategies/pin_dependencies__as_used_by__fpm__.md)

1.  **Mitigation Strategy:** Pin Dependencies (as used by `fpm`)

    *   **Description:**
        1.  **Identify Dependencies:** List all direct dependencies in your project's dependency specification file (e.g., `Gemfile` for Ruby, `requirements.txt` for Python) that `fpm` will use.
        2.  **Specify Exact Versions:** For each dependency, specify the exact version number.  Instead of `gem 'sinatra'`, use `gem 'sinatra', '2.2.3'`. Avoid version ranges or no specifier.
        3.  **Generate Lockfile:** Use the appropriate tool (e.g., `bundle install` for Ruby, `pip freeze > requirements.txt` or `pipenv`/`poetry` for Python) to generate a lockfile.
        4.  **Commit Lockfile:** Commit the lockfile (e.g., `Gemfile.lock`, `requirements.txt`, `Pipfile.lock`) to version control.
        5.  **Ensure `fpm` Uses Lockfile:** `fpm` *should* automatically use the lockfile if it exists and is appropriate for the input type (e.g., `-s gem` will use `Gemfile.lock`).  This ensures `fpm` pulls the *exact* versions specified, not just any matching version.  There's no explicit `fpm` flag for this; it's inherent in how `fpm` handles different input types.

    *   **Threats Mitigated:**
        *   **Dependency Confusion/Substitution (High Severity):** `fpm` will not pull in a malicious package with a higher version number from a public repository if the exact version is pinned and locked.
        *   **Supply Chain Attacks on Dependencies (High Severity):** `fpm` will use the known-good, locked versions of dependencies, even if a newer, compromised version is published.
        *   **Unintentional Breaking Changes (Medium Severity):** `fpm` will consistently use the same dependency versions, preventing unexpected behavior.

    *   **Impact:**
        *   **Dependency Confusion/Substitution:** Risk significantly reduced (almost eliminated when combined with private repositories, but even without, pinning prevents `fpm` from grabbing the wrong version).
        *   **Supply Chain Attacks on Dependencies:** Risk significantly reduced; `fpm` is locked to specific, known-good versions.
        *   **Unintentional Breaking Changes:** Risk eliminated; `fpm` uses consistent versions.

    *   **Currently Implemented:**
        *   Example: Partially. `Gemfile` uses some version pinning, but `requirements.txt` uses loose versioning. Lockfiles are generated but not consistently checked.

    *   **Missing Implementation:**
        *   Example: `requirements.txt` needs strict version pinning. CI/CD should fail if lockfiles are out-of-date, ensuring `fpm` *always* uses the locked versions.

## Mitigation Strategy: [Controlled Input Source (for `fpm`)](./mitigation_strategies/controlled_input_source__for__fpm__.md)

2.  **Mitigation Strategy:** Controlled Input Source (for `fpm`)

    *   **Description:**
        1.  **Identify `fpm` Input:** Identify all sources of input *directly* provided to `fpm` commands (e.g., directories with `-s dir`, files, command-line arguments).
        2.  **Restrict Sources:** Limit these input sources to trusted locations.  Ideally, this is a dedicated build directory within a CI/CD pipeline, populated only with files from your version control system.
        3.  **Avoid Untrusted Input:** *Never* run `fpm` directly on untrusted user-supplied input (e.g., a directory uploaded by a user).  If user input is *indirectly* involved (e.g., influencing the contents of a build directory), sanitize and validate it *before* it affects the input to `fpm`.
        4.  **CI/CD Integration:** Use a CI/CD pipeline to automate the `fpm` build process.  This ensures `fpm` receives a consistent, controlled set of inputs, pulled from version control and processed in a defined environment.  The CI/CD pipeline itself becomes the "controlled source."

    *   **Threats Mitigated:**
        *   **Path Traversal (High Severity):** Prevents attackers from using malicious input to `fpm` (e.g., a crafted directory structure) to access files outside the intended build directory.
        *   **Arbitrary File Inclusion (High Severity):** Reduces the risk of `fpm` including malicious files in the package if the input source is compromised.
        *   **Code Injection (Critical Severity):** If input files to `fpm` contain code (e.g., scripts), this mitigates the risk of malicious code being injected *through* that input.

    *   **Impact:**
        *   **Path Traversal:** Risk significantly reduced; `fpm` operates within a controlled environment.
        *   **Arbitrary File Inclusion:** Risk significantly reduced; `fpm`'s input is restricted.
        *   **Code Injection:** Risk significantly reduced; `fpm`'s input comes from a trusted source (version control).

    *   **Currently Implemented:**
        *   Example: Partially. `fpm` is *usually* run in CI/CD, but manual builds exist.

    *   **Missing Implementation:**
        *   Example: Eliminate all manual `fpm` invocations.  Ensure the CI/CD pipeline is the *only* way packages are built with `fpm`.  Add input validation *within* the CI/CD pipeline to check for suspicious file names or content *before* `fpm` is invoked.

## Mitigation Strategy: [Keep `fpm` Updated](./mitigation_strategies/keep__fpm__updated.md)

3.  **Mitigation Strategy:** Keep `fpm` Updated

    *   **Description:**
        1.  **Monitor Releases:** Regularly check for new `fpm` releases (GitHub, RubyGems.org).
        2.  **Update Command:** When a new version is available, update `fpm`.  This is typically done via `gem update fpm` (if installed as a gem) or your system's package manager. This directly impacts `fpm`'s behavior.
        3.  **Test After Update:** After updating `fpm`, run your test suite to ensure no regressions were introduced.

    *   **Threats Mitigated:**
        *   **Vulnerabilities in `fpm` Itself (Variable Severity):** Reduces the risk of exploiting known vulnerabilities *within* `fpm`. These could allow an attacker to control the build or the resulting package.

    *   **Impact:**
        *   **Vulnerabilities in `fpm` Itself:** Risk reduced (depends on the specific vulnerabilities patched).

    *   **Currently Implemented:**
        *   Example: Partially. `fpm` is updated periodically, but not automatically.

    *   **Missing Implementation:**
        *   Example: Automate checking for new `fpm` releases and updating it in the development environment and CI/CD pipeline.

## Mitigation Strategy: [Minimize and Review Scripts (used *by* `fpm`)](./mitigation_strategies/minimize_and_review_scripts__used_by__fpm__.md)

4. **Mitigation Strategy:** Minimize and Review Scripts (used *by* `fpm`)

    *   **Description:**
        1.  **Identify Scripts:** Identify all pre/post-install/uninstall scripts that `fpm` will include in the generated package. These might be explicitly provided to `fpm` (e.g., using `--before-install`, `--after-install` flags) or implicitly generated by `fpm` based on the input type (e.g., from a `control` file in a Debian source directory).
        2.  **Justify Necessity:** For *each* script, determine if it's absolutely required. Can the functionality be achieved declaratively (e.g., through package dependencies or configuration files)?
        3.  **Simplify:** If a script is necessary, keep it as short and simple as possible. Avoid complex logic.
        4.  **Review for Vulnerabilities:** Thoroughly review each script for:
            *   **Shell Injection:** Ensure user input is *never* used directly in shell commands without proper escaping. Use parameterized commands or libraries.
            *   **Hardcoded Credentials:** Never store credentials in scripts. Use environment variables or secure configuration.
            *   **Unnecessary Privileges:** Scripts should run with the *minimum* necessary privileges. Avoid running as root unless absolutely required.
            *   **External Calls:** Minimize/eliminate calls to external commands (e.g., `curl`, `wget`). If unavoidable, verify downloaded resource integrity (checksums).
        5. **Provide to fpm securely:** When providing scripts to fpm (using flags like `--before-install`), ensure the script files themselves come from a trusted source (version control).
        6. **Automated checks:** Use linters and static analysis tools to automatically check for common scripting errors and vulnerabilities.

    *   **Threats Mitigated:**
        *   **Arbitrary Code Execution (Critical Severity):** Reduces the risk of an attacker injecting malicious code into scripts that `fpm` includes in the package, which are then executed during installation.
        *   **Privilege Escalation (High Severity):** Prevents scripts included by `fpm` from running with unnecessary privileges.
        *   **Information Disclosure (Medium Severity):** Reduces the risk of sensitive information leaks through scripts included by `fpm`.

    *   **Impact:**
        *   **Arbitrary Code Execution:** Risk significantly reduced (but not eliminated, as scripts might still exist).
        *   **Privilege Escalation:** Risk significantly reduced.
        *   **Information Disclosure:** Risk reduced.

    *   **Currently Implemented:**
        *   Example: Partially. Some scripts exist, but they haven't been thoroughly reviewed.

    *   **Missing Implementation:**
        *   Example: Comprehensive script review is needed. Simplify scripts. Add automated checks for scripting vulnerabilities to the CI/CD pipeline *before* `fpm` is invoked.

