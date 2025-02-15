# Threat Model Analysis for jordansissel/fpm

## Threat: [Malicious File Inclusion](./threats/malicious_file_inclusion.md)

*   **Threat:** Malicious File Inclusion
    *   **Description:** An attacker crafts the input directory structure or files provided to `fpm` to include malicious code (e.g., a shell script, a trojaned binary, or files with malicious content). The attacker might leverage symbolic links or hard links (if not handled properly by `fpm`) to include files outside the intended source directory. They could also exploit file parsing vulnerabilities *within fpm itself* if any exist for specific file types it handles.
    *   **Impact:** The generated package will contain the malicious code.  When the package is installed, this code will be executed, potentially leading to arbitrary code execution, data breaches, or complete system compromise.
    *   **Affected fpm Component:** Primarily the file system input handling (common to all source types like `-s dir`), and potentially specific parsers for different source types if they have vulnerabilities. The core package creation logic is also affected.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Use a dedicated, clean build environment. Do not allow untrusted users to modify the source directory or any input provided to `fpm`.
        *   **Checksum Verification:** Calculate checksums (e.g., SHA256) of *all* input files *before* passing them to `fpm` and verify them against a known-good list. This is crucial.
        *   **Least Privilege:** Run `fpm` with the *least* necessary privileges.  Absolutely avoid running as root.
        *   **Chroot/Containerization:** Use a chroot jail or a container (e.g., Docker) to isolate the build process, severely limiting the impact of any successful exploit.
        *   **File Type Whitelisting:** If possible (and practical), restrict the types of files that `fpm` is allowed to include in the package.
        *   **Secure Symbolic Link Handling:** Configure `fpm` (if such options exist) or the build environment to handle symbolic links safely, preventing them from pointing outside the intended source directory.  Consider disabling symbolic link following entirely if it's not strictly required.

## Threat: [Argument Injection (Command-Line Manipulation)](./threats/argument_injection__command-line_manipulation_.md)

*   **Threat:** Argument Injection (Command-Line Manipulation)
    *   **Description:** An attacker gains the ability to modify the command-line arguments passed to `fpm`. This could be through a compromised build script, environment variable manipulation, or a vulnerability in a system that invokes `fpm`. The attacker injects malicious options, *most critically* specifying an arbitrary `--after-install` (or similar) script, or manipulating other options that control package behavior.
    *   **Impact:** The attacker can control `fpm`'s behavior, leading to arbitrary code execution (especially through injected scripts), creation of packages with malicious settings, or potentially data leakage. The most severe impact is the execution of attacker-controlled scripts during package installation.
    *   **Affected fpm Component:** The command-line argument parsing logic (`FPM::Command` and related components).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Sanitization:** *Strictly* sanitize and validate *all* input to `fpm`, including command-line arguments and environment variables. Assume *all* input is potentially malicious.
        *   **Controlled Invocation:** Use a well-defined, *controlled* wrapper script to invoke `fpm`.  *Never* construct `fpm` command lines dynamically based on untrusted input.
        *   **Principle of Least Privilege:** Run the script that invokes `fpm` (and `fpm` itself) with the least necessary privileges.
        *   **Hardcoded Arguments:** Where possible, hardcode safe and necessary arguments directly in the build script, rather than relying on external input or environment variables.

## Threat: [Template Injection (Custom Script Manipulation)](./threats/template_injection__custom_script_manipulation_.md)

*   **Threat:** Template Injection (Custom Script Manipulation)
    *   **Description:** If custom templates are used with the `-t` option (and a templating engine like ERB), an attacker who can modify these template files can inject arbitrary code or commands. This code will be executed during package creation or, *more critically*, during package installation on the target system. This is a direct code injection vulnerability.
    *   **Impact:** This can lead to arbitrary code execution, either during the build process (less severe) or, *much more dangerously*, on the target system when the package is installed. This is equivalent to a remote code execution vulnerability.
    *   **Affected fpm Component:** The template processing logic (e.g., `FPM::Package#template`, the specific templating engine used, and how it interacts with `fpm`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Secure Template Storage:** Store templates in a *secure* location with *strictly restricted* write access. Only *highly trusted* users should be able to modify them.
        *   **Template Integrity Verification:** Calculate checksums of the template files and verify them *before* use. This detects any unauthorized modification.
        *   **Template Review:** *Thoroughly* review templates for *any* potentially dangerous constructs or code that could be exploited. Look for any way user input could influence the template output.
        *   **Input Validation (within templates):** If templates *must* accept any input, ensure that this input is *rigorously* sanitized and validated *within the template itself* using the templating language's features.
        *   **Sandboxed Templating:** If possible, use a templating engine that provides *strong* sandboxing capabilities to limit the code that can be executed within the template. This is the best defense.

## Threat: [Sensitive Data Leakage](./threats/sensitive_data_leakage.md)

*   **Threat:** Sensitive Data Leakage
    *   **Description:** `fpm` inadvertently includes sensitive files or directories in the package. This could happen if the input directory is not carefully controlled, or if `fpm` is configured incorrectly. Examples include API keys, passwords, private keys, or internal documentation.
    *   **Impact:** Sensitive information is exposed to anyone who obtains the package, potentially leading to unauthorized access, data breaches, or other security compromises.
    *   **Affected fpm Component:** File system input handling and the overall package creation process.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Careful Input Selection:** Define the input directory precisely and exclude any sensitive files or directories.
        *   **Exclusion Patterns:** Use a `.gitignore`-like mechanism or `fpm`'s exclusion options (if available) to explicitly exclude sensitive files.
        *   **Package Content Review:** Thoroughly review the contents of the generated package *before* distribution to ensure that no sensitive data has been included. Use tools specific to the package format to inspect the contents.
        *   **Environment Variable Handling:** Be cautious about including environment variables in the package. If necessary, use a secure mechanism for managing secrets (e.g., a secrets management service).

