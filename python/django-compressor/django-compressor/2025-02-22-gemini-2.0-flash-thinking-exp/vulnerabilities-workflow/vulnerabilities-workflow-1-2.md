- **Vulnerability Name:** Command Injection via External Precompiler Execution

  - **Description:**  
    Django Compressor builds external precompiler commands (for example, for processing CoffeeScript, Less, etc.) by substituting parameters into a command template. The command template—sourced from configuration settings—is formatted using Python’s string formatting. While file path parameters (such as `{infile}` and `{outfile}`) are sanitized using a shell‑quoting function on non‑Windows platforms, other placeholders (such as parts of the command template itself and/or optional unsanitized parameters) are not further validated. An attacker who is able to influence any of these unsanitized configuration values (for example, via a misconfiguration that inadvertently exposes settings or by controlling file names in a static assets directory) may be able to break out of the intended command format to inject arbitrary shell commands.  
    **Step-by-step trigger:**  
    1. Override a precompiler setting (for a file type or via misconfiguration) with a command template that includes a placeholder that is not shell‑quoted (for example, `{extra}`).
    2. Supply attacker-controlled input containing shell metacharacters (for example, `"; rm -rf /"`) that ends up substituted into the unsanitized placeholder.
    3. When Django Compressor calls the external precompiler (via the `CompilerFilter.input()` method), the final command string is constructed and passed to `subprocess.Popen()` with `shell=True`, which results in the injected command being executed by the host’s shell.

  - **Impact:**  
    With arbitrary shell command execution, an attacker may achieve full system compromise. The execution of unintended commands could lead to data loss, service disruption, or complete control over the server environment.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**  
    - File path parameters (i.e. `{infile}` and `{outfile}`) are passed through a shell‑quoting function (using Python’s `shlex.quote` on non‑Windows platforms) before substitution.
    - Standard precompiler command settings (for assets such as YUglify, YUI, CleanCSS, etc.) are expected to be defined by trusted, hard‑coded configuration values rather than influenced by user input.

  - **Missing Mitigations:**  
    - No generic validation or sanitization is applied to additional placeholder values or dynamically supplied arguments beyond basic file path quoting.
    - There is no whitelist or explicit check ensuring that the final resolved command matches an approved “safe” pattern.
    - No defense‐in‐depth measures (such as executing the commands in a restricted privilege sandbox, chroot, or similar container) are implemented to mitigate damage if unsanitized content is injected.

  - **Preconditions:**  
    - An attacker must be able to influence a value that is substituted into the external precompiler command. This may occur if file names or configuration values (such as those used for precompiler settings) are allowed to be influenced by untrusted input (for example, via a file upload mechanism or misconfiguration of static asset sources).
    - The system must be configured to use an external precompiler (or a custom precompiler command) where at least one portion of the command template or parameters is not tightly restricted to trusted constants.

  - **Source Code Analysis:**  
    - In the relevant code (such as `/code/compressor/filters/base.py` in the `CompilerFilter.input()` method), the command string is produced by:
      - Creating a temporary file (or using an existing file) for `{infile}` and `{outfile}`.
      - Passing the values for these placeholders through a shell‑quoting function.
      - Substituting the options into the command template using Python’s string formatting (`self.command.format(**options)`).
      - Invoking the final command string with `subprocess.Popen(..., shell=True)`.  
    - **Visualization:**  
      1. **Template:** `"%(binary)s %(args)s {infile} {outfile}"`
      2. **Parameter preparation:**  
         - `{infile}` and `{outfile}` are sanitized.
         - Other parameters (such as `{binary}` or `{args}`) are taken directly from configuration.
      3. **Formatting:**  
         - The unsanitized placeholders are inserted into the command, and if an attacker can control one of these values the final command may look like:  
           `"trusted_binary --safe " + malicious_payload`  
      4. **Execution:**  
         - The command is executed with `shell=True`, thereby executing any injected shell commands.
  
  - **Security Test Case:**  
    1. **Setup:**  
       - In a controlled testing environment, override a precompiler setting (e.g. for a custom file type such as “text/malicious”) with a command template that includes an additional placeholder (e.g. `{extra}`) that is not subject to shell‑quoting.
       - Ensure that the mechanism (for example, a file upload or static file naming process) accepts input that can be controlled by an untrusted source.
    2. **Execution:**  
       - Supply a malicious payload for the unsanitized placeholder (for example, a string like `"; rm -rf /"`).
       - Instantiate the corresponding precompiler filter (i.e. a subclass of `CompilerFilter`) with the overridden command template and malicious input injected into the unsanitized placeholder.
       - Trigger the process (for example, by calling the `input()` method) so that the command is formatted and scheduled for execution.
    3. **Verification:**  
       - Monitor or mock the subprocess call to verify that the final command string contains the injected shell command.
       - In a safe testing sandbox, confirm that the malicious payload appears in the command string and would (in a real attack scenario) result in unintended shell command execution.
    4. **Cleanup:**  
       - Restore the original configuration settings and clean up any temporary alterations to ensure no side effects affect further testing.

---

**Summary:**
The above list contains the only identified vulnerability that meets the specified criteria (valid, not fully mitigated, rank at least high, and applicable to an external attacker on a publicly available instance).