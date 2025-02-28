# VS Code Extension Generator Vulnerabilities

## Critical Vulnerabilities

- **Vulnerability Name:** Malicious Template Injection Leading to Remote Code Execution  
- **Description:**  
  The generator's file‐generation logic relies heavily on processing template files via the built‐in "copyTpl" method (which uses an EJS‐based templating engine). In a standard (trusted) generator repository the templates (for example, the README, package.json, and other extension scaffolding files) contain placeholders such as `<%= name %>` or `<%- name %>`. A threat actor who provides a malicious repository (or compromises an existing one) can manipulate these template files to include attacker‐controlled EJS scriptlets. For instance, an attacker could modify a template to include a payload like:  
  `<% require('child_process').execSync('maliciousCommand') %>`  
  When an unsuspecting victim runs the generator (for example, by executing "yo code"), the generator will process the compromised templates via `copyTpl()`. As the templating engine evaluates the file's contents, any embedded malicious code is executed within the victim's environment. This injection of attacker‐controlled executable code directly during file generation leads to arbitrary remote code execution.  
- **Impact:**  
  - **Remote Code Execution:** An attacker can execute arbitrary commands in the victim's environment at generation time.  
  - **System Compromise:** The attacker may exfiltrate data, modify files, install malware, or perform lateral movement on the victim's system.  
- **Vulnerability Rank:** Critical  
- **Currently Implemented Mitigations:**  
  - The project uses standard Yeoman generator functions (such as `copyTpl()`) that rely on the established EJS templating engine.  
  - There is no custom logic to reprocess (or "double‐evaluate") untrusted input beyond the normal templating; however, the generator assumes that the repository's templates are trusted.  
- **Missing Mitigations:**  
  - **Integrity Verification:** No mechanism is in place to verify the cryptographic integrity or authenticity of the template files.  
  - **Sandboxed Evaluation:** The templating process is not isolated (for example, via sandboxing) so that even if a template contains embedded code, it is executed in the host environment.  
  - **Content Validation:** There is no filtering or static analysis of template content before processing that could detect injected EJS scriptlets or potentially malicious payloads.  
- **Preconditions:**  
  - The victim must install or use a repository (or package distributed via the generator's update channel) that has been manipulated by an attacker.  
  - The manipulated repository contains modified template files with embedded EJS code that executes commands (for example, by using `<% ... %>` blocks).  
  - The victim then runs the generator (e.g. via `yo code`), triggering the template rendering process during extension scaffolding.  
- **Source Code Analysis:**  
  1. **Template Processing:** Multiple generator modules (for example, in `generate-keymap.js`, `generate-command-js.js`, `generate-colortheme.js`, etc.) call  
     ```js
     generator.fs.copyTpl(generator.templatePath('someFile'), generator.destinationPath('someFile'), extensionConfig);
     ```  
     This method reads a template from the repository (located under `/code/generators/app/templates/…`) and renders it using data from the `extensionConfig` object.
  2. **Embedded EJS Tags:** The template files (such as `/code/generators/app/templates/ext-language/README.md`) include EJS tokens like `<%= name %>` and `<%- name %>`.  
  3. **Manipulated Template Example:** If an attacker replaces a trusted template with one that embeds a payload—e.g.,  
     ```ejs
     # Malicious README
     <% require('child_process').execSync('touch /tmp/attacker-controlled') %>
     ```
     —then during the generator's writing phase the `copyTpl()` method will execute the payload as part of the EJS template evaluation.
  4. **No Verification:** There is no built‐in verification or sanitization step for the template file contents. The generator trusts all files under its repository.
  5. **Visualization:**  
     - **Input:** Attacker-controlled template file with malicious EJS scriptlets.  
     - **Processing:** The call to `generator.fs.copyTpl()` loads and evaluates the template with the supplied context.  
     - **Outcome:** The embedded EJS code is executed, for example invoking a system command via `child_process.execSync(…)`.
- **Security Test Case:**  
  1. **Setup a Malicious Repository:** Create a modified version of the generator repository where one of the template files (for example, `/code/generators/app/templates/ext-keymap/README.md`) is altered to include an EJS payload. For testing on a non‑production system, insert a benign command such as:  
     ```ejs
     <% require('child_process').execSync('touch /tmp/test_rce_triggered') %>
     ```
  2. **Installation:** Install or point the generator to use this malicious repository.
  3. **Execution:** Run the generator (e.g., execute `yo code` with appropriate options to generate a new keymap extension).
  4. **Observation:** After the generator runs, check the victim machine's filesystem (for example, verify whether `/tmp/test_rce_triggered` exists).  
  5. **Result:** The presence of the test file confirms that the malicious code was executed during template processing, demonstrating remote code execution.
  6. **Cleanup:** Remove any test artifacts and document the findings.