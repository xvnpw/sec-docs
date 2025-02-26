- **Vulnerability Name:** Arbitrary Code Execution via Unsafe YAML Deserialization in Infracost Config File  
  **Description:**  
  The extension looks for a configuration file (named “infracost.yml”) at the workspace root. In the function that runs the config file (in `Workspace.runConfigFile` in *workspace.ts*), the file is read and parsed by calling the generic YAML function `load()` from the js-yaml package. Because this function uses an unsafe schema by default, an attacker who commits a malicious infracost.yml—one that embeds unsafe YAML constructs (for example using tags such as `!!js/function` to instantiate a JavaScript function)—can cause arbitrary code to be instantiated and executed when the extension processes the file.  
  **Impact:**  
  If the payload is executed, the attacker may obtain arbitrary code execution with the privileges of the VS Code extension. This could lead to compromise of the user’s machine, exposure of sensitive data, or further escalation within the development environment.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  • No additional validation or safe‐parsing is done when the configuration file is read. (The code simply calls `load(readFileSync(...))`.)  
  **Missing Mitigations:**  
  • Use a safe YAML parser (for example, using js-yaml’s `safeLoad` or the current safe API) or enforce a strict schema that disallows dangerous tags.  
  **Preconditions:**  
  • The workspace must contain an infracost configuration file that an attacker can supply—such as via a malicious commit or pull request in a public repository.  
  **Source Code Analysis:**  
  • In *workspace.ts* inside the `runConfigFile` method, the following code snippet is used without further sanitization:  
  ```js
  const encoding = await getFileEncoding(configFilePath);
  const doc = <ConfigFile>load(readFileSync(configFilePath, encoding as BufferEncoding));
  ```  
  • Since `load()` (rather than a safe alternative) is used, any YAML constructs offering custom types or functions can be interpreted and executed during deserialization.  
  **Security Test Case:**  
  1. In a test repository, create an infracost.yml file that includes a malicious payload using an unsafe YAML tag (for example, a `!!js/function` that calls a harmless alert or writes to a log file).  
  2. Open the repository in VS Code with the Infracost extension installed.  
  3. Verify (for example, via logging or a controlled indicator) that the payload is executed when the extension initializes its projects.  
  4. Confirm that replacing the unsafe YAML parsing with a safe approach prevents payload execution.

- **Vulnerability Name:** Arbitrary File Access via Malicious Project Path Injection in Infracost Config File  
  **Description:**  
  The same infracost configuration file also defines one or more projects via a “projects” array (with each project having a “path” property). In the extension’s implementation (again in *workspace.ts* inside `runConfigFile` and later when building the CLI command), the project path from the config file is accepted verbatim and then passed as an argument (via `--path`) to the infracost CLI. An attacker who supplies a path that points outside the intended workspace (for example a relative path like `../../sensitive` or even an absolute path) can force the CLI to process files in unintended locations.  
  **Impact:**  
  This may lead to disclosure of sensitive files or unintended processing of directories outside the repository. An attacker could trigger errors or, depending on how the CLI processes the given path, even cause leakage of confidential configuration or system files to the output that the extension subsequently displays in the UI.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  • No sanitization or validation is performed on the value of the project path once it is read from the YAML config file.  
  **Missing Mitigations:**  
  • Validate that the supplied project paths are relative to (or reside within) the workspace directory.
  • Enforce a whitelist or use path–normalization checks that prevent directory traversal or absolute path injections.  
  **Preconditions:**  
  • The attacker must be able to commit a malicious infracost.yml file that sets a project “path” to a location outside the repository.  
  **Source Code Analysis:**  
  • After the YAML is parsed in the `runConfigFile` method, the code later builds CLI arguments using the project path (taken directly from the config object):  
  ```js
  let args = ['--config-file', configFilePath];
  // … later in the call:
  const out = await this.cli.exec(['breakdown', ...args, '--format', 'json', '--log-level', 'info'], this.root);
  ```  
  • There is no check to ensure that `p.path` points to an allowed subdirectory.  
  **Security Test Case:**  
  1. Create an infracost.yml that defines at least one project entry with a “path” value set to a directory outside the workspace (for example, `../../sensitive-directory`).  
  2. Open the repository in VS Code so that the extension reads this configuration file.  
  3. Monitor the arguments passed to the infracost CLI (for example, by logging or intercepting the spawn call) to see that the unsafe path is being used.  
  4. Verify that sensitive file information (or error messages containing such information) is disclosed, thereby confirming the vulnerability.  
  5. Validate that adding proper path–validation prevents the CLI from processing disallowed paths.

- **Vulnerability Name:** Potential Cross‑Site Scripting (XSS) via Unsanitized Template Rendering in VS Code Webview  
  **Description:**  
  When a cost breakdown is shown the extension creates a webview panel (see *block.ts* in the `display()` method) and sets its HTML content to the result of a Handlebars template. Although Handlebars escapes HTML by default, if the template is written to use triple–brace notation (e.g. `{{{ }}}`) for any field that could contain attacker–controlled content (such as resource names or other cost data passed from the CLI output or even from a mis‐crafted configuration file), then an attacker may inject arbitrary HTML or JavaScript.  
  **Impact:**  
  If exploited, this cross–site scripting vulnerability would allow an attacker to run arbitrary JavaScript in the context of the extension’s webview. This could be used to phish sensitive information, manipulate the UI, or launch further attacks within the host VS Code environment.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  • The Handlebars templates are compiled using the standard engine with auto–escaping enabled by default.  
  **Missing Mitigations:**  
  • Audit all templates to ensure that no user–supplied data is rendered using unsafe triple–brace (unescaped) expressions.  
  • Consider adding an extra layer of sanitization and a strict Content Security Policy (CSP) for the webview.  
  **Preconditions:**  
  • An attacker must be able to supply data (for example, via a malicious Terraform configuration or via a manipulated config file) that ends up in one or more fields rendered by the webview template.  
  **Source Code Analysis:**  
  • In *block.ts*, the `display()` method creates a new webview panel and sets its HTML as follows:  
  ```js
  this.webview.webview.html = this.template(this);
  ```  
  • The data object (`this`), which includes fields such as the block’s name, cost, and possibly other metadata (all originating from CLI outputs or the configuration), is passed straight into the template. If any field contains an attacker–supplied string and the template uses triple braces, then the output will not be escaped.  
  **Security Test Case:**  
  1. In a controlled test workspace, create a resource block whose name (or other displayed field) includes a malicious payload (for example, `<script>alert('XSS')</script>`).  
  2. Ensure that this field is rendered by the webview (for example by having it appear in the cost breakdown UI).  
  3. Observe whether the alert (or other JavaScript payload) is executed when the webview is displayed.  
  4. Verify that applying proper escaping (or removing unsafe triple–brace usage) in the Handlebars template prevents the script execution.