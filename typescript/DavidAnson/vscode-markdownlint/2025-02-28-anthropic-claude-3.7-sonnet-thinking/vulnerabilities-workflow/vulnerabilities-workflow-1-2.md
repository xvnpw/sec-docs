# Vulnerability Analysis

## Remote Code Execution via Malicious Custom Rule or Configuration File Injection

- **Vulnerability Name:**  
  Remote Code Execution via Malicious Custom Rule or Configuration File Injection

- **Description:**  
  The extension supports JavaScript-based configuration and custom rules (for example, files with names such as `.markdownlint.cjs` or custom rule modules specified via the `markdownlint.customRules` setting). An attacker who is able to supply a manipulated repository can include one or more of these files containing malicious JavaScript. When a victim opens such a repository in Visual Studio Code and (either inadvertently or by necessity) marks the workspace as trusted, the extension will load and execute the JavaScript from these files. In doing so, the attacker's code is executed in the context of the extension and the user's environment.  
  **Step by step trigger:**  
  1. The attacker creates a forked or entirely new repository that follows the expected structure of a markdownlint project.  
  2. The repository is manipulated to include a JavaScript configuration file (for example, a `.markdownlint.cjs` or a custom rule file referenced via the `markdownlint.customRules` setting) where the attacker embeds code that performs unwanted actions (such as writing to disk, spawning processes, or exfiltrating data).  
  3. The attacker distributes or makes available this repository (for example, via a link or recommendation) so that a victim installs or opens it in VS Code.  
  4. If the victim marks the workspace as trusted—as is required to allow JavaScript execution in the workspace—the extension will load and execute the malicious configuration or custom rule file.  
  5. The embedded malicious code is run, leading to arbitrary command execution in the victim's environment.

- **Impact:**  
  Successful exploitation would result in arbitrary code execution (RCE) within the context of the victim's VS Code environment. This can lead to full system compromise, data exfiltration, and other malicious actions since the code may execute with the same privileges as the user. In short, an attacker taking advantage of this flaw could run any code on the victim's system.

- **Vulnerability Rank:**  
  Critical

- **Currently Implemented Mitigations:**  
  - The extension's documentation explicitly warns that "running JavaScript from custom rules, markdown-it plugins, or configuration files […] could be a security risk" and that VS Code's Workspace Trust setting is used to block JavaScript for untrusted workspaces.  
  - This means that if a workspace is marked untrusted, the dangerous JS files should not be executed.

- **Missing Mitigations:**  
  - There is no additional sandboxing or runtime isolation for JavaScript executed from configuration files or custom rule modules once a workspace is trusted.  
  - The extension (and its underlying engine, markdownlint-cli2) does not appear to perform runtime validation or content scanning of these JavaScript files to detect malicious behavior.  
  - There is also no mechanism to restrict the filesystem or process privileges of the executed configuration code.  
  - In environments where a user (or organization) inadvertently trusts a malicious repository, relying solely on the Workspace Trust setting is insufficient.

- **Preconditions:**  
  - The attacker must be able to supply a repository (or convince the victim to open one) that contains a malicious JavaScript configuration or custom rule file.  
  - The victim must open the repository in Visual Studio Code and mark the workspace as trusted.  
  - The extension must be configured (or the user's settings must allow) to load custom rules and JavaScript configuration files—this is the default behavior.

- **Source Code Analysis:**  
  - The extension's README and configuration documentation clearly explain that custom rules and configuration files (with extensions such as `.cjs` or files referenced in `markdownlint.customRules`) are automatically loaded and executed.  
  - Although the project does not show the internal loader code (which is part of the underlying markdownlint-cli2 engine), the documentation warns about the insecurity of executing JavaScript from these files.  
  - For example, the "Security" section in the README states:  
    > "Running JavaScript from custom rules, markdown-it plugins, or configuration files […] could be a security risk, so VS Code's Workspace Trust setting is honored to block JavaScript for untrusted workspaces."
  - This indicates that when a workspace is trusted, the extension defers to Node's standard behavior for loading JS files—using `require` or dynamic import—which means no additional checks, sanitization, or sandboxing are performed.  
  - If an attacker supplies a malicious `.markdownlint.cjs` or a custom rule module, the code inside will be executed as part of the extension's initialization or during linting without further validation.  
  - The absence of additional runtime safeguards beyond workspace trust creates an avenue for RCE.

- **Security Test Case:**  
  1. **Setup a Malicious Repository:**  
     - Create a repository that mimics a standard markdownlint project structure.  
     - Add a JavaScript configuration file (e.g., `.markdownlint.cjs`) that contains a payload such as a command to write a file or open a reverse shell. For testing purposes, the payload might simply write an identifiable file to disk (e.g., using `fs.writeFileSync('pwned.txt', 'malicious code executed!')`).

  2. **Configure Workspace Trust:**  
     - Open the repository in Visual Studio Code.  
     - When prompted by the Workspace Trust dialog, choose to "Trust" the workspace (simulating a scenario where the victim trusts the repository).

  3. **Trigger Code Execution:**  
     - Open a Markdown file so that the extension starts loading its configuration.  
     - Verify that the malicious configuration file is executed by checking for the side effect (for instance, the presence of `pwned.txt` in the project folder).

  4. **Validation:**  
     - Confirm that the payload executed successfully, proving that arbitrary JavaScript code embedded in repository-provided configuration files/custom rules can run.  
     - Document the steps and findings.