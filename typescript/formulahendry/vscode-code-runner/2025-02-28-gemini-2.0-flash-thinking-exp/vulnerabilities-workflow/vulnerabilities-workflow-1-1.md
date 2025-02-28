### Vulnerability List

- Vulnerability Name: Command Injection via Executor Map Configuration
- Description: An attacker can inject arbitrary commands by manipulating the workspace configuration settings of the Code Runner extension. Specifically, the `code-runner.executorMap`, `code-runner.executorMapByGlob`, `code-runner.executorMapByFileExtension`, and `code-runner.customCommand` settings are vulnerable. The extension uses these settings to construct commands that are executed using `child_process.spawn` with `shell: true`, without proper sanitization of user-provided values. By crafting malicious executor commands containing shell metacharacters like backticks, command substitution, or shell operators, an attacker can achieve arbitrary code execution on the user's system when the user runs code through the extension.
- Impact: Arbitrary code execution on the user's machine with the privileges of the VS Code process. This can lead to sensitive data theft, malware installation, or complete system compromise.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The extension directly uses user-provided configuration values to construct and execute commands without any input sanitization or validation.
- Missing Mitigations:
    - Input sanitization: Sanitize and validate executor commands obtained from workspace settings to remove or escape shell-sensitive characters and prevent command injection.
    - `shell: false`:  Use `shell: false` in `child_process.spawn` and construct commands by passing executor and arguments as separate array elements, which avoids shell interpretation and reduces injection risks. If `shell: true` is necessary, ensure robust escaping of all arguments.
    - Principle of least privilege: Explore if there are safer ways to execute code, possibly within sandboxed environments or by using more restricted APIs to minimize the impact of potential vulnerabilities.
    - User education: Provide clear documentation and warnings to users about the security risks associated with modifying executor settings, especially when opening workspaces from untrusted sources.
- Preconditions:
    - The "Code Runner" extension must be installed and activated in VS Code.
    - The attacker needs a way to influence the user's VS Code workspace or user settings. This is achievable if a user opens a workspace provided by the attacker (e.g., cloning a malicious repository containing crafted workspace settings).
- Source Code Analysis:
    - Vulnerable code path: `codeManager.ts` -> `CodeManager.getExecutor()` -> `CodeManager.getFinalCommandToRunCodeFile()` -> `CodeManager.executeCommandInOutputChannel()`/`CodeManager.executeCommandInTerminal()`.
    - The `getExecutor()` function in `codeManager.ts` retrieves the executor string from VS Code configuration (`executorMap`, `executorMapByGlob`, `executorMapByFileExtension`, `defaultLanguage`).
    - The `getFinalCommandToRunCodeFile()` function constructs the final command string by replacing placeholders within the executor string. This function uses simple string replacement and `quoteFileName()` which uses basic quoting, insufficient for robust command injection prevention.
    - The `executeCommandInOutputChannel()` and `executeCommandInTerminal()` functions use `child_process.spawn(command, [], { cwd: this._cwd, shell: true })` to execute the constructed command. The critical part is `{ shell: true }`, which enables shell interpretation of the command, making it susceptible to command injection if the `command` string is not meticulously sanitized.
    - Code snippet from `executeCommandInOutputChannel()`:
      ```typescript
      const spawn = require("child_process").spawn;
      const command = await this.getFinalCommandToRunCodeFile(executor, appendFile);
      this._process = spawn(command, [], { cwd: this._cwd, shell: true });
      ```
- Security Test Case:
    1. Open VS Code.
    2. Open any folder or create a new workspace.
    3. Open the workspace settings (File -> Preferences -> Settings -> Workspace).
    4. In the settings.json file for the workspace, add the following configuration to maliciously redefine the executor for JavaScript:
       ```json
       {
           "code-runner.executorMap": {
               "javascript": "node -e 'require(\"child_process\").execSync(\"touch /tmp/pwned\"); process.exit()'"
           }
       }
       ```
       (Note: For Windows, replace `touch /tmp/pwned` with `type nul > C:\\Windows\\Temp\\pwned.txt` to create a file in the temporary directory).
    5. Create a new JavaScript file (e.g., `test.js`) and add any simple JavaScript code, for example: `console.log("Test Code Runner");`.
    6. Run the JavaScript file using Code Runner (Right-click in the editor -> "Run Code" or use the shortcut `Ctrl+Alt+N`).
    7. After running, check if the file `/tmp/pwned` (or `C:\\Windows\\Temp\\pwned.txt` on Windows) has been created.
    8. If the file is created, it confirms that arbitrary code execution was achieved through the malicious executor configuration, demonstrating a successful command injection vulnerability.