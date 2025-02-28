### Vulnerability List

- Vulnerability Name: Command Injection via `customCommand`
- Description: An attacker can configure the `code-runner.customCommand` setting to execute arbitrary commands on the user's system. This occurs when the "Run Custom Command" feature is used, and the extension directly passes the user-provided command to the system shell without proper sanitization.
    1.  Attacker compromises or controls a VSCode workspace (e.g., via a malicious Git repository or workspace file).
    2.  Attacker modifies the workspace settings to set a malicious command in `code-runner.customCommand`, for example: `echo vulnerable > output.txt && echo`. On Windows, the attacker would use `echo vulnerable > output.txt & echo`.
    3.  User opens the compromised workspace in VSCode.
    4.  User executes the "Run Custom Command" command (e.g., by pressing `Ctrl+Alt+K` or selecting "Run Custom Command" from the command palette).
    5.  The extension executes the malicious command specified in `code-runner.customCommand` using `child_process.spawn` with `shell: true`.
    6.  The injected command `echo vulnerable > output.txt && echo` (or `echo vulnerable > output.txt & echo` on Windows) is executed by the shell, creating a file named `output.txt` in the workspace directory containing the text "vulnerable". This demonstrates arbitrary command execution.
- Impact: Arbitrary code execution on the user's machine with the privileges of the VSCode process. This can lead to data theft, malware installation, or complete system compromise.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The `customCommand` configuration value is directly used in the `executeCommand` function without any sanitization.
- Missing Mitigations:
    - Input sanitization for the `customCommand` setting to prevent command injection.
    - Display a clear warning to the user about the security risks of using custom commands and the importance of only using trusted commands.
    - Ideally, the extension should avoid using `shell: true` in `child_process.spawn`. Instead, it should parse the command and use the arguments array to execute the command directly, which would prevent shell injection vulnerabilities.
- Preconditions:
    - The attacker must be able to modify the VSCode workspace settings. This can be achieved by tricking the user into opening a workspace controlled by the attacker, which contains a malicious workspace configuration file.
    - The user must execute the "Run Custom Command" feature.
- Source Code Analysis:
    - `src/codeManager.ts`:
        ```typescript
        public runCustomCommand(): void {
            if (this._isRunning) {
                vscode.window.showInformationMessage("Code is already running!");
                return;
            }
            // ...
            const executor = this._config.get<string>("customCommand"); // [POINT 1] - Retrieves unsanitized customCommand from configuration
            // ...
            this.executeCommand(executor, false); // [POINT 2] - Passes unsanitized executor to executeCommand
        }

        private executeCommand(executor: string, appendFile: boolean = true) {
            if (this._config.get<boolean>("runInTerminal")) {
                this.executeCommandInTerminal(executor, appendFile);
            } else {
                this.executeCommandInOutputChannel(executor, appendFile);
            }
        }

        private async executeCommandInOutputChannel(executor: string, appendFile: boolean = true) {
            // ...
            const spawn = require("child_process").spawn;
            const command = await this.getFinalCommandToRunCodeFile(executor, appendFile);
            // ...
            this._process = spawn(command, [], { cwd: this._cwd, shell: true }); // [POINT 3] - Executes command with shell: true, vulnerable to injection
            // ...
        }
        ```
    - **[POINT 1]**: The `runCustomCommand` function retrieves the value of `code-runner.customCommand` from the workspace configuration. This value is directly controlled by the user and is not sanitized.
    - **[POINT 2]**: The retrieved `executor` (which is the `customCommand` value) is passed to the `executeCommand` function, and subsequently to `executeCommandInOutputChannel`.
    - **[POINT 3]**: Inside `executeCommandInOutputChannel`, `child_process.spawn` is called with `shell: true`. This is a critical point because when `shell: true` is used, the `command` is executed through a system shell (like bash or cmd.exe). This allows shell metacharacters (like `&&`, `||`, `;`, `$()`, `` ` ``) in the `command` to be interpreted by the shell, leading to command injection vulnerabilities. Since the `command` is constructed using the unsanitized `customCommand` configuration, it becomes vulnerable to injection.

- Security Test Case:
    1.  Open VSCode.
    2.  Create a new workspace or open an existing one.
    3.  Go to Workspace Settings: `File -> Preferences -> Settings`, and select the "Workspace" tab.
    4.  In the settings search bar, type `code-runner.customCommand`.
    5.  Click on "Edit in settings.json" to modify the workspace settings JSON file.
    6.  Add or modify the `code-runner.customCommand` setting with the following malicious command.
        ```json
        "code-runner.customCommand": "echo vulnerable > output.txt && echo"
        ```
        For Windows, use:
        ```json
        "code-runner.customCommand": "echo vulnerable > output.txt & echo"
        ```
    7.  Save the `settings.json` file.
    8.  Create a new text file (e.g., `test.txt`) or open any existing file in the workspace.
    9.  Execute the "Run Custom Command" command:
        - Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) to open the command palette.
        - Type `Run Custom Command` and select the "Code Runner: Run Custom Command" option.
    10. After executing the command, check your workspace directory for a new file named `output.txt`.
    11. Open `output.txt`. If the file contains the text "vulnerable", the command injection vulnerability is confirmed.

- Vulnerability Name: Command Injection via `executorMap` and other executor configurations
- Description: An attacker can configure the `code-runner.executorMap`, `code-runner.executorMapByGlob`, or `code-runner.executorMapByFileExtension` settings to execute arbitrary commands on the user's system when code for a specific language or matching a specific file pattern is run. Similar to the `customCommand` vulnerability, this arises because the extension uses user-provided executor commands directly in the system shell without sanitization.
    1.  Attacker compromises or controls a VSCode workspace.
    2.  Attacker modifies the workspace settings to set a malicious executor in `code-runner.executorMap` (or `executorMapByGlob`, `executorMapByFileExtension`) for a specific language or file pattern, for example: for javascript: `"javascript": "echo vulnerable > output.txt && echo"`. On Windows, the attacker would use `"javascript": "echo vulnerable > output.txt & echo"`.
    3.  User opens the compromised workspace in VSCode.
    4.  User opens or creates a file of the specified language (e.g., a `.js` file for javascript).
    5.  User executes the "Run Code" command for this file (e.g., by pressing `Ctrl+Alt+N` or right-clicking in the editor and selecting "Run Code").
    6.  The extension retrieves the malicious executor from the configuration for the corresponding language.
    7.  The extension executes the malicious command using `child_process.spawn` with `shell: true`.
    8.  The injected command `echo vulnerable > output.txt && echo` (or `echo vulnerable > output.txt & echo` on Windows) is executed by the shell, creating a file named `output.txt` in the workspace directory containing the text "vulnerable". This demonstrates arbitrary command execution when running code for the configured language.
- Impact: Arbitrary code execution on the user's machine with the privileges of the VSCode process. This can lead to data theft, malware installation, or complete system compromise, triggered when a user runs code of a specific type.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The executor commands from `executorMap`, `executorMapByGlob`, and `executorMapByFileExtension` are used directly without any sanitization.
- Missing Mitigations:
    - Input sanitization for the executor commands in `executorMap`, `executorMapByGlob`, and `executorMapByFileExtension` to prevent command injection.
    - Display a warning to the user about the security risks of modifying executor maps and the importance of using only trusted executor commands.
    - Ideally, avoid using `shell: true` in `child_process.spawn`. Instead, parse the executor and file arguments and use the arguments array to execute the command directly, preventing shell injection.
- Preconditions:
    - The attacker must be able to modify the VSCode workspace settings.
    - The user must open a file of the language or matching the file pattern for which the malicious executor is configured and then execute the "Run Code" command for that file.
- Source Code Analysis:
    - `src/codeManager.ts`:
        ```typescript
        private getExecutor(languageId: string, fileExtension: string): string {
            // ...
            const executorMap = this._config.get<any>("executorMap"); // [POINT 1] - Retrieves executorMap from configuration
            if (executor == null) {
                executor = executorMap[this._languageId]; // [POINT 2] - Retrieves executor from executorMap based on languageId
            }
            // ...
            return executor; // [POINT 3] - Returns unsanitized executor
        }

        private executeCommand(executor: string, appendFile: boolean = true) {
            if (this._config.get<boolean>("runInTerminal")) {
                this.executeCommandInTerminal(executor, appendFile);
            } else {
                this.executeCommandInOutputChannel(executor, appendFile);
            }
        }

        private async executeCommandInOutputChannel(executor: string, appendFile: boolean = true) {
            // ...
            const spawn = require("child_process").spawn;
            const command = await this.getFinalCommandToRunCodeFile(executor, appendFile);
            // ...
            this._process = spawn(command, [], { cwd: this._cwd, shell: true }); // [POINT 4] - Executes command with shell: true, vulnerable to injection
            // ...
        }
        ```
    - **[POINT 1]**: The `getExecutor` function retrieves the `executorMap` (and similarly `executorMapByGlob`, `executorMapByFileExtension`) from the workspace configuration. These maps contain executor commands that are user-configurable and unsanitized.
    - **[POINT 2]**: The function then retrieves the executor command from the `executorMap` based on the `_languageId`. This executor command is directly from the user configuration and is not validated or sanitized.
    - **[POINT 3]**: The unsanitized `executor` is returned.
    - **[POINT 4]**: In `executeCommandInOutputChannel`, similar to the `customCommand` vulnerability, the `child_process.spawn` is called with `shell: true` and the `command` is constructed using the unsanitized `executor`. This makes the system vulnerable to command injection when running code if a malicious executor is configured for the language.

- Security Test Case:
    1.  Open VSCode.
    2.  Create a new workspace or open an existing one.
    3.  Go to Workspace Settings: `File -> Preferences -> Settings`, and select the "Workspace" tab.
    4.  In the settings search bar, type `code-runner.executorMap`.
    5.  Click on "Edit in settings.json" to modify the workspace settings JSON file.
    6.  Add or modify the `code-runner.executorMap` setting for `javascript` with the following malicious command.
        ```json
        "code-runner.executorMap": {
            "javascript": "echo vulnerable > output.txt && echo"
        }
        ```
        For Windows, use:
        ```json
        "code-runner.executorMap": {
            "javascript": "echo vulnerable > output.txt & echo"
        }
        ```
    7.  Save the `settings.json` file.
    8.  Create a new JavaScript file (e.g., `test.js`) with any content (e.g., `console.log('Hello, world!');`).
    9.  Open the `test.js` file in the editor.
    10. Execute the "Run Code" command for the JavaScript file:
        - Press `Ctrl+Alt+N`.
        - Alternatively, right-click in the editor and select "Run Code".
    11. After executing the code, check your workspace directory for a new file named `output.txt`.
    12. Open `output.txt`. If the file contains the text "vulnerable", the command injection vulnerability is confirmed.