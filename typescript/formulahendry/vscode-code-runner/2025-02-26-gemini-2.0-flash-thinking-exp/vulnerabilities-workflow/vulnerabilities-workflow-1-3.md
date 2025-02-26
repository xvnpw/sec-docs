### Vulnerability List:

- Vulnerability Name: Command Injection via Custom Executors

- Description:
    1. An attacker can modify the workspace settings of a project.
    2. The attacker sets a malicious command in `code-runner.executorMap`, `code-runner.executorMapByGlob`, `code-runner.executorMapByFileExtension`, or `code-runner.customCommand` settings. For example, setting the Python executor to `python -c "import os; os.system('malicious_command')"`.
    3. A user opens the project in VSCode and runs code using the Code Runner extension.
    4. The extension retrieves the malicious executor from the workspace settings.
    5. The `getFinalCommandToRunCodeFile` function constructs the execution command using the malicious executor without sanitization.
    6. The `executeCommandInOutputChannel` or `executeCommandInTerminal` functions execute the command using `child_process.spawn`, resulting in the execution of the attacker's injected command.

- Impact:
    Arbitrary command execution on the user's machine with the privileges of the VSCode process. This allows for a wide range of malicious activities, including data theft, malware installation, and system compromise.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - File names are quoted using double quotes in the constructed command via the `quoteFileName` function. This offers limited protection against command injection in file paths but does not mitigate injection within the executor commands themselves.

- Missing mitigations:
    - Input validation and sanitization for all user-configurable executor commands and custom commands.
    - Implement a strict allowlist of characters for executor paths and commands to prevent injection of shell metacharacters.
    - Display a warning to users when custom executors or commands are configured, especially if they deviate from standard or expected values.
    - Consider sandboxing code execution or running processes with reduced privileges to limit the impact of successful command injection.

- Preconditions:
    - The attacker must be able to modify the workspace settings (settings.json) of a project. This could occur if a user opens a workspace containing malicious settings, or if the attacker has write access to the workspace settings in a shared environment.
    - The user must execute code within the compromised workspace using the Code Runner extension.

- Source Code Analysis:
    - `src/codeManager.ts`:
        - The `getExecutor` function retrieves executor commands directly from the configuration (`executorMap`, `executorMapByGlob`, `executorMapByFileExtension`).
        - The `runCustomCommand` function retrieves the custom command from the configuration (`customCommand`).
        - The `getFinalCommandToRunCodeFile` function constructs the command string by embedding the executor and file paths, but does not sanitize the executor string.
        - The `executeCommandInOutputChannel` and `executeCommandInTerminal` functions use `child_process.spawn` to execute the unsanitized command string, which includes the attacker-controlled executor, directly in a shell.
        ```typescript
        private async getFinalCommandToRunCodeFile(executor: string, appendFile: boolean = true): Promise<string> {
            let cmd = executor; // Executor is taken directly from config without sanitization
            // ... placeholder replacements ...
            return (cmd !== executor ? cmd : executor + (appendFile ? " " + this.quoteFileName(this._codeFile) : "")); // Command is constructed and returned
        }

        private async executeCommandInOutputChannel(executor: string, appendFile: boolean = true) {
            // ...
            const command = await this.getFinalCommandToRunCodeFile(executor, appendFile); // Command is prepared
            this._process = spawn(command, [], { cwd: this._cwd, shell: true }); // Command is executed with shell: true
            // ...
        }
        ```
        - The use of `shell: true` in `child_process.spawn` further increases the risk of command injection, as it allows shell expansion and interpretation of metacharacters within the command string.

- Security Test Case:
    1. Open VSCode. Create or open any folder as a workspace.
    2. Create a new file named `test.py` (or any other language supported by Code Runner) with any content.
    3. Open the Workspace Settings (File > Preferences > Settings, then click the "Workspace" tab).
    4. In the settings.json file, add the following configuration within the curly braces `{}` to set a malicious Python executor:
        ```json
        "code-runner.executorMap": {
            "python": "python -c 'import os; os.system(\"touch /tmp/pwned_by_code_runner\")'"
        }
        ```
    5. Save the settings.json file.
    6. Open the `test.py` file in the editor.
    7. Execute the code using Code Runner by pressing `Ctrl+Alt+N` (or `Cmd+Alt+N` on macOS), or right-clicking in the editor and selecting "Run Code".
    8. After execution, open a terminal in your system and check if the file `/tmp/pwned_by_code_runner` has been created by running the command `ls /tmp/pwned_by_code_runner`.
    9. If the file `/tmp/pwned_by_code_runner` exists, it confirms that the malicious command injected through the workspace settings was successfully executed, demonstrating the command injection vulnerability.