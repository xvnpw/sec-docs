### Vulnerability List for Code Runner VSCode Extension

* Vulnerability Name: Command Injection via Executor Map Configuration

* Description:
    1. The Code Runner extension allows users to configure custom executors for different languages or file patterns through the `code-runner.executorMap`, `code-runner.executorMapByGlob`, `code-runner.executorMapByFileExtension`, and `code-runner.customCommand` settings.
    2. These settings are read from the VSCode configuration and used to construct commands that are executed by the extension.
    3. The extension uses `child_process.spawn` with `shell: true` to execute these commands.
    4. If a malicious user can modify these configuration settings (e.g., by contributing a malicious workspace configuration to a shared project, or by tricking a user into importing malicious settings), they can inject arbitrary shell commands into the executor strings.
    5. When the extension runs code using these modified settings, the injected commands will be executed by the system shell.

* Impact:
    - Arbitrary code execution on the user's machine with the privileges of the VSCode process.
    - An attacker could potentially gain full control of the user's system, steal sensitive data, install malware, or perform other malicious actions.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None. The extension relies on user-provided configuration without proper sanitization or validation of the executor strings. The quoting mechanism used (`quoteFileName`) is insufficient to prevent command injection in all cases when `shell: true` is used.

* Missing Mitigations:
    - Input sanitization and validation for all executor-related configuration settings (`code-runner.executorMap`, `code-runner.executorMapByGlob`, `code-runner.executorMapByFileExtension`, `code-runner.customCommand`).
    - Consider using `shell: false` in `child_process.spawn` and constructing commands with arguments array instead of relying on `shell: true` to prevent shell injection. If `shell: true` is necessary for certain functionalities, implement robust input sanitization to escape shell metacharacters.
    - Implement a Content Security Policy (CSP) for extension configurations to restrict the characters and commands allowed in executor strings.
    - Documentation warning users about the risks of modifying executor settings and advising them to only use trusted configurations.

* Preconditions:
    - Attacker needs to be able to modify the VSCode workspace or user settings configuration for the victim. This could be achieved through:
        - Contributing a malicious `.vscode/settings.json` file to a shared project (e.g., in a Git repository).
        - Social engineering to trick a user into manually modifying their user or workspace settings to include malicious executors.

* Source Code Analysis:
    1. **`codeManager.ts`:** The core logic for command execution resides in `codeManager.ts`.
    2. **`getExecutor` function:** This function retrieves the executor string from the configuration based on language ID, file extension, or filename glob.
    3. **`getFinalCommandToRunCodeFile` function:** This function takes the executor string and constructs the final command by replacing placeholders like `$fileName`, `$dir`, etc. and quoting the filename using `quoteFileName`.
    4. **`executeCommandInOutputChannel` function:** This function uses `child_process.spawn(command, [], { cwd: this._cwd, shell: true })` to execute the command. The crucial part is `shell: true`, which makes the system shell interpret the `command` string, opening the door for command injection.
    5. **`quoteFileName` function:** This function simply adds double quotes around the filename: `'\"' + fileName + '\"'`. This is not sufficient to prevent command injection if the executor string itself contains malicious shell commands or if filenames contain special characters that bypass simple quoting.

    ```typescript
    // codeManager.ts - executeCommandInOutputChannel function (simplified)
    private async executeCommandInOutputChannel(executor: string, appendFile: boolean = true) {
        // ...
        const command = await this.getFinalCommandToRunCodeFile(executor, appendFile);
        this._process = spawn(command, [], { cwd: this._cwd, shell: true });
        // ...
    }

    // codeManager.ts - getFinalCommandToRunCodeFile function (simplified)
    private async getFinalCommandToRunCodeFile(executor: string, appendFile: boolean = true): Promise<string> {
        let cmd = executor;
        if (this._codeFile) {
            // ... placeholder replacement ...
        }
        return (cmd !== executor ? cmd : executor + (appendFile ? " " + this.quoteFileName(this._codeFile) : ""));
    }

    // codeManager.ts - quoteFileName function
    private quoteFileName(fileName: string): string {
        return '\"' + fileName + '\"';
    }
    ```

    **Vulnerability Flow:**

    ```mermaid
    graph LR
        A[Configuration Settings (executorMap, customCommand)] --> B(getExecutor);
        B --> C(getFinalCommandToRunCodeFile);
        C --> D(executeCommandInOutputChannel / executeCommandInTerminal);
        D --> E{child_process.spawn (shell: true)};
        E --> F[System Shell (Command Injection)];
    ```

* Security Test Case:
    1. **Prerequisites:**
        - VSCode installed with the Code Runner extension.
        - A workspace folder opened in VSCode.
    2. **Steps:**
        - Open VSCode settings (File -> Preferences -> Settings or Code -> Settings -> Settings).
        - Go to Workspace Settings.
        - Search for "code-runner.executorMap".
        - Click "Edit in settings.json" to modify the workspace settings.
        - Add or modify an entry in `code-runner.executorMap` for a language you will use for testing (e.g., "javascript"). Set the executor to a malicious command, for example:
          ```json
          {
              "code-runner.executorMap": {
                  "javascript": "node -e 'require(\"child_process\").execSync(\"calc.exe\"); process.exit()'"
              }
          }
          ```
          (For macOS/Linux, replace `calc.exe` with a command like `osascript -e 'display notification \"PWNED!\" with title \"Code Runner Vulnerability\"'` or `xmessage "PWNED!"` if xmessage is installed.)
        - Create a new JavaScript file (e.g., `test.js`) in the workspace. The content of the file doesn't matter, it can be empty.
        - Run the JavaScript file using Code Runner (e.g., right-click in the editor and select "Run Code", or use the shortcut `Ctrl+Alt+N`).
    3. **Expected Behavior:**
        - The injected command (`calc.exe` or equivalent) will be executed by the system shell. On Windows, Calculator application should open. On macOS/Linux, a notification should appear or a message box should be displayed, depending on the injected command.
    4. **Actual Behavior:**
        - The injected command is executed, demonstrating arbitrary code execution.

This test case confirms the command injection vulnerability by showing that a malicious executor defined in the workspace settings can be executed by the Code Runner extension.