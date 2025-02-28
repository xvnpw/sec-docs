## Combined Vulnerability List: Command Injection in Code Runner Extension

This document describes a critical command injection vulnerability present in the Code Runner extension for VS Code. The vulnerability stems from the extension's use of user-configurable settings to define code execution commands, which are then executed by the system shell without proper sanitization. This allows an attacker to inject arbitrary commands by manipulating these settings, leading to arbitrary code execution on the user's machine.

### Vulnerability Name: Command Injection via Executor Configuration Settings

- **Description:**
    The Code Runner extension offers extensive customization through various settings, enabling users to define how code is executed for different languages and file types. These settings include `code-runner.executorMap`, `code-runner.executorMapByGlob`, `code-runner.executorMapByFileExtension`, and `code-runner.customCommand`.  The vulnerability lies in the fact that these user-provided configuration values, which dictate the commands used to run code, are directly passed to `child_process.spawn` with the `shell: true` option, without any sanitization. This allows an attacker to inject arbitrary shell commands by crafting malicious executor configurations.

    **Step-by-step trigger:**
    1. An attacker gains control over or the ability to modify the VS Code workspace or user settings. This can be achieved by:
        - Providing a malicious workspace to the user (e.g., via a compromised Git repository).
        - Socially engineering the user to import malicious settings.
        - In collaborative environments, by modifying shared workspace settings.
    2. The attacker modifies the `code-runner.executorMap`, `code-runner.executorMapByGlob`, `code-runner.executorMapByFileExtension`, or `code-runner.customCommand` settings within the workspace or user settings. For example, an attacker might set the executor for JavaScript to: `"javascript": "node -e 'require(\"child_process\").execSync(\"touch /tmp/pwned\"); process.exit()'"`.
    3. If targeting `executorMap`, `executorMapByGlob`, or `executorMapByFileExtension`: The user opens or creates a file of the language or matching the file pattern for which the malicious executor is configured (e.g., a `.js` file if the JavaScript executor was modified). If targeting `customCommand`: The user invokes the "Run Custom Command" feature.
    4. If targeting `executorMap`, `executorMapByGlob`, or `executorMapByFileExtension`: The user executes the "Run Code" command for the file (e.g., using `Ctrl+Alt+N` or right-clicking and selecting "Run Code"). If targeting `customCommand`: The user executes the "Run Custom Command" command (e.g., using `Ctrl+Alt+K` or from the command palette).
    5. The Code Runner extension retrieves the malicious executor command from the configuration.
    6. The extension uses `child_process.spawn` with `shell: true` to execute the command string, which now includes the attacker's injected commands.
    7. The shell interprets and executes the entire command string, including the injected malicious parts, leading to arbitrary code execution on the user's system.

- **Impact:**
    Successful exploitation of this vulnerability leads to **arbitrary code execution** on the user's machine with the privileges of the VS Code process. This can have severe security implications:
    - **Sensitive Data Theft:** Attackers can access and exfiltrate any data accessible to the user, including files, credentials, and other sensitive information.
    - **Malware Installation:** Attackers can install malware, ransomware, or other malicious software on the user's system.
    - **System Compromise:** Attackers can gain persistent access to the system, potentially leading to complete system compromise and further attacks.
    - **Lateral Movement:** In networked environments, attackers might use compromised systems as a pivot point to attack other systems on the network.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    **None**. The Code Runner extension, in its current implementation, does not implement any mitigations against command injection in executor configurations or custom commands. The extension directly retrieves the configuration values and uses them to construct and execute shell commands without any form of sanitization, validation, or escaping. The use of `shell: true` in `child_process.spawn` exacerbates the issue, as it enables shell interpretation of the command string, making it highly susceptible to injection attacks.

- **Missing Mitigations:**
    - **Input Sanitization and Validation:** The most critical missing mitigation is input sanitization and validation of all user-provided executor commands from `code-runner.executorMap`, `code-runner.executorMapByGlob`, `code-runner.executorMapByFileExtension`, and `code-runner.customCommand` settings. This should include:
        - **Strict input validation:** Implement checks to ensure that executor commands conform to expected formats and do not contain shell metacharacters or command separators.
        - **Escaping shell metacharacters:** If sanitization is not feasible, properly escape all shell-sensitive characters within the executor command string before passing it to `child_process.spawn` when using `shell: true`. However, escaping is complex and error-prone, and should be a last resort.
    - **`shell: false` and Argument Array:** The extension should ideally avoid using `shell: true` in `child_process.spawn`. Instead, it should:
        - Parse the executor command into the executable and its arguments.
        - Use `shell: false` and pass the executable and arguments as separate elements in the arguments array to `child_process.spawn`. This prevents the shell from interpreting metacharacters and significantly reduces the risk of command injection.
    - **Principle of Least Privilege:** Explore alternative, safer methods for executing code. Consider if sandboxing or more restricted APIs can be used to minimize the impact of potential vulnerabilities.
    - **User Education and Warnings:** Implement clear warnings and documentation within the extension to educate users about the security risks associated with modifying executor settings, especially when opening workspaces from untrusted sources or using custom commands. Prominent warnings should be displayed when users attempt to modify these settings, highlighting the potential for arbitrary code execution.

- **Preconditions:**
    - The "Code Runner" extension must be installed and activated in VS Code.
    - An attacker must have a way to influence the user's VS Code workspace or user settings. This is most commonly achieved by:
        - The user opening a workspace provided or controlled by the attacker (e.g., cloning a malicious repository containing crafted workspace settings).
        - The user importing malicious user settings.
        - In shared workspace scenarios, an attacker with write access to the workspace settings.
    - For vulnerabilities via `executorMap`, `executorMapByGlob`, `executorMapByFileExtension`: The user must execute code using the Code Runner extension for a language or file type that corresponds to the attacker's modified executor setting.
    - For vulnerabilities via `customCommand`: The user must explicitly execute the "Run Custom Command" feature.

- **Source Code Analysis:**
    - **File:** `src/codeManager.ts`
    - **Vulnerable Functions:** `getExecutor`, `runCustomCommand`, `executeCommandInOutputChannel`, `executeCommandInTerminal`, `getFinalCommandToRunCodeFile`.
    - **Vulnerability Flow:**
        1. **Configuration Retrieval:** Functions like `getExecutor` and `runCustomCommand` retrieve executor commands and custom commands directly from VS Code configuration settings (`this._config.get(...)`). These configuration values are user-controlled and unsanitized.
        2. **Command Construction:** `getFinalCommandToRunCodeFile` constructs the final command string by performing placeholder replacements within the retrieved executor string. Critically, it does not sanitize the executor string itself.
        3. **Command Execution:** `executeCommandInOutputChannel` and `executeCommandInTerminal` call `child_process.spawn(command, [], { cwd: this._cwd, shell: true })` to execute the constructed command. The `{ shell: true }` option is the core issue, as it enables shell interpretation of the command, making it vulnerable to injection.

    - **Code Snippets:**
        ```typescript
        // From executeCommandInOutputChannel and executeCommandInTerminal:
        const spawn = require("child_process").spawn;
        const command = await this.getFinalCommandToRunCodeFile(executor, appendFile);
        this._process = spawn(command, [], { cwd: this._cwd, shell: true }); // Vulnerable line

        // From runCustomCommand:
        const executor = this._config.get<string>("customCommand"); // Unsanitized customCommand

        // From getExecutor:
        const executorMap = this._config.get<any>("executorMap"); // Unsanitized executorMap
        executor = executorMap[this._languageId]; // Unsanitized executor from map
        ```

    - **Visualization of Vulnerable Path:**

    ```mermaid
    graph LR
        A[User Settings (executorMap, customCommand)] --> B(getConfiguration("code-runner"));
        B --> C{get<any>("executorMap") / get<string>("customCommand")};
        C -- executorMap --> D[getExecutor];
        C -- customCommand --> E[runCustomCommand];
        D --> F(executor - unsanitized string);
        E --> G(executor - unsanitized string);
        F --> H[getFinalCommandToRunCodeFile];
        G --> H;
        H --> I(command - still unsanitized);
        I --> J[executeCommandInOutputChannel / executeCommandInTerminal];
        J --> K{child_process.spawn(command, [], { shell: true })};
        K --> L[Command Execution (Vulnerable to Injection)];
    ```

- **Security Test Case:**
    To verify the command injection vulnerability, follow these steps as an external attacker with access to a publicly available instance of VS Code (assuming you can convince a user to open a malicious workspace):

    1. **Prepare a Malicious Workspace:**
        - Create a new folder for the malicious workspace.
        - Inside the folder, create a `.vscode` subfolder.
        - Inside the `.vscode` folder, create a `settings.json` file.
        - Add the following malicious configuration to `settings.json` to target JavaScript execution (example for Linux/macOS):
          ```json
          {
              "code-runner.executorMap": {
                  "javascript": "node -e 'require(\"child_process\").execSync(\"touch /tmp/pwned\"); process.exit()'"
              }
          }
          ```
          (For Windows, use: `"javascript": "node -e 'require(\"child_process\").execSync(\"type nul > C:\\\\Windows\\\\Temp\\\\pwned.txt\"); process.exit()'"`)
        - Optionally, create a simple JavaScript file (e.g., `test.js`) with content like `console.log("Test Code Runner");` to make testing easier for the victim.
        - Zip or package the malicious workspace folder.

    2. **Deliver the Malicious Workspace to the Victim:**
        - Use social engineering or other methods to convince the victim to download and open the malicious workspace in VS Code. For example, you could host the zip file in a seemingly legitimate repository or share it via email, claiming it's a project they need to review or collaborate on.

    3. **Victim Opens the Workspace and Runs Code:**
        - Once the victim opens the workspace in VS Code and has the Code Runner extension installed, instruct them to open the `test.js` file (or any JavaScript file in the workspace).
        - Ask the victim to run the JavaScript code using Code Runner (e.g., by pressing `Ctrl+Alt+N` or right-clicking in the editor and selecting "Run Code").

    4. **Verify Command Injection:**
        - After the victim runs the code, instruct them to check for the creation of the file `/tmp/pwned` (or `C:\\Windows\\Temp\\pwned.txt` on Windows).
        - If the file exists, it confirms that the injected command was executed successfully, demonstrating the command injection vulnerability.

This test case demonstrates how an attacker can leverage workspace settings to inject malicious commands and achieve arbitrary code execution when a user opens a compromised workspace and uses the Code Runner extension to run code.