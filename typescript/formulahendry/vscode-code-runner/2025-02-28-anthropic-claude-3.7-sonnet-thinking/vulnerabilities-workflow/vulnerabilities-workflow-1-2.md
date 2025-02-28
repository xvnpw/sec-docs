# Vulnerabilities in Code Runner Extension

## 1. Arbitrary Code Execution via Malicious Executor Injection (Workspace Configuration)

- **Description:**
  - An attacker can supply a repository containing a crafted workspace configuration (e.g. a manipulated **.vscode/settings.json**) that overrides the extension's executor command mappings (such as in the `"code-runner.executorMap"` or `"code-runner.customCommand"` keys) with a malicious command string.
  - When the victim opens this repository in VS Code, the extension loads these configuration settings without additional sanitization.
  - Later, when the victim triggers a code run, the extension's `getExecutor()` function retrieves the malicious executor.
  - The command string is then processed by `getFinalCommandToRunCodeFile()`, where placeholder values are substituted but no validation is performed.
  - Finally, the command is executed via Node's `spawn` with `shell: true`, thus allowing command injection that can lead to arbitrary code execution.
  
- **Impact:**
  - An attacker-controlled executor command results in arbitrary command execution on the victim machine.
  - This could lead to complete system compromise, data loss, or unauthorized access.
  
- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - The extension relies on VS Code's native workspace configuration mechanism and (if the user enabled it) workspace trust; however, there is no specific sanitization or validation of the executor commands read from the configuration.
  
- **Missing Mitigations:**
  - Input sanitization and strict validation of configuration values (especially the values in `"code-runner.executorMap"` and `"code-runner.customCommand"`).
  - An explicit prompt or confirmation when executing a command that originates from workspace settings.
  - A whitelist (or safe list) of allowed executor commands.
  
- **Preconditions:**
  - The victim must open a malicious repository in which the attacker has provided a modified **.vscode/settings.json**.
  - The user must have accepted (or bypassed) any workspace trust warnings so that the malicious configuration is active.
  
- **Source Code Analysis:**
  - In `CodeManager.getExecutor()`, the extension retrieves the executor command from workspace configuration settings (from entries such as `"executorMap"`, `"executorMapByGlob"`, or `"executorMapByFileExtension"`) without any sanitization.
  - The obtained string is passed to `getFinalCommandToRunCodeFile()` where placeholders (for example `$workspaceRoot`, `$fullFileName`, etc.) are replaced in a simple string substitution process.
  - The final command string is then executed in `executeCommandInOutputChannel()` using `spawn(command, [], { cwd: this._cwd, shell: true })`, which runs the command in a shell context, making it vulnerable to shell injection.
  
- **Security Test Case:**
  1. Create a malicious repository that includes a **.vscode/settings.json** file with an executor override:
     ```json
     {
         "code-runner.executorMap": {
             "javascript": "node maliciousScript.js; echo 'Injected Command Executed'"
         }
     }
     ```
  2. Open the repository in VS Code (ensuring the workspace trust prompt is accepted).
  3. Open any JavaScript file and trigger the Code Runner extension command.
  4. Verify that the output contains the text `Injected Command Executed` (or another benign indicator) to confirm that the malicious command was executed.

## 2. Command Injection via Malicious File Name Placeholders

- **Description:**
  - The extension builds the final command string for execution by substituting placeholders in the executor command. In particular, the placeholders `$fileName` and `$fileNameWithoutExt` are replaced with the file's base name and name without extension, respectively.
  - These two placeholder values are retrieved from the file system (via functions such as `getCodeBaseFile()` and `getCodeFileWithoutDirAndExt()`) and are inserted into the command without being wrapped in quotes or sanitized.
  - An attacker controlling the repository may include a file with a deliberately crafted name containing shell metacharacters (for example, using a semicolon, ampersand, or backticks).
  - When the executor command (as defined in the configuration) references these placeholders, the malicious file name is substituted directly into the command. This may prematurely terminate the intended command and inject additional arbitrary shell commands.
  
- **Impact:**
  - Successful exploitation could lead to arbitrary command execution on the victim's machine.
  - Depending on the injected commands, this may compromise the system, delete files, or leak sensitive information.
  
- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - Some placeholders (such as `$fullFileName`, `$dirWithoutTrailingSlash`, and `$dir`) are wrapped with a simple quoting function (`quoteFileName()`).
  - However, the placeholders `$fileName` and `$fileNameWithoutExt` are not quoted during replacement.
  
- **Missing Mitigations:**
  - Proper escaping or quoting of all file name–based placeholders.
  - Validation that file names do not contain malicious shell metacharacters before substituting them in the command.
  
- **Preconditions:**
  - The victim must run the Code Runner extension on a file whose name has been maliciously chosen (or crafted) by an attacker.
  - The executor command configured (or defaulted) must reference either the `$fileName` or `$fileNameWithoutExt` placeholder.
  
- **Source Code Analysis:**
  - In the `getFinalCommandToRunCodeFile()` function, after retrieving the command string from configuration, the code iterates over an array of placeholder objects.
  - For `$fileName` and `$fileNameWithoutExt`, the functions `getCodeBaseFile()` and `getCodeFileWithoutDirAndExt()` are used to obtain their values. Unlike other placeholders, these values are not processed using the `quoteFileName()` helper.
  - The final command is then executed using Node's `spawn()` with the `shell: true` option, which interprets any injected shell commands.
  
- **Security Test Case:**
  1. In a test repository, rename a source code file to a name such as `example; echo injected`.
  2. Modify the executor command in the configuration (via workspace settings) so that it uses the `$fileName` placeholder. For instance, set an executor like:
     ```
     "gcc $fileName -o output && ./output"
     ```
  3. Open the file and trigger the Code Runner command.
  4. Monitor the terminal output to see if the injected command (`echo injected`) executes, thereby indicating successful command injection.

## 3. Arbitrary Command Execution via Malicious Shebang in Code Files

- **Description:**
  - The extension supports using a file's shebang (the first line) as an override for selecting the executor command when the configuration does not explicitly set a language.
  - In the `getExecutor()` function, if no language is provided and the configuration option `"respectShebang"` is enabled, the extension reads the first line of the code file.
  - If the first line matches a regular expression (`/^#!(?!\[)/`), the extension extracts the command by removing the initial `#!` and uses the remainder as the executor command.
  - Because this value is taken directly from the file without sanitization or validation, an attacker could supply a file with a malicious shebang line such as:
    ```
    #!/bin/sh; echo hacked
    ```
  - When the file is run, the malicious component of the shebang is executed.
  
- **Impact:**
  - The attacker gains the ability to execute arbitrary shell commands on the victim's machine.
  - This can lead to system compromise, unauthorized data modification, or other malicious activities.
  
- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - The extension provides the option (`respectShebang`) to honor the shebang line; however, it does not validate or sanitize the content of this line.
  
- **Missing Mitigations:**
  - Sanitization and validation of the shebang content to ensure only safe commands (or a predefined set of allowed commands) are executed.
  - An explicit user confirmation or warning when executing a command sourced directly from the file content.
  - Consider disabling the `respectShebang` feature by default or requiring higher levels of workspace trust.
  
- **Preconditions:**
  - The user must open a malicious repository that includes a code file whose first line is a maliciously crafted shebang.
  - The configuration option `"respectShebang"` must be enabled (which is the default behavior), and no external language override is provided.
  
- **Source Code Analysis:**
  - Within `CodeManager.getExecutor()`, the code checks if `languageId` is null and `"respectShebang"` is enabled.
  - It then reads the first line of the code file (`const firstLineInFile = this._document.lineAt(0).text;`) and tests it against the regular expression `/^#!(?!\[)/`.
  - Upon a match, the executor command is set to `firstLineInFile.slice(2)`—this is a raw extraction without further sanitization.
  - The resulting executor command is subsequently passed through the normal command construction and executed via `spawn()` with `shell: true`.
  
- **Security Test Case:**
  1. Create a code file in a test repository with the following first line:
     ```
     #!/bin/sh; echo hacked
     ```
  2. Open the repository in VS Code (ensure workspace trust is in place).
  3. Run the Code Runner command on the file.
  4. Observe the terminal output to confirm that the message `hacked` (or a similar benign indicator) is printed, demonstrating that the malicious shebang was executed.