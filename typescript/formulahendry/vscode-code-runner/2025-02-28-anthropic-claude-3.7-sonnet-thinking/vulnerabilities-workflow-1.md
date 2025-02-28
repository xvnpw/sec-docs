# Vulnerabilities in Code Runner Extension

## 1. Command Injection via ExecutorMap in Settings

### Description
The Code Runner extension allows users to configure custom executors using the `executorMap` setting. When a malicious repository contains a custom VS Code workspace configuration (`.vscode/settings.json`), it can define arbitrary shell commands as executors that will run when the victim tries to execute code with the extension.

Step by step:
1. Attacker creates a repository with a malicious `.vscode/settings.json` file.
2. The settings file contains a modified `code-runner.executorMap` that includes command injection payloads.
3. When victim opens the repository and tries to run code using Code Runner, the malicious command is executed.

### Impact
This vulnerability allows full Remote Code Execution (RCE) with the privileges of the user running VS Code. An attacker can execute arbitrary commands on the victim's machine, potentially gaining persistent access, stealing sensitive information, or compromising the entire system.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension relies on VS Code's native workspace configuration mechanism and (if the user enabled it) workspace trust; however, there is no specific sanitization or validation of the executor commands read from the configuration.

### Missing Mitigations
- Validation of executor commands against a whitelist of allowed patterns
- Warning or confirmation prompt when using custom executor configurations
- Sandboxing the execution environment
- Disabling custom executors from untrusted workspaces by default
- Input sanitization and strict validation of configuration values
- A whitelist (or safe list) of allowed executor commands

### Preconditions
- Victim must open a malicious repository in VS Code
- The Code Runner extension must be installed
- Victim must trigger code execution using the extension (e.g., clicking "Run Code")
- The user must have accepted (or bypassed) any workspace trust warnings so that the malicious configuration is active

### Source Code Analysis
Looking at `codeManager.ts`, the vulnerability exists in several functions that work together:

1. In the `getExecutor` method, the executor is retrieved from configuration without validation:
```typescript
const executorMap = this._config.get<any>("executorMap");
executor = executorMap[this._languageId];
```

2. The command is then built in `getFinalCommandToRunCodeFile`:
```typescript
private async getFinalCommandToRunCodeFile(executor: string, appendFile: boolean = true): Promise<string> {
    let cmd = executor;
    // Placeholders get replaced...
    return (cmd !== executor ? cmd : executor + (appendFile ? " " + this.quoteFileName(this._codeFile) : ""));
}
```

3. Finally, the command is executed using Node.js's child_process in `executeCommandInOutputChannel`:
```typescript
const spawn = require("child_process").spawn;
const command = await this.getFinalCommandToRunCodeFile(executor, appendFile);
this._process = spawn(command, [], { cwd: this._cwd, shell: true });
```

The critical issue is that `shell: true` is used, allowing command injection through the executor string, which comes directly from user-controllable settings.

### Security Test Case
1. Create a repository with a `.vscode/settings.json` file containing:
```json
{
    "code-runner.executorMap": {
        "javascript": "node & echo 'Command injection successful' > proof.txt &"
    }
}
```
2. Create a simple JavaScript file in the repository:
```javascript
console.log("Hello World");
```
3. Victim opens the repository in VS Code with Code Runner extension installed
4. Victim clicks "Run Code" on the JavaScript file
5. Check for the existence of `proof.txt` file with the injected content to verify the vulnerability

## 2. Command Injection via Shebang

### Description
Code Runner respects shebang (#!) lines at the beginning of files to determine the command used to execute the file. This feature can be exploited by creating files with malicious shebang lines that include injected commands.

Step by step:
1. Attacker creates a repository with a file containing a malicious shebang line
2. When victim opens the repository and runs the file, the extension extracts and executes the shebang line without proper validation

### Impact
This vulnerability allows arbitrary command execution on the victim's machine. The commands run with the same privileges as the VS Code process, enabling attackers to exfiltrate data, install malware, or establish persistence.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension attempts to ignore shebang-like lines used in Rust (`#![...]`), but otherwise performs no validation on the shebang content. The extension provides the option (`respectShebang`) to honor the shebang line; however, it does not validate or sanitize the content of this line.

### Missing Mitigations
- Validation of shebang contents against a whitelist of allowed executors
- Sanitization of special shell characters in shebang lines
- Option to disable shebang execution from untrusted workspaces
- An explicit user confirmation or warning when executing a command sourced directly from the file content
- Consider disabling the `respectShebang` feature by default or requiring higher levels of workspace trust

### Preconditions
- Victim must open a malicious repository in VS Code
- Code Runner extension must be installed with default settings (the `respectShebang` option is true by default)
- Victim must run a file containing a malicious shebang
- The configuration option `"respectShebang"` must be enabled (which is the default behavior), and no external language override is provided

### Source Code Analysis
In `codeManager.ts`, the `getExecutor` method extracts and uses the shebang without proper validation:

```typescript
if (languageId == null && this._config.get<boolean>("respectShebang")) {
    const firstLineInFile = this._document.lineAt(0).text;
    if (/^#!(?!\[)/.test(firstLineInFile)) { // #![...] are used in rust
        executor = firstLineInFile.slice(2);
    }
}
```

The shebang line is extracted by simple string slicing (removing the first two characters `#!`), and then used directly as the executor command. This is a raw extraction without further sanitization. The resulting executor command is subsequently passed through the normal command construction and executed via `spawn()` with `shell: true`, allowing command injection.

### Security Test Case
1. Create a repository with a file named `malicious.js` containing:
```javascript
#!/usr/bin/env node && echo 'Shebang injection successful' > shebang_proof.txt && node
console.log("Harmless looking code");
```
2. Victim opens the repository in VS Code with Code Runner installed
3. Victim runs the malicious.js file
4. Check for the existence of `shebang_proof.txt` with the injected content

## 3. Code Injection via Custom Command

### Description
Code Runner has a feature to run custom commands via the `code-runner.customCommand` setting. An attacker can create a malicious repository with a `.vscode/settings.json` file that defines a harmful custom command. When the victim invokes the "Run Custom Command" feature, arbitrary code is executed.

Step by step:
1. Attacker creates a repository with a `.vscode/settings.json` file containing a malicious `code-runner.customCommand`
2. When victim opens the repository and runs the custom command (Ctrl+Alt+K), the malicious command is executed

### Impact
Arbitrary command execution on the victim's system, allowing attackers to execute malware, steal sensitive data, or compromise the system.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The extension executes custom commands without validation.

### Missing Mitigations
- Disable custom commands from untrusted workspaces
- Validate custom commands against a whitelist
- Show a security warning when executing custom commands from workspace settings

### Preconditions
- Victim must open a malicious repository in VS Code
- Code Runner extension must be installed
- Victim must manually trigger the "Run Custom Command" functionality (Ctrl+Alt+K)

### Source Code Analysis
In `codeManager.ts`, the custom command is retrieved from settings without validation:

```typescript
public runCustomCommand(): void {
    // ...
    const executor = this._config.get<string>("customCommand");
    
    if (this._document) {
        const fileExtension = extname(this._document.fileName);
        this.getCodeFileAndExecute(fileExtension, executor, false);
    } else {
        this.executeCommand(executor, false);
    }
}
```

The custom command is then passed to `executeCommand`, which eventually executes it using Node.js's spawn with `shell: true`, allowing command injection.

### Security Test Case
1. Create a repository with a `.vscode/settings.json` file containing:
```json
{
    "code-runner.customCommand": "echo 'Custom command injection successful' > custom_proof.txt"
}
```
2. Victim opens the repository in VS Code with Code Runner installed
3. Victim presses Ctrl+Alt+K to run the custom command
4. Check for the existence of `custom_proof.txt` with the injected content

## 4. Command Injection via Malicious File Name Placeholders

### Description
The extension builds the final command string for execution by substituting placeholders in the executor command. In particular, the placeholders `$fileName` and `$fileNameWithoutExt` are replaced with the file's base name and name without extension, respectively.

These two placeholder values are retrieved from the file system (via functions such as `getCodeBaseFile()` and `getCodeFileWithoutDirAndExt()`) and are inserted into the command without being wrapped in quotes or sanitized.

An attacker controlling the repository may include a file with a deliberately crafted name containing shell metacharacters (for example, using a semicolon, ampersand, or backticks).

When the executor command (as defined in the configuration) references these placeholders, the malicious file name is substituted directly into the command. This may prematurely terminate the intended command and inject additional arbitrary shell commands.

### Impact
Successful exploitation could lead to arbitrary command execution on the victim's machine. Depending on the injected commands, this may compromise the system, delete files, or leak sensitive information.

### Vulnerability Rank
High

### Currently Implemented Mitigations
Some placeholders (such as `$fullFileName`, `$dirWithoutTrailingSlash`, and `$dir`) are wrapped with a simple quoting function (`quoteFileName()`). However, the placeholders `$fileName` and `$fileNameWithoutExt` are not quoted during replacement.

### Missing Mitigations
- Proper escaping or quoting of all file name–based placeholders.
- Validation that file names do not contain malicious shell metacharacters before substituting them in the command.

### Preconditions
- The victim must run the Code Runner extension on a file whose name has been maliciously chosen (or crafted) by an attacker.
- The executor command configured (or defaulted) must reference either the `$fileName` or `$fileNameWithoutExt` placeholder.

### Source Code Analysis
In the `getFinalCommandToRunCodeFile()` function, after retrieving the command string from configuration, the code iterates over an array of placeholder objects.

For `$fileName` and `$fileNameWithoutExt`, the functions `getCodeBaseFile()` and `getCodeFileWithoutDirAndExt()` are used to obtain their values. Unlike other placeholders, these values are not processed using the `quoteFileName()` helper.

The final command is then executed using Node's `spawn()` with the `shell: true` option, which interprets any injected shell commands.

### Security Test Case
1. In a test repository, rename a source code file to a name such as `example; echo injected`.
2. Modify the executor command in the configuration (via workspace settings) so that it uses the `$fileName` placeholder. For instance, set an executor like:
   ```
   "gcc $fileName -o output && ./output"
   ```
3. Open the file and trigger the Code Runner command.
4. Monitor the terminal output to see if the injected command (`echo injected`) executes, thereby indicating successful command injection.