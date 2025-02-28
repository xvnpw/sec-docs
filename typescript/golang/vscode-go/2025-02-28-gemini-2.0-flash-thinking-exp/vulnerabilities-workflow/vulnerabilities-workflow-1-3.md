## Vulnerability List for VSCode Go Extension

### 2. Vulnerability Name: Potential Command Injection in custom formatTool

- Description: The VSCode Go extension allows users to configure a custom formatting tool via the `go.formatTool` and `go.alternateTools` settings. If a user configures `go.formatTool` to `custom` and `go.alternateTools.customFormatter` to a path controlled by an attacker, or a path containing malicious arguments, it could lead to command injection when the extension executes this custom formatter.
- Impact: Arbitrary code execution on the user's machine with the privileges of the VSCode process. This could lead to data exfiltration, malware installation, or other malicious activities.
- Vulnerability Rank: High
- Currently Implemented Mitigations: The extension uses `resolvePath` function to resolve the path of the custom formatter. However, this function does not prevent command injection if the resolved path itself contains malicious arguments. The `usingCustomFormatTool` function checks against a predefined list of safe formatters, but this check is bypassed when `go.formatTool` is set to `custom`.
- Missing Mitigations:
    - Input validation and sanitization for the `go.alternateTools.customFormatter` setting. The extension should verify that the path is safe and does not contain any command injection characters.
    - Consider disallowing the `custom` formatTool option altogether or providing a more secure way to configure custom tools.
- Preconditions:
    - The attacker needs to convince a user to set `go.formatTool` to `custom` and `go.alternateTools.customFormatter` to a malicious path or a path with malicious arguments. This could be achieved through social engineering or by compromising the user's settings.json file.
- Source Code Analysis:
    1. In `/code/extension/src/language/legacy/goFormat.ts`, the `getFormatTool` function retrieves the format tool path based on the `goConfig['formatTool']` setting.
    2. If `goConfig['formatTool']` is set to `custom`, it uses `resolvePath(goConfig['alternateTools']['customFormatter'] || 'goimports')` to get the path.
    3. The `resolvePath` function in `/code/extension/src/util.ts` only resolves `~` to the home directory but does not sanitize the path for command injection.
    4. The `GoDocumentFormattingEditProvider.runFormatter` function then uses `cp.spawn(formatCommandBinPath, formatFlags, { env, cwd })` to execute the formatter.
    5. If `formatCommandBinPath` (which is derived from `goConfig['alternateTools']['customFormatter']`) is attacker-controlled or contains malicious arguments, `cp.spawn` could execute arbitrary commands.
    ```typescript
    // /code/extension/src/language/legacy/goFormat.ts
    private runFormatter(
        formatTool: string,
        formatFlags: string[],
        document: vscode.TextDocument,
        token: vscode.CancellationToken
    ): Thenable<vscode.TextEdit[]> {
        const formatCommandBinPath = getBinPath(formatTool); // formatTool is from getFormatTool which can return user-controlled path
        if (!path.isAbsolute(formatCommandBinPath)) {
            // ...
        }
        return new Promise<vscode.TextEdit[]>((resolve, reject) => {
            const env = toolExecutionEnvironment();
            const cwd = path.dirname(document.fileName);
            let stdout = '';
            let stderr = '';

            // Use spawn instead of exec to avoid maxBufferExceeded error
            const p = cp.spawn(formatCommandBinPath, formatFlags, { env, cwd }); // formatCommandBinPath is potentially unsafe
            token.onCancellationRequested(() => !p.killed && killProcessTree(p));
            // ...
        });
    }
    ```
- Security Test Case:
    1. Create a malicious script (e.g., `malicious_formatter.sh` on Linux or `malicious_formatter.bat` on Windows) that executes a harmful command (e.g., creates a file in `/tmp` or `C:\`).
    2. In VSCode settings, set `go.formatTool` to `custom`.
    3. Set `go.alternateTools.customFormatter` to the absolute path of the malicious script.
    4. Open a Go file in VSCode.
    5. Trigger document formatting (e.g., Shift+Alt+F).
    6. Observe that the harmful command in the malicious script is executed (e.g., the file in `/tmp` or `C:\` is created).