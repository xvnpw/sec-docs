## Vulnerability List

- Vulnerability Name: Potential Command Injection in PowerShell Execution via `powerShellAdditionalExePaths` setting
- Description:
    1. An attacker can modify the `powerShellAdditionalExePaths` setting in VSCode. This setting allows users to specify additional PowerShell executable paths.
    2. The extension in `PowerShellExeFinder.enumerateAdditionalPowerShellInstallations` iterates through these paths and constructs `PossiblePowerShellExe` objects.
    3. If an attacker injects a specially crafted path containing command injection payloads into `powerShellAdditionalExePaths`, this payload could be executed when the extension attempts to execute PowerShell using this path.
    4. The vulnerability lies in the potential lack of proper sanitization or validation of the paths provided in the `powerShellAdditionalExePaths` setting, specifically when constructing the execution command. Although the code itself doesn't directly execute commands with these paths, the paths are used to spawn PowerShell processes which could be manipulated if the path itself is malicious.
- Impact: Arbitrary command execution. If an attacker can successfully inject a command into the path, they can execute arbitrary commands on the machine where the VSCode extension is running with the privileges of the VSCode process.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    - None in the provided code snippets directly related to sanitizing paths from `powerShellAdditionalExePaths`.
- Missing Mitigations:
    - Input sanitization and validation for paths provided in `powerShellAdditionalExePaths` setting. The extension should validate that the provided paths are indeed file paths and not contain any command injection characters or sequences.
- Preconditions:
    - Attacker needs to be able to modify VSCode settings, which could be achieved if the attacker has compromised the user's settings file or if there is another vulnerability that allows settings modification. For an external attacker, this is less likely unless they can trick a user to import malicious settings. However, if we consider a scenario where a user might copy settings from untrusted sources, this becomes a valid precondition.
- Source Code Analysis:
    1. **`src/settings.ts`:** (No changes in provided files, analysis remains the same as before) This file defines the `PowerShellAdditionalExePathSettings` type and the `Settings` class which includes `powerShellAdditionalExePaths`. It retrieves settings using `vscode.workspace.getConfiguration`, but doesn't perform any validation on the values themselves.
    2. **`src/platform.ts`:**
        - `PowerShellExeFinder.enumerateAdditionalPowerShellInstallations` function iterates over `this.additionalPowerShellExes` (which comes from settings).
        - The code retrieves `exePath` from settings and uses `untildify` to expand `~`. However, it does not sanitize the `exePath` for command injection characters.
        - `PossiblePowerShellExe` class is then instantiated with this potentially attacker-controlled path. While `PossiblePowerShellExe` itself doesn't execute code, the `exePath` is used later in `PowerShellProcess` to spawn a process.
        ```typescript
        private async *enumerateAdditionalPowerShellInstallations(): AsyncIterable<IPossiblePowerShellExe> {
            for (const versionName in this.additionalPowerShellExes) {
                if (Object.prototype.hasOwnProperty.call(this.additionalPowerShellExes, versionName)) {
                    let exePath: string | undefined = utils.stripQuotePair(this.additionalPowerShellExes[versionName]);
                    if (!exePath) {
                        continue;
                    }

                    exePath = untildify(exePath);
                    const args: [string, undefined, boolean, boolean]
                        // Must be a tuple type and is suppressing the warning
                        = [versionName, undefined, true, true];

                    // Always search for what the user gave us first, but with the warning
                    // suppressed so we can display it after all possibilities are exhausted
                    let pwsh = new PossiblePowerShellExe(exePath, ...args);
                    if (await pwsh.exists()) {
                        yield pwsh;
                        continue;
                    }
                    // ... (rest of the logic for finding executables)
                }
            }
        }
        ```
    3. **`src/process.ts`:**
        - `PowerShellProcess.start` function uses `this.exePath` (which can originate from `powerShellAdditionalExePaths`) to spawn a PowerShell process by creating a VSCode terminal.
        - The `shellPath` in `terminalOptions` is directly taken from `this.exePath`, which could originate from the unsanitized `powerShellAdditionalExePaths` setting. If a malicious path like `/path/to/pwsh; touch /tmp/pwned` is provided in settings, the `createTerminal` API might interpret the `;` as a command separator, leading to command injection.
        ```typescript
        public async start(cancellationToken: vscode.CancellationToken): Promise<IEditorServicesSessionDetails | undefined> {
            // ...
            const terminalOptions: vscode.TerminalOptions = {
                name: this.isTemp ? `${PowerShellProcess.title} (TEMP)` : PowerShellProcess.title,
                shellPath: this.exePath, // <--- Unsanitized path from settings
                shellArgs: powerShellArgs,
                cwd: await validateCwdSetting(this.logger),
                env: envMixin,
                iconPath: new vscode.ThemeIcon("terminal-powershell"),
                isTransient: true,
                hideFromUser: this.sessionSettings.integratedConsole.startInBackground,
                location: vscode.TerminalLocation[this.sessionSettings.integratedConsole.startLocation],
            };
            // ...
            this.consoleTerminal = vscode.window.createTerminal(terminalOptions);
            // ...
        }
        ```
    4. **`src/features/DebugSession.ts` and `src/features/ExtensionCommands.ts`**: These files do not directly interact with `powerShellAdditionalExePaths` or `PowerShellProcess` in a way that would mitigate or further expose this vulnerability. They use `PowerShellProcess` indirectly through session management for debugging, but the core vulnerability remains in the unsanitized path setting.
    5. **`test/core/platform.test.ts`**: This test file includes tests for `PowerShellExeFinder.enumerateAdditionalPowerShellInstallations`, but it focuses on verifying correct path expansion and file system traversal for finding executables, not on security aspects like command injection prevention. The tests use mocked file systems and environment variables, which are helpful for unit testing functionality but do not cover security validation. **The test file does not include any tests that try to use malicious paths or paths with command injection payloads in `powerShellAdditionalExePaths`, further highlighting the lack of security considerations in this area.**

- Security Test Case:
    1. Open VSCode.
    2. Open User Settings (JSON) or Workspace Settings (JSON).
    3. Add the following entry to `powershell.powerShellAdditionalExePaths`:
       ```json
       "powershell.powerShellAdditionalExePaths": {
           "Malicious PowerShell": "/usr/bin/pwsh; touch /tmp/pwned"
       }
       ```
       *(Note: Adjust the path `/usr/bin/pwsh` to a valid pwsh executable on your system and `/tmp/pwned` to a location where you have write access.)*
    4. Restart VSCode or reload the PowerShell extension.
    5. Open a PowerShell script or the extension terminal. This should trigger the extension to enumerate PowerShell installations, and attempt to use the malicious path.
    6. Observe if a file named `pwned` is created in the `/tmp` directory.
    7. If the `pwned` file is created, it indicates that the command injection was successful.

- Vulnerability Name: Potential Path Traversal Vulnerability in `validateCwdSetting`
- Description:
    1. The `validateCwdSetting` function in `src/settings.ts` is responsible for validating and resolving the current working directory (CWD) for the PowerShell extension.
    2. It takes the `powershell.cwd` setting, expands `~` using `untildify`, and then checks if the path is absolute and exists.
    3. If the `cwd` setting matches a workspace folder name, it uses the workspace folder as CWD.
    4. However, if the `cwd` setting contains path traversal characters (e.g., `../`, `..\\`), and it resolves to an existing directory outside the intended workspace or home directory, it could lead to a path traversal vulnerability.
    5. This vulnerability can be exploited if an attacker can influence the `powershell.cwd` setting, potentially by tricking a user into opening a workspace with a malicious `.vscode/settings.json` file or by other means of settings manipulation.
- Impact: Path traversal, potentially leading to information disclosure or actions being performed in unexpected directories. In the context of a VSCode extension, this could mean that PowerShell scripts or commands are executed in a directory outside of the user's intended workspace, potentially accessing or modifying sensitive files.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    - `untildify` to expand `~`.
    - `path.isAbsolute()` check.
    - `utils.checkIfDirectoryExists()` check.
- Missing Mitigations:
    - Path traversal sanitization to prevent navigating outside of intended boundaries (workspace or home directory). The validation should ensure that the resolved CWD is within the workspace or a predefined safe directory.
- Preconditions:
    - Attacker needs to be able to influence the `powershell.cwd` setting. This could be via a malicious workspace settings file or other settings modification methods.
- Source Code Analysis:
    1. **`src/settings.ts`:**
        - `validateCwdSetting` function retrieves the `cwd` setting:
        ```typescript
        export async function validateCwdSetting(logger: ILogger | undefined): Promise<string> {
            let cwd = utils.stripQuotePair(
                vscode.workspace.getConfiguration(utils.PowerShellLanguageId).get<string>("cwd"))
                ?? "";

            // Replace ~ with home directory.
            cwd = untildify(cwd);

            // Use the cwd setting if it's absolute and exists. We don't use or resolve
            // relative paths here because it'll be relative to the Code process's cwd,
            // which is not what the user is expecting.
            if (path.isAbsolute(cwd) && await utils.checkIfDirectoryExists(cwd)) {
                return cwd;
            }
            // ... (rest of the logic to determine cwd)
        }
        ```
        - `untildify(cwd)` expands `~`, which is generally safe, but doesn't prevent path traversal within the expanded directory.
        - `path.isAbsolute(cwd)` checks if the path is absolute, which is good, but an absolute path can still be a traversal path.
        - `await utils.checkIfDirectoryExists(cwd)` only checks for existence, not for path traversal.
        - The function returns the `cwd` if it's absolute and exists, without further sanitization for path traversal sequences.
    2. **`src/features/ExtensionCommands.ts`:**
        - `resolveFilePathWithCwd` function in `ExtensionCommands.ts` uses `validateCwdSetting`:
        ```typescript
        private async resolveFilePathWithCwd(filePath: string): Promise<string> {
            if (!path.isAbsolute(filePath)) {
                const cwd = await validateCwdSetting(this.logger);
                return path.resolve(cwd, filePath);
            }
            return filePath;
        }
        ```
        - This shows that file operations like `openFile`, `closeFile`, and `saveFile` in `ExtensionCommands.ts` are vulnerable to path traversal if `validateCwdSetting` returns a path outside the intended boundaries due to a malicious `powershell.cwd` setting.
    3. **`src/features/DebugSession.ts`:**
        - Debug configurations, especially `LaunchScript`, can use paths that are potentially resolved against the CWD. While the debug adapter execution context is more controlled, the initial path resolution could still be influenced by a path traversal vulnerability in `validateCwdSetting`.
    4. **`test/core/settings.test.ts`**: This test file includes tests for `validateCwdSetting`, verifying correct behavior for default CWD, non-existent folders, existing folders, home directory expansion, and relative paths. **However, the tests do not include any negative test cases that specifically check for path traversal vulnerabilities when the `cwd` setting contains malicious path traversal sequences like `../` to navigate outside of the intended workspace or home directory. This lack of security-focused testing reinforces the missing mitigation.**

- Security Test Case:
    1. Create a new VSCode workspace.
    2. In the workspace, create a `.vscode/settings.json` file.
    3. Add the following setting to `.vscode/settings.json`:
       ```json
       {
           "powershell.cwd": "../../"
       }
       ```
       *(This path attempts to traverse two levels up from the workspace root.)*
    4. Open a PowerShell file in the workspace.
    5. Start the PowerShell extension session (if not started automatically).
    6. Use a feature that relies on the CWD, for example, use "PowerShell: Open File" command and try to open a file using a relative path that would resolve outside of the workspace if path traversal is successful, e.g., `../../../../etc/passwd` (on Linux) or `../../../../Windows/System32/drivers/etc/hosts` (on Windows).
    7. Observe if the extension is able to access and open the file outside of the workspace. Check the logs or behavior to confirm if the CWD has been traversed outside the workspace root as intended by the malicious setting.
    8. Alternatively, in the Extension Terminal, check the current directory using `pwd` or `$pwd` to see if it reflects the traversed path.

- Vulnerability Name: Potential Command Injection in `OpenInISEFeature` via file path
- Description:
    1. The `OpenInISEFeature` executes PowerShell ISE using `ChildProcess.exec(\`${ISEPath} -File "\${uri.fsPath}"\`)`.
    2. The `uri.fsPath` is derived from the currently active text editor's document URI.
    3. If an attacker can somehow influence the `uri.fsPath` to contain command injection characters, they could execute arbitrary commands when the "PowerShell: Open in ISE" command is triggered.
    4. This is possible if a malicious workspace is crafted such that opening a file within it results in a `uri.fsPath` that contains command injection payloads. While directly controlling the file path might be difficult, if there is a way to manipulate how VSCode resolves or handles file paths within a workspace, it could be exploited.
- Impact: Arbitrary command execution. An attacker could execute arbitrary commands on the machine where VSCode is running with the privileges of the VSCode process.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    - None in the provided code directly related to sanitizing `uri.fsPath` before command execution in `OpenInISEFeature`.
- Missing Mitigations:
    - Input sanitization and validation for `uri.fsPath` before passing it to `ChildProcess.exec`. Ensure that the file path is treated as a literal path and not interpreted as a command. Using parameterized execution or escaping shell metacharacters in the file path before execution is needed.
- Preconditions:
    - Attacker needs to trick a user into opening a workspace that contains a file path which, when processed by VSCode and passed to `OpenInISEFeature`, results in a malicious `uri.fsPath`. This might involve exploiting how VSCode handles specially crafted file names or paths within a workspace.
    - User must trigger the "PowerShell: Open in ISE" command when a malicious file (or a file in a malicious workspace) is active in the editor.
- Source Code Analysis:
    1. **`src/features/OpenInISE.ts`:**
        - The `OpenInISEFeature` executes the command using `ChildProcess.exec`:
        ```typescript
        ChildProcess.exec(`${ISEPath} -File "${uri.fsPath}"`).unref();
        ```
        - `ISEPath` is constructed based on system environment variables and hardcoded paths, which is likely safe.
        - `uri.fsPath` is obtained from `editor.document.uri.fsPath`. While `uri.fsPath` is usually expected to be a safe file path, there's no explicit sanitization before it's embedded within the command string for `ChildProcess.exec`.
        - If `uri.fsPath` contains characters like `"` or `;` that are not properly escaped, it could lead to command injection. For example, if `uri.fsPath` is crafted as `\"; touch /tmp/pwned & \"`, the executed command might become:
        ```bash
        C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe -File "\"; touch /tmp/pwned & \""
        ```
        This could lead to the execution of `touch /tmp/pwned` command.

- Security Test Case:
    1. Create a new VSCode workspace.
    2. In the workspace, create a file with a malicious name. For example, create a file named `pwned_file\"; touch /tmp/pwned & \"`. Ensure this filename is properly handled by your OS and filesystem.
    3. Open this file in VSCode.
    4. Trigger the "PowerShell: Open in ISE" command (e.g., via command palette or context menu).
    5. Observe if a file named `pwned` is created in the `/tmp` directory.
    6. If the `pwned` file is created, it indicates that command injection was successful via the file path.