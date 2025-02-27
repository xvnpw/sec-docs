### Vulnerability List

* Vulnerability Name: Arbitrary Code Execution via Workspace Configuration
* Description:
    1. An attacker creates a malicious Laravel project.
    2. The attacker adds a `.vscode/settings.json` file to the project, setting the `LaravelExtraIntellisense.phpCommand` configuration to execute arbitrary commands, for example: `bash -c "mkdir /tmp/vscode-laravel-extra-intellisense-pwned"`.
    3. The attacker convinces a victim to open this malicious Laravel project in VSCode with the "Laravel Extra Intellisense" extension installed.
    4. When the victim opens the project, the extension activates and executes the configured `phpCommand`.
    5. The arbitrary command is executed on the victim's machine. For example, a directory `/tmp/vscode-laravel-extra-intellisense-pwned` is created.
* Impact: Arbitrary code execution on the victim's machine, potentially leading to data theft, malware installation, or system compromise.
* Vulnerability Rank: high
* Currently implemented mitigations:
    - The extension includes a "Security Note" in the README.md file, warning users that the extension executes their Laravel application.
    - The extension displays error alerts when it can't get data, which might indirectly alert users if something unexpected happens due to malicious configuration.
* Missing mitigations:
    - A warning message displayed to the user upon activation of the extension in a workspace, explicitly stating that the extension will execute PHP code from the workspace and advising caution when opening untrusted projects.
    - Input validation or sanitization for the `phpCommand` setting is missing, although sanitizing command execution is complex and might not be fully effective.
    - Sandboxing the execution of the PHP code to limit the potential damage from malicious code execution. This is a more complex mitigation.
* Preconditions:
    - The victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim opens a malicious Laravel project provided by the attacker in VSCode.
    - The malicious project contains a `.vscode/settings.json` file with a maliciously crafted `LaravelExtraIntellisense.phpCommand` setting.
* Source code analysis:
    1. `/code/src/helpers.ts`: The `runPhp` function retrieves the `phpCommand` configuration from VSCode settings:
       ```typescript
       let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
       let command = commandTemplate.replace("{code}", code);
       cp.exec(command, ...);
       ```
       This code directly substitutes the user-provided `phpCommand` setting into the `cp.exec` command without any sanitization or validation.
    2. `/code/src/extension.ts`: The `activate` function is called when the extension is activated, which usually happens when a workspace is opened in VSCode. The extension then proceeds to register completion providers, which trigger the execution of PHP code via `Helpers.runLaravel` and `Helpers.runPhp`.
    3. Multiple provider files (e.g., `/code/src/RouteProvider.ts`, `/code/src/ViewProvider.ts`, etc.): These providers call `Helpers.runLaravel()` with hardcoded PHP code snippets to fetch Laravel application data for autocompletion. This triggers the vulnerable code execution path when the extension is active and autocompletion is invoked.
* Security test case:
    1. Create a new directory named `malicious-laravel-project`.
    2. Inside `malicious-laravel-project`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "bash -c 'mkdir /tmp/vscode-laravel-extra-intellisense-pwned'"
       }
       ```
    4. Open VSCode and open the `malicious-laravel-project` directory as a workspace. Ensure the "Laravel Extra Intellisense" extension is installed and activated.
    5. Observe the file system. Check if a directory named `vscode-laravel-extra-intellisense-pwned` has been created in the `/tmp` directory.
    6. If the directory `/tmp/vscode-laravel-extra-intellisense-pwned` exists, the vulnerability is confirmed.