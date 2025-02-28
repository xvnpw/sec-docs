## Vulnerability List:

### 1. Command Injection in Heartbeat Sending

- Description:
    - The WakaTime extension for VSCode is vulnerable to command injection.
    - The vulnerability exists in the way the extension handles file paths when sending heartbeats to the WakaTime API via the `wakatime-cli`.
    - Specifically, the extension uses `child_process.execFile` to execute the `wakatime-cli` with arguments including the file path being tracked.
    - The file path is passed as an argument to the `--entity` flag of `wakatime-cli`.
    - The extension attempts to sanitize the file path using a custom `Utils.quote` function, which only adds double quotes around the string if it contains spaces.
    - This sanitization is insufficient to prevent command injection if the file path contains other special characters that are interpreted by the shell when `execFile` is used without `shell: false` option.
    - An attacker can create a file with a malicious name containing shell command separators or other injection payloads.
    - When the extension sends a heartbeat for this file, the malicious file name is passed to `wakatime-cli` and executed by `child_process.execFile`, leading to command injection.
    - Step-by-step trigger:
        1. An attacker creates a file in a project opened in VSCode with a malicious filename, for example:  `testfile\`\` -i "malicious command" \`\`.js`.
        2. The attacker opens this file in VSCode.
        3. The WakaTime extension triggers a heartbeat event for the opened file.
        4. The `sendHeartbeat` function in `src/wakatime.ts` is called.
        5. The `sendHeartbeat` function constructs arguments for `wakatime-cli`, including the malicious filename as the `--entity` argument.
        6. `child_process.execFile` is called with the `wakatime-cli` binary and the crafted arguments.
        7. Due to insufficient sanitization, the filename is not properly escaped, and the shell command injection payload in the filename is executed by the system shell.

- Impact:
    - **Critical**
    - Successful command injection allows the attacker to execute arbitrary commands on the system with the privileges of the user running VSCode.
    - This can lead to complete compromise of the user's machine, including data theft, malware installation, and further propagation of attacks.

- Vulnerability rank: critical

- Currently implemented mitigations:
    - The project uses a `Utils.quote` function in `src/utils.ts` to add double quotes around arguments containing spaces.
    - However, this mitigation is insufficient as it doesn't escape other shell-sensitive characters.
    - Location: `src/utils.ts` and usage in `src/wakatime.ts`.

- Missing mitigations:
    - Proper sanitization of file paths to prevent command injection.
    - Using `shell: false` option in `child_process.execFile` to avoid shell interpretation of arguments.
    - Consider using `child_process.spawn` with explicitly separated command and arguments, which inherently avoids shell injection when `shell: true` is not used.

- Preconditions:
    - The attacker needs to be able to create a file with a malicious name in a project folder that is opened in VSCode.
    - The WakaTime extension must be active and enabled.

- Source code analysis:
    - File: `/code/src/wakatime.ts`
    - Function: `sendHeartbeat` and `_sendHeartbeat`

    ```typescript
    private async _sendHeartbeat(
        doc: vscode.TextDocument,
        time: number,
        selection: vscode.Position,
        isWrite: boolean,
        isCompiling: boolean,
        isDebugging: boolean,
    ): Promise<void> {
        if (!this.dependencies.isCliInstalled()) return;

        let file = doc.fileName;
        // ...
        let args: string[] = [];

        args.push('--entity', Utils.quote(file)); // [!] Vulnerable point: file path is quoted using insufficient Utils.quote

        // ... other arguments ...

        const binary = this.dependencies.getCliLocation();
        this.logger.debug(`Sending heartbeat: ${Utils.formatArguments(binary, args)}`);
        const options = Desktop.buildOptions();
        let proc = child_process.execFile(binary, args, options, (error, stdout, stderr) => { // [!] Vulnerable point: child_process.execFile is used, which is susceptible to shell injection if arguments are not properly sanitized.
            // ... error handling ...
        });
        // ...
    }
    ```

    - File: `/code/src/utils.ts`
    - Function: `quote`

    ```typescript
    public static quote(str: string): string {
        if (str.includes(' ')) return `"${str.replace('"', '\\"')}"`; // [!] Insufficient sanitization: only handles spaces and double quotes.
        return str;
    }
    ```

- Security test case:
    - Step-by-step test:
        1. Create a new project directory, for example `wakatime-test-project`.
        2. Open VSCode and open the `wakatime-test-project` directory.
        3. Create a new file named `testfile\`\`payload\`\`.js` in `wakatime-test-project`. Replace `payload` with a command that will create a marker file in the user's home directory, for example: `\`\`touch $HOME/command_injection_marker\`\``. The final filename should be `testfile\`\`touch $HOME/command_injection_marker\`\`.js`.
        4. Open the created file `testfile\`\`touch $HOME/command_injection_marker\`\`.js` in VSCode editor.
        5. Observe if a file named `command_injection_marker` is created in your home directory (`$HOME`).
        6. If the file `command_injection_marker` is created, it indicates successful command injection.