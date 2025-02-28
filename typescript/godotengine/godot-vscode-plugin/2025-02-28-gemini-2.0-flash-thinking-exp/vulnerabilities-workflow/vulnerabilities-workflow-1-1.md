### Vulnerability List

- Vulnerability Name: Command Injection in Godot Editor and Debugger Launch

- Description:
    1. The extension allows users to configure the path to the Godot editor executable via the `godotTools.editorPath.godot3` and `godotTools.editorPath.godot4` settings.
    2. This configured path is used in several commands, including "Open workspace with Godot editor", "Start Language Server (Headless LSP)", and when launching the debugger.
    3. In these commands, the configured Godot editor path is directly embedded into shell commands using template literals without sufficient sanitization.
    4. An attacker could potentially configure the Godot editor path to include malicious shell commands.
    5. When the extension executes commands like "Open workspace with Godot editor", "Start Language Server (Headless LSP)", or starts debugging, these malicious commands would be executed by the system shell.

- Impact:
    - Arbitrary code execution on the user's machine with the privileges of the VSCode process.
    - An attacker could potentially gain full control of the user's system, steal sensitive data, or install malware.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - The project uses `verify_godot_version` to check the Godot executable version, but this function still executes the provided path to get the version, and does not prevent command injection if the path itself is malicious.
    - `clean_godot_path` function is used to remove surrounding quotes and handle macOS `.app` paths, but it does not sanitize against command injection characters.

- Missing Mitigations:
    - Input sanitization of the Godot editor path to remove or escape shell-sensitive characters before constructing shell commands.
    - Use of parameterized execution or safer APIs for process spawning that avoid shell interpolation, like `child_process.spawn` with arguments array instead of shell:true.

- Preconditions:
    - The attacker needs to be able to modify the VSCode settings for the Godot Tools extension. This could be achieved by:
        - Social engineering to trick a user into manually changing the settings.
        - If there are other vulnerabilities in VSCode or other extensions that allow settings modification.
        - Supply chain attack by compromising a settings sync service if used by the victim.

- Source Code Analysis:
    1. **File: `/code/src/extension.ts` - `open_workspace_with_editor` function:**
        ```typescript
        async function open_workspace_with_editor() {
            // ...
            const settingName = `editorPath.godot${projectVersion[0]}`;
            const result = verify_godot_version(get_configuration(settingName), projectVersion[0]);
            const godotPath = result.godotPath;
            // ...
            case "SUCCESS": {
                let command = `"${godotPath}" --path "${projectDir}" -e`; // Vulnerable command construction
                // ...
                const options: vscode.ExtensionTerminalOptions = {
                    name: "Godot Editor",
                    iconPath: get_extension_uri("resources/godot_icon.svg"),
                    pty: new GodotEditorTerminal(command), // Command is passed to terminal
                    isTransient: true,
                };
                const terminal = vscode.window.createTerminal(options);
                // ...
                break;
            }
            // ...
        }

        class GodotEditorTerminal implements vscode.Pseudoterminal {
            // ...
            open(initialDimensions: vscode.TerminalDimensions | undefined): void {
                const proc = subProcess("GodotEditor", this.command, { shell: true, detached: true }); // shell: true is used
                // ...
            }
            // ...
        }
        ```
        The `command` variable is constructed using template literals embedding `godotPath` and other parameters, and then executed using `subProcess` with `shell: true`, making it vulnerable to command injection.

    2. **File: `/code/src/lsp/ClientConnectionManager.ts` - `start_language_server` function:**
        ```typescript
        private async start_language_server() {
            // ...
            const settingName = `editorPath.godot${projectVersion[0]}`;
            let godotPath = get_configuration(settingName);
            const result = verify_godot_version(godotPath, projectVersion[0]);
            godotPath = result.godotPath;
            // ...
            this.client.port = await get_free_port();
            // ...
            const command = `"${godotPath}" --path "${projectDir}" --editor ${headlessFlags} --lsp-port ${this.client.port}`; // Vulnerable command construction
            const lspProcess = subProcess("LSP", command, { shell: true, detached: true }); // shell: true is used
            // ...
        }
        ```
        Similar to `open_workspace_with_editor`, the `command` is constructed vulnerably and executed with `shell: true`.

    3. **File: `/code/src/debugger/godot3/server_controller.ts` and `/code/src/debugger/godot4/server_controller.ts` - `launch` function:**
        ```typescript
        public async launch(args: LaunchRequestArguments) {
            // ...
            let command = `"${godotPath}" --path "${args.project}"`; // Vulnerable command construction
            const address = args.address.replace("tcp://", "");
            command += ` --remote-debug "${address}:${args.port}"`;
            // ...
            command += this.session.debug_data.get_breakpoint_string();
            // ...
            log.info(`Launching game process using command: '${command}'`);
            const debugProcess = subProcess("debug", command, { shell: true, detached: true }); // shell: true is used
            // ...
        }
        ```
        Again, the `command` is vulnerably constructed with `godotPath` and other parameters and executed with `shell: true`. This pattern is present in both Godot 3 and Godot 4 debugger server controllers.

- Security Test Case:
    1. Open VSCode with a Godot project.
    2. Go to VSCode settings and find the `godotTools.editorPath.godot4` or `godotTools.editorPath.godot3` setting.
    3. Set the value of this setting to a malicious command, for example: `/Applications/Calculator.app/Contents/MacOS/Calculator; echo vulnerable > /tmp/vuln.txt;`. (Note: the exact malicious command will depend on the operating system. `/Applications/Calculator.app/Contents/MacOS/Calculator` is a valid executable path on macOS that will also execute the additional command after semicolon). For Windows, a similar path to `calc.exe` can be used, and for Linux, `gnome-calculator` or similar. For testing purposes, a simple `touch /tmp/vuln.txt` or `echo vulnerable > /tmp/vuln.txt` might be more convenient.
    4. Execute the "Godot Tools: Open workspace with Godot editor" command from the command palette.
    5. Check if the malicious command was executed. In this example, check if the file `/tmp/vuln.txt` was created with the content "vulnerable".
    6. Repeat steps 2-5 for "Godot Tools: Start Language Server" and "Debug Current File" or "Debug Pinned File" commands, and verify that malicious commands are also executed in these scenarios.