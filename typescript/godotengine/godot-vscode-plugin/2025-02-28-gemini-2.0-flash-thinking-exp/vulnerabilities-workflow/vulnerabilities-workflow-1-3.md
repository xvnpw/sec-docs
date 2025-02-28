- Vulnerability Name: Command Injection in Godot Editor Launch via Workspace Setting
- Description:
    1. An attacker can modify the workspace settings (`.code-workspace` file) within a Godot project that they can convince a victim to open.
    2. The attacker sets a malicious path for `godotTools.editorPath.godot3` or `godotTools.editorPath.godot4` in the workspace settings. This path points to a malicious executable instead of the actual Godot editor.
    3. The victim opens the workspace in VSCode and uses the "Godot Tools: Open workspace with Godot editor" command.
    4. The extension executes the malicious executable specified in the workspace settings, potentially leading to arbitrary code execution on the victim's machine.
- Impact: Arbitrary code execution on the victim's machine with the privileges of the VSCode process. This can lead to data theft, malware installation, or further system compromise.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The extension uses the path directly from the workspace configuration without sanitization.
- Missing Mitigations:
    - Input sanitization and validation of the `godotTools.editorPath.godot3` and `godotTools.editorPath.godot4` settings, especially when read from workspace configurations.
    - Displaying a warning to the user when workspace settings override the global/user settings for `godotTools.editorPath.*`.
    - Potentially restricting the execution of Godot editor to paths within the workspace or known safe locations.
- Preconditions:
    - The victim must open a workspace that contains a malicious `.code-workspace` file.
    - The victim must execute the "Godot Tools: Open workspace with Godot editor" command.
- Source Code Analysis:
    1. File `/code/src/extension.ts` function `open_workspace_with_editor`:
    ```typescript
    async function open_workspace_with_editor() {
    ...
        const settingName = `editorPath.godot${projectVersion[0]}`;
        const result = verify_godot_version(get_configuration(settingName), projectVersion[0]); // [1] get_configuration is used here
        const godotPath = result.godotPath;

        switch (result.status) {
            case "SUCCESS": {
                let command = `"${godotPath}" --path "${projectDir}" -e`; // [2] godotPath is used in command execution
                if (get_configuration("editor.verbose")) {
                    command += " -v";
                }
                ...
                const options: vscode.ExtensionTerminalOptions = {
                    name: "Godot Editor",
                    iconPath: get_extension_uri("resources/godot_icon.svg"),
                    pty: new GodotEditorTerminal(command), // [3] command is passed to terminal
                    isTransient: true,
                };
                const terminal = vscode.window.createTerminal(options);
                if (get_configuration("editor.revealTerminal")) {
                    terminal.show();
                }
                break;
            }
            ...
        }
    }
    ```
    - [1] `get_configuration(settingName)` in `/code/src/utils/vscode_utils.ts` retrieves the setting value. When a workspace configuration is present, it will override user/global settings.
    - [2] The `godotPath`, obtained from the potentially attacker-controlled workspace configuration, is directly incorporated into a shell command without sanitization.
    - [3] This command is then executed in a VSCode terminal using `GodotEditorTerminal` in `/code/src/extension.ts`, leading to command injection.
    2. File `/code/src/utils/vscode_utils.ts` function `get_configuration`:
    ```typescript
    export function get_configuration(name: string, defaultValue?: any) {
        const configValue = vscode.workspace.getConfiguration(EXTENSION_PREFIX).get(name, null); // [4] workspace.getConfiguration
        if (defaultValue && configValue === null) {
            return defaultValue;
        }
        return configValue;
    }
    ```
    - [4] `vscode.workspace.getConfiguration(EXTENSION_PREFIX).get(name, null)` retrieves the configuration, prioritizing workspace settings if available.

    Visualization:

    ```mermaid
    graph LR
        A[User opens malicious workspace] --> B(VSCode loads workspace settings);
        B --> C{Workspace settings for godotTools.editorPath.*?};
        C -- Yes --> D[Attacker controlled malicious path];
        C -- No --> E[User/Global settings];
        D --> F(get_configuration() returns malicious path);
        E --> F(get_configuration() returns user/global path);
        F --> G{User executes "Open workspace with Godot editor" command};
        G --> H["`"${godotPath}" --path ... -e` command\nconstructed with malicious path"];
        H --> I(GodotEditorTerminal executes command);
        I --> J[Arbitrary code execution];
    ```
- Security Test Case:
    1. Create a new folder named `godot_vuln_test`.
    2. Inside `godot_vuln_test`, create a file named `malicious.sh` (or `malicious.bat` on Windows) with the following content:
        ```bash
        #!/bin/bash
        echo "Vulnerable!" > /tmp/vuln.txt # or C:\vuln.txt on Windows
        ```
        (For Windows `malicious.bat`):
        ```bat
        @echo off
        echo Vulnerable! > C:\vuln.txt
        ```
        Make sure to make the script executable (`chmod +x malicious.sh`).
    3. Inside `godot_vuln_test`, create a file named `test.code-workspace` with the following content, adjusting the path to `malicious.sh` (or `malicious.bat`):
        ```jsonc
        {
            "folders": [
                {
                    "path": "."
                }
            ],
            "settings": {
                "godotTools.editorPath.godot4": "/tmp/malicious.sh" // or "C:\\vuln\\malicious.bat" on Windows, adjust the path
            }
        }
        ```
        Adjust the path to point to the location of `malicious.sh` or `malicious.bat` you created.
    4. Open VSCode and then open the `godot_vuln_test` folder as a workspace by opening the `test.code-workspace` file.
    5. Open the command palette (Ctrl+Shift+P or Cmd+Shift+P) and execute the command "Godot Tools: Open workspace with Godot editor".
    6. Check if the file `/tmp/vuln.txt` (or `C:\vuln.txt` on Windows) has been created and contains the text "Vulnerable!". If it does, the vulnerability is confirmed.