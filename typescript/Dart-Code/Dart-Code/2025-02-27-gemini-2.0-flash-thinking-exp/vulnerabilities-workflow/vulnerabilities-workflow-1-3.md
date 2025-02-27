## Vulnerability List

- Vulnerability Name: Command Injection via Custom Tool Scripts
- Description:
    The Dart Code extension allows users to specify custom scripts for various tools (Dart, Flutter, WebDev) through configuration settings like `dart.customTool`, `flutter.customTool`, and `webdev.customTool`. These custom scripts, defined in the extension's launch configurations, are executed by the extension using `safeSpawn` and `usingCustomScript` functions. If a malicious user were able to modify these settings (e.g., by contributing a malicious workspace configuration to a shared project or through a compromised workspace settings file), they could inject arbitrary commands into the executed scripts. This is because the arguments passed to these custom scripts are not properly sanitized, allowing for command injection vulnerabilities.
- Impact:
    Successful command injection can allow an attacker to execute arbitrary commands on the machine running VSCode with the privileges of the VSCode process. This could lead to sensitive information disclosure, modification of files, or further system compromise. In the context of a VSCode extension, this could potentially allow an attacker to gain control over the user's workspace and potentially their machine.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    The project uses `safeSpawn` to execute commands, which attempts to prevent some basic command injection by quoting arguments. However, this is not sufficient to prevent all types of command injection, especially with complex shell commands or when users can control parts of the command string directly (like in custom scripts).
- Missing Mitigations:
    - Input sanitization: The extension should sanitize any user-provided input (especially arguments to custom scripts) to prevent command injection. This could involve validating input against a whitelist, encoding special characters, or using safer APIs for command execution that avoid shell interpretation.
    - Disallow custom scripts from untrusted sources: The extension could restrict the use of custom scripts to only trusted workspaces or provide warnings to users when custom scripts are being used, especially if they originate from untrusted sources (like shared workspaces or repositories).
- Preconditions:
    - User must use a launch configuration that utilizes the `customTool` or `customToolReplacesArgs` settings.
    - An attacker must be able to modify the workspace or user settings to inject malicious code into the custom script path or its arguments.
- Source Code Analysis:
    - File: `/code/src/shared/processes.ts`
        - The `safeSpawn` function is used to spawn processes, but it relies on shell quoting, which is not a robust mitigation against command injection, especially when complex shell commands or user-controlled arguments are involved.
    - File: `/code/src/debug/dart_debug_impl.ts`
        - In `DartDebugSession.spawnProcess` and `DartDebugSession.spawnRemoteEditorProcess`, the `buildExecutionInfo` method is called.
        - File: `/code/src/debug/dart_debug_impl.ts`
        - In `DartDebugSession.buildExecutionInfo`, the `usingCustomScript` function is used to potentially modify the executable and arguments based on user settings (`args.customTool`, `args.customToolReplacesArgs`).
        - File: `/code/src/shared/utils.ts`
        - The `usingCustomScript` function from `/code/src/shared/utils.ts` takes user-controlled `customTool` and `customToolReplacesArgs` without sufficient sanitization and constructs commands that are then passed to `safeSpawn`.

        ```
        // Visualization of code flow in `DartDebugSession.buildExecutionInfo`:

        // User-provided settings (launch.json)
        const args = {
            customTool: args.customTool, // Potentially malicious script path
            customToolReplacesArgs: args.customToolReplacesArgs, // User-controlled argument replacement index
            vmAdditionalArgs: args.vmAdditionalArgs,
            toolArgs: args.toolArgs,
            args: args.args,
            dartSdkPath: args.dartSdkPath,
            program: args.program
        };

        // ...

        // Call to usingCustomScript with user-controlled customTool and replacesArgs
        const execution = usingCustomScript(
            binPath, // Dart VM path (generally safe)
            allArgs, // Arguments, potentially containing user input
            customTool, // User-provided custom script details
        );

        // ...

        // safeSpawn is called with potentially unsafe executable and args
        const process = safeSpawn(args.cwd, dartPath, appArgs, env);
        ```
    - File: `/code/src/test/test_projects/hello_world/scripts/custom_dart.sh` and similar files
        - These script files demonstrate how custom scripts are intended to be used and show that arguments are directly appended to the command, highlighting the potential for injection if a user provides malicious input as part of configuration.
- Security Test Case:
    1. Create a new Dart project in VS Code.
    2. Open the `launch.json` file and add a new configuration of type "dart".
    3. In the new configuration, add the following configuration to exploit the vulnerability:
        ```json
        {
            "name": "Dart: Custom Tool Command Injection",
            "type": "dart",
            "request": "launch",
            "program": "bin/main.dart",
            "customTool": "/bin/bash",
            "customToolReplacesArgs": 0,
            "toolArgs": [
                "-c",
                "touch /tmp/pwned" // Malicious command injection
            ]
        }
        ```
    4. Run the debug configuration "Dart: Custom Tool Command Injection".
    5. After the debug session ends, check if the file `/tmp/pwned` exists. If the file exists, the vulnerability is confirmed.
    6. For Windows, the `customTool` and `toolArgs` should be adjusted to use `cmd.exe` and a valid Windows command (e.g., `type nul > C:\\pwned.txt`).