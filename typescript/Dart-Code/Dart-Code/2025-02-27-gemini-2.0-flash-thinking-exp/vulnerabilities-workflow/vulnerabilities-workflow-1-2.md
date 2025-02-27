- Vulnerability Name: Command Injection via Custom Tool Script
  - Description:
    1. An attacker can craft a malicious `launch.json` configuration for a Dart or Flutter debug session.
    2. This malicious configuration can specify a `customTool` script and `customToolReplacesArgs`.
    3. If the `customToolReplacesArgs` is set to a value that includes user-controlled arguments (like the target program), and the `customTool` script does not properly sanitize these arguments, it can lead to command injection.
    4. When the user starts a debug session using this crafted `launch.json`, the VS Code extension will execute the malicious script with attacker-controlled arguments.
  - Impact:
    - **High**: Successful command injection can allow the attacker to execute arbitrary code on the machine running VS Code with the privileges of the VS Code process. This could lead to:
        - Data exfiltration.
        - Installation of malware.
        - Privilege escalation.
        - Further compromise of the user's system.
  - Vulnerability Rank: high
  - Currently Implemented Mitigations:
    - None. The code in `src/shared/utils/processes.ts` and `src/debug/dart_debug_impl.ts` does not perform any sanitization of arguments passed to the custom tool script.
  - Missing Mitigations:
    - Input sanitization: The project should sanitize user-provided arguments before passing them to the `customTool` script execution. This could involve:
        - Whitelisting allowed characters.
        - Encoding/escaping special characters.
        - Validating argument structure and content.
  - Preconditions:
    1. Attacker needs to be able to provide a malicious `launch.json` configuration to the user. This could be achieved by:
        - Social engineering (e.g., tricking a user into opening a workspace containing the malicious launch configuration).
        - Supply chain attacks (e.g., compromising a workspace or project template that users might download and use).
  - Source Code Analysis:
    1. **File:** `/code/src/shared/utils/processes.ts`
    ```typescript
    export function safeSpawn(workingDirectory: string | undefined, binPath: string, args: string[], env: { [key: string]: string | undefined } | undefined): SpawnedProcess {
        ...
        return child_process.spawn(binPath, args, { cwd: workingDirectory, env: customEnv }) as SpawnedProcess;
    }
    ```
    The `safeSpawn` function directly uses `child_process.spawn` with user-provided `binPath` and `args` without any sanitization.

    2. **File:** `/code/src/debug/dart_debug_impl.ts`
    ```typescript
    private buildExecutionInfo(binPath: string, args: DartLaunchArgs): ExecutionInfo {
        ...
        const customTool = {
            replacesArgs: args.customToolReplacesArgs,
            script: args.customTool,
        };
        const execution = usingCustomScript(
            binPath,
            allArgs,
            customTool,
        );
        allArgs = execution.args;
        ...
    }
    ```
    The `buildExecutionInfo` function in `DartDebugSession` uses `usingCustomScript` to potentially replace arguments with a user-supplied script.

    3. **File:** `/code/src/shared/utils.ts`
    ```typescript
    export function usingCustomScript(
        binPath: string,
        binArgs: string[],
        customTool: CustomScript | undefined,
    ): ExecutionInfo {
        if (customTool?.script) {
            binPath = customTool.script;
            if (customTool.replacesArgs)
                binArgs = binArgs.slice(customTool.replacesArgs);
        }

        return {
            args: allArgs,
            executable: execution.executable,
        };
    }
    ```
    The `usingCustomScript` function directly replaces the `binPath` and slices `binArgs` based on user-provided settings without sanitization.

    **Visualization:**

    ```mermaid
    graph LR
        A[launchRequest in DartDebugSession] --> B{buildExecutionInfo};
        B --> C{usingCustomScript};
        C --> D{safeSpawn};
        D --> E[child_process.spawn];
        F[Malicious launch.json: customTool/customToolReplacesArgs] --> B;
        G[External Attacker] --> F;
        E -- Command Injection --> H[Attacker gains code execution]
    ```

  - Security Test Case:
    1. Create a new Dart project.
    2. Create a new file `malicious_script.sh` in the project root with the following content:
    ```bash
    #!/bin/bash
    mkdir -p `dirname "$0"`/has_run && touch `dirname "$0"`/has_run/pwned
    dart "$@"
    ```
    ```batch
    @echo off
    mkdir "%~dp0has_run" 2>nul
    echo > "%~dp0has_run\dart.bat"
    dart %*
    ```
    3. Modify the `.vscode/launch.json` to include the following configuration:
    ```json
    {
        "version": "0.2.0",
        "configurations": [
            {
                "name": "Dart: Run Malicious Script",
                "type": "dart",
                "request": "launch",
                "program": "bin/main.dart",
                "customTool": "${workspaceFolder}/malicious_script.sh",
                "customToolReplacesArgs": 1,
                "toolArgs": ["--arg"]
            }
        ]
    }
    ```
    (Adjust `customTool` path for Windows to `"${workspaceFolder}\\malicious_script.bat"` and remove shebang from script if using `.bat`)
    4. Open `bin/main.dart` and set a breakpoint.
    5. Run the "Dart: Run Malicious Script" debug configuration.
    6. After debug session starts and terminates, check if a new folder `has_run` with file `pwned` exists in the `scripts` folder of the project root.
    7. If the file exists, the vulnerability is confirmed because the `malicious_script.sh` was executed, creating the file.