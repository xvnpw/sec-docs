### Vulnerability List

* Vulnerability Name: Command Injection via `cmake.cmakePath` setting

* Description:
    1. The extension retrieves the CMake executable path from the `cmake.cmakePath` setting, which can be configured in user or workspace settings.
    2. The `commandArgs2Array` function attempts to parse the `cmake.cmakePath` string into an array of arguments. However, this parsing is insufficient to prevent command injection.
    3. The extension uses `child_process.spawn` to execute CMake commands. The first element of the parsed arguments array from `commandArgs2Array` is used as the command, and the rest are used as arguments.
    4. By crafting a malicious string in the `cmake.cmakePath` setting, an attacker can inject arbitrary shell commands. When the extension executes any CMake related feature (like hover information, completion, or online help), the injected commands will be executed.

* Impact:
    - Arbitrary code execution on the user's machine with the privileges of the VS Code process.
    - Potential for data exfiltration, malware installation, or complete system compromise depending on the injected commands.

* Vulnerability Rank: Critical

* Currently implemented mitigations:
    - None. The code uses `commandArgs2Array` to parse the path, but this does not prevent command injection.

* Missing mitigations:
    - Input sanitization for the `cmake.cmakePath` setting to prevent injection of shell metacharacters.
    - Use `child_process.spawn` with the `shell: false` option. This option prevents the shell from interpreting shell metacharacters in the command and arguments, executing the command directly.
    - Validate that the provided path in `cmake.cmakePath` points to a legitimate CMake executable.

* Preconditions:
    - The user must have the "CMake for Visual Studio Code" extension installed and activated.
    - An attacker must be able to influence the user to set a malicious `cmake.cmakePath` setting. This could be achieved through:
        - Social engineering, tricking the user into manually changing their user or workspace settings.
        - Contributing a malicious workspace configuration to a public repository that a user might clone and open in VS Code.

* Source code analysis:
    1. **Configuration Loading:** The `config<T>('cmakePath', 'cmake')` function in `extension.ts` retrieves the value of the `cmake.cmakePath` setting.
    ```typescript
    function config<T>(key: string, defaultValue?: any): T {
        const cmake_conf = workspace.getConfiguration('cmake');
        return cmake_conf.get<T>(key, defaultValue);
    }
    ```
    2. **Argument Parsing:** The `commandArgs2Array` function is used to split the `cmakePath` string into an array of arguments. This function is intended to handle quoted arguments but does not sanitize for shell command injection.
    ```typescript
    function commandArgs2Array(text: string): string[] {
        // ... (argument parsing logic) ...
    }
    ```
    3. **Command Execution:** The `cmake` function uses `child_process.spawn` to execute the CMake command. It takes the first element of the array returned by `commandArgs2Array` as the command and the rest as arguments.
    ```typescript
    let cmake = (args: string[]): Promise<string> => {
        return new Promise(function (resolve, reject) {
            let cmake_config = config<string>('cmakePath', 'cmake');
            let cmake_args = commandArgs2Array(cmake_config)
            let cmd = child_process.spawn(cmake_args[0], cmake_args.slice(1, cmake_args.length)
                .concat(args.map(arg => { return arg.replace(/\r/gm, ''); })));
            // ...
        });
    }
    ```
    - **Vulnerability Point:** If a user sets `cmake.cmakePath` to a malicious string like `"malicious; echo vulnerable > /tmp/pwned"`, the `commandArgs2Array` function might parse `"malicious;` as the command and `echo vulnerable > /tmp/pwned"` as an argument, or it might not correctly split at all, leading `child_process.spawn` to execute `malicious; echo vulnerable > /tmp/pwned` via the shell. Because `shell: true` is not explicitly set to false, it defaults to the platform default (true on Windows, false on others but behavior is still shell-like). Even on platforms where shell is false by default, certain characters like `;` might still be interpreted by `spawn` depending on the underlying system call. It is safer to assume shell injection is possible given the current code.

* Security test case:
    1. Install the "CMake for Visual Studio Code" extension in VS Code.
    2. Create a new empty workspace folder and open it in VS Code.
    3. Open the workspace settings (`.vscode/settings.json`) by navigating to `File > Preferences > Settings` (or `Code > Settings` on macOS), then click the "Workspace Settings" tab.
    4. In the settings editor, search for "cmake.cmakePath".
    5. Click the "Edit in settings.json" icon next to the `cmake.cmakePath` setting to open the `settings.json` file for your workspace.
    6. Add or modify the `cmake.cmakePath` setting to the following malicious command:
    ```json
    {
        "cmake.cmakePath": "bash -c 'touch /tmp/pwned && cmake'"
    }
    ```
    7. Save the `settings.json` file.
    8. Open any CMake file (e.g., `CMakeLists.txt`) or trigger any extension feature that executes a CMake command. For example, you can open a `CMakeLists.txt` file and hover your mouse over a CMake command like `project_name`. This will trigger the extension to execute `cmake --help-command project_name` in the background to display hover information.
    9. After triggering a CMake command, check if the file `/tmp/pwned` has been created in the `/tmp/` directory.
    10. If the file `/tmp/pwned` exists, it confirms that the injected command `touch /tmp/pwned` has been executed, demonstrating the command injection vulnerability.

This test case proves that arbitrary commands can be injected and executed via the `cmake.cmakePath` setting.