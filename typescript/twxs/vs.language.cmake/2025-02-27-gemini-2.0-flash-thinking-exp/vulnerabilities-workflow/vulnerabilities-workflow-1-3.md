### Vulnerability List

* Vulnerability Name: Workspace Settings Command Injection via `cmakePath`
* Description:
    An attacker can craft a malicious workspace that, when opened in VSCode with the CMake extension installed, allows for arbitrary code execution. This is achieved by manipulating the workspace settings to set the `cmake.cmakePath` configuration to a malicious executable or script. When the extension subsequently attempts to execute a CMake command (e.g., for online help, code completion, or hover information), it will inadvertently execute the attacker-controlled script instead of the legitimate CMake executable.

    Steps to trigger the vulnerability:
    1. Attacker creates a malicious script (e.g., `malicious.sh`) that performs malicious actions.
    2. Attacker creates a VSCode workspace and includes a `.vscode/settings.json` file within it.
    3. In the `.vscode/settings.json` file, the attacker sets the `"cmake.cmakePath"` property to the path of the malicious script (e.g., `"./malicious.sh"`).
    4. Attacker distributes this malicious workspace to a victim, for example, via email, a public repository, or social engineering tactics.
    5. Victim opens the malicious workspace in VSCode with the CMake extension installed and activated.
    6. The CMake extension, upon activation or when triggered by user actions (like requesting online help or code completion), reads the `cmake.cmakePath` from the workspace settings.
    7. When the extension attempts to execute a CMake command, it uses the attacker-specified path from `cmake.cmakePath`, resulting in the execution of the malicious script.

* Impact:
    Arbitrary code execution on the victim's machine with the privileges of the VSCode process. This can allow the attacker to:
    - Steal sensitive data from the victim's file system.
    - Install malware or backdoors.
    - Modify or delete files.
    - Pivot to other systems on the network.
    - Perform any other actions that the user running VSCode is permitted to do.

* Vulnerability Rank: high

* Currently implemented mitigations:
    None. The extension directly uses the value provided in the `cmake.cmakePath` configuration setting without any validation or sanitization.

* Missing mitigations:
    - Input validation and sanitization for the `cmake.cmakePath` configuration setting. The extension should verify that the path points to a legitimate CMake executable and does not contain any potentially malicious commands or scripts.
    - Implement a warning mechanism when the `cmake.cmakePath` is modified in workspace settings. A dialog box could be displayed to the user, informing them about the change and asking for confirmation before applying the new setting.
    - Consider using a more secure method to execute CMake commands, possibly by using a sandboxed environment or by verifying the integrity of the CMake executable.

* Preconditions:
    - Victim has the "CMake for Visual Studio Code" extension installed and activated in VSCode.
    - Victim opens a malicious workspace provided by the attacker.
    - The malicious workspace contains a `.vscode/settings.json` file that sets `cmake.cmakePath` to a malicious executable.

* Source code analysis:
    1. **Configuration Loading:** The `config<T>(key: string, defaultValue?: any): T` function in `extension.ts` is responsible for retrieving configuration values. It uses `workspace.getConfiguration('cmake')` to access the CMake extension's settings.
    ```typescript
    function config<T>(key: string, defaultValue?: any): T {
        const cmake_conf = workspace.getConfiguration('cmake');
        return cmake_conf.get<T>(key, defaultValue);
    }
    ```
    2. **CMake Path Retrieval:** The `cmake = (args: string[]): Promise<string> => { ... }` function retrieves the CMake executable path using `config<string>('cmakePath', 'cmake')`.
    ```typescript
    let cmake = (args: string[]): Promise<string> => {
        return new Promise(function (resolve, reject) {
            let cmake_config = config<string>('cmakePath', 'cmake');
            // ...
        });
    }
    ```
    3. **Command Execution:** The `cmake` function then uses `child_process.spawn` to execute the CMake command. Critically, it uses the `cmake_config` value (obtained from the settings) as the executable path.
    ```typescript
    let cmake_args = commandArgs2Array(cmake_config)
    let cmd = child_process.spawn(cmake_args[0], cmake_args.slice(1, cmake_args.length)
            .concat(args.map(arg => { return arg.replace(/\r/gm, ''); })));
    ```
    - **Vulnerability Point:** The `child_process.spawn(cmake_args[0], ...)` directly uses the first element from the parsed `cmake_config` (which originates from the potentially attacker-controlled workspace settings) as the executable to run. There is no validation to ensure that `cmake_args[0]` points to a safe or expected executable. If an attacker modifies the workspace settings to set `cmake.cmakePath` to a malicious script, this script will be executed.

* Security test case:
    1. **Prepare Malicious Script:**
        - Create a file named `malicious.sh` in a temporary directory.
        - Add the following content to `malicious.sh`:
        ```bash
        #!/bin/bash
        whoami > /tmp/pwned_cmake_extension.txt
        ```
        - Make the script executable: `chmod +x malicious.sh`

    2. **Create Malicious Workspace:**
        - Create a new directory to serve as the malicious workspace, e.g., `malicious-workspace`.
        - Navigate into this directory: `cd malicious-workspace`.
        - Create a `.vscode` subdirectory: `mkdir .vscode`.
        - Create a `settings.json` file inside the `.vscode` directory: `touch .vscode/settings.json`.
        - Open `.vscode/settings.json` and add the following JSON content. Adjust the path to `malicious.sh` to be relative to the workspace root. If `malicious.sh` is in the same directory as the workspace, use `"cmake.cmakePath": "./malicious.sh"`. If it's in a parent directory, adjust accordingly (e.g., `"cmake.cmakePath": "../malicious.sh"` if `malicious.sh` is one level up). For this test case, assuming `malicious.sh` is in the same directory as `malicious-workspace`, use:
        ```json
        {
            "cmake.cmakePath": "./malicious.sh"
        }
        ```
        - Create a dummy `CMakeLists.txt` file in the `malicious-workspace` directory: `touch CMakeLists.txt`. The content of this file is not important for triggering the vulnerability.

    3. **Open Malicious Workspace in VSCode:**
        - Open Visual Studio Code.
        - Open the `malicious-workspace` directory as a workspace in VSCode (File -> Open Folder... and select `malicious-workspace`).

    4. **Trigger CMake Extension Command:**
        - In VSCode, open the command palette (Ctrl+Shift+P or Cmd+Shift+P).
        - Type and execute the command "CMake: Online Help". This command will trigger the extension to execute a CMake-related process.

    5. **Verify Malicious Script Execution:**
        - After executing the "CMake: Online Help" command, check if the file `/tmp/pwned_cmake_extension.txt` has been created.
        - If the file exists and contains the output of the `whoami` command, it confirms that the `malicious.sh` script was executed due to the manipulated `cmake.cmakePath` setting, demonstrating successful command injection.