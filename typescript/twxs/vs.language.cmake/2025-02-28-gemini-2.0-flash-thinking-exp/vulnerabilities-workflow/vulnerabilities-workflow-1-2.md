### Vulnerability List

- Vulnerability Name: Command Injection via `cmake.cmakePath` setting
- Description:
    1. The VSCode CMake extension allows users to configure the path to the CMake executable using the `cmake.cmakePath` setting.
    2. This setting can be configured in user preferences or workspace settings.
    3. The extension uses `child_process.spawn` to execute the CMake command, using the path specified in `cmake.cmakePath`.
    4. The `commandArgs2Array` function parses the `cmake.cmakePath` string into an array of arguments, splitting by spaces and respecting double quotes.
    5. However, this parsing is insufficient to prevent command injection. If a user sets `cmake.cmakePath` to a string containing command separators (like `&&`, `;`, `||`) followed by malicious commands, these commands will be executed by `child_process.spawn`.
    6. For example, setting `cmake.cmakePath` to `"cmake && touch /tmp/pwned"` will execute `cmake` and then execute `touch /tmp/pwned`.
- Impact: Arbitrary code execution on the user's machine with the privileges of the VSCode process. This can lead to data theft, installation of malware, or complete system compromise.
- Vulnerability Rank: Critical
- Currently implemented mitigations: None. The extension directly uses the user-provided `cmake.cmakePath` setting to execute commands without sanitization.
- Missing mitigations:
    - Sanitize or validate the `cmake.cmakePath` setting to prevent command injection.
    - Instead of parsing `cmake.cmakePath` into arguments, directly use it as the executable path in `child_process.spawn` and provide CMake arguments separately. This would prevent the interpretation of command separators within the path.
    - Display a warning to the user if `cmake.cmakePath` contains suspicious characters or command separators.
- Preconditions:
    - An attacker needs to convince a user to either:
        - Manually set the `cmake.cmakePath` setting to a malicious value in their user or workspace settings.
        - Open a workspace that contains a malicious `settings.json` file in the `.vscode` folder, which sets `cmake.cmakePath` to a malicious value.
- Source code analysis:
    1. In `extension.ts`, the `cmake` function is defined to execute CMake commands:
    ```typescript
    let cmake = (args: string[]): Promise<string> => {
        return new Promise(function (resolve, reject) {
            let cmake_config = config<string>('cmakePath', 'cmake'); // Reads cmake.cmakePath setting
            let cmake_args = commandArgs2Array(cmake_config) // Parses cmake.cmakePath into arguments
            let cmd = child_process.spawn(cmake_args[0], cmake_args.slice(1, cmake_args.length) // Executes command
                    .concat(args.map(arg => { return arg.replace(/\r/gm, ''); })));
            ...
        });
    }
    ```
    2. The `config<string>('cmakePath', 'cmake')` function retrieves the value of the `cmake.cmakePath` setting.
    3. The `commandArgs2Array(cmake_config)` function parses this string into an array of arguments. For example, if `cmake_config` is `"cmake && malicious"`, `cmake_args` will be `["cmake && malicious"]`.
    4. `child_process.spawn(cmake_args[0], ...)` then executes the first element of `cmake_args` as a command. In our example, it tries to execute `"cmake && malicious"` as a command, leading to command injection.

- Security test case:
    1. Create a malicious workspace:
        a. Create a folder named `cmake-injection-test`.
        b. Inside `cmake-injection-test`, create a folder named `.vscode`.
        c. Inside `.vscode`, create a file named `settings.json` with the following content:
        ```json
        {
            "cmake.cmakePath": "cmake && touch /tmp/cmake-extension-pwned"
        }
        ```
        d. Create an empty file named `CMakeLists.txt` in `cmake-injection-test`.
    2. Open VSCode.
    3. Open the `cmake-injection-test` folder as a workspace in VSCode.
    4. Open the `CMakeLists.txt` file in the opened workspace. This action should trigger the CMake extension to become active and potentially execute CMake commands.
    5. After a short delay (to allow the extension to initialize and potentially execute cmake), check if the file `/tmp/cmake-extension-pwned` has been created.
    6. If the file `/tmp/cmake-extension-pwned` exists, the command injection vulnerability is confirmed. This indicates that the malicious command part of `cmake.cmakePath` setting was executed.