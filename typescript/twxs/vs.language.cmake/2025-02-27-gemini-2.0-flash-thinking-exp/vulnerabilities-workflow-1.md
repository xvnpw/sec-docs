Here is the combined list of vulnerabilities, formatted as markdown:

### Vulnerability: CMake Path Command Injection / Arbitrary Command Execution via Malicious Workspace Configuration

- **Vulnerability Name:** CMake Path Command Injection / Arbitrary Command Execution via Malicious Workspace Configuration / Workspace Settings Command Injection via `cmakePath`

- **Description:**
    The "CMake for Visual Studio Code" extension is vulnerable to command injection due to insecure handling of the `cmake.cmakePath` setting. This setting, configurable at the workspace or user level, specifies the path to the CMake executable. The extension retrieves this path from the configuration and uses it to execute CMake commands via Node.js's `child_process.spawn()`.  However, the extension fails to properly sanitize or validate the `cmake.cmakePath` setting.

    An attacker can exploit this by crafting a malicious workspace that includes a `.vscode/settings.json` file. Within this file, the attacker can modify the `cmake.cmakePath` setting to point to a malicious executable or inject commands into the path. When a user opens this workspace in VSCode with the CMake extension activated and triggers any CMake-related functionality (such as online help, code completion, or hover information), the extension will use the attacker-controlled path. This results in the execution of arbitrary commands on the user's system with the privileges of the VSCode process.

    Specifically, the vulnerability arises from the following steps:
    1. The extension reads the `cmake.cmakePath` from the workspace or user configuration without validation.
    2. The `commandArgs2Array` function attempts to parse the `cmake.cmakePath` string into command and arguments, but it is insufficient to prevent command injection. It splits the path by spaces and handles quoted arguments, but does not sanitize for shell metacharacters or prevent the injection of malicious commands.
    3. The `cmake` function uses `child_process.spawn` to execute the CMake command. It takes the potentially attacker-controlled path from the settings (parsed by `commandArgs2Array`) and directly uses it as the executable command, along with any provided arguments.
    4. If an attacker sets `cmake.cmakePath` to a malicious script or includes shell commands within the path (e.g., using `&&`, `;`, `|`, or backticks), these commands will be executed when the extension invokes CMake.

- **Impact:**
    Successful exploitation of this vulnerability allows for arbitrary command execution on the victim's machine. The impact is severe, as an attacker can:
    - Gain full control over the user's system with the privileges of the VSCode process.
    - Steal sensitive data from the victim's file system.
    - Install malware, backdoors, or other malicious software.
    - Modify or delete files.
    - Pivot to other systems on the network accessible from the victim's machine.
    - Exfiltrate data to external servers.
    - Compromise the confidentiality, integrity, and availability of the victim's system and data.

- **Vulnerability Rank:** Critical / High (Ranked as both critical and high in provided lists, prioritizing critical due to the severity of arbitrary command execution)

- **Currently Implemented Mitigations:**
    None. The extension directly retrieves and uses the `cmake.cmakePath` configuration value without any input validation, sanitization, or security checks. While the project uses Node’s `child_process.spawn()` with an argument array, which helps avoid basic shell interpolation issues, it does not address the core problem of using an untrusted path from the configuration. There is no whitelist or check to ensure the provided path is a legitimate CMake executable or to prevent injection of malicious commands.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement robust input validation and sanitization for the `cmake.cmakePath` configuration setting. The extension should verify that the path points to a legitimate CMake executable and does not contain any potentially malicious commands or shell metacharacters.
    - **Path Whitelisting or Verification:** Consider whitelisting known safe paths for CMake executables or implementing checks to verify that the provided path exists and is a valid executable file.
    - **Workspace Trust Policies and User Warnings:** Enforce workspace trust policies or at least warn users when a workspace configuration supplies a non-standard executable path for CMake. Display a dialog box to the user informing them about the change and asking for explicit confirmation before applying a new `cmake.cmakePath` setting, especially when it deviates from a default or known safe path.
    - **Secure Command Execution:** Harden the `child_process.spawn()` call by explicitly setting options to ensure that no shell is used (e.g., by setting `shell: false` explicitly). While using argument arrays with `spawn` is a good practice, explicitly disabling the shell can further reduce risks if combined with path validation.
    - **Restrict Path Parsing:** Instead of parsing `cmake.cmakePath` into command and arguments using `commandArgs2Array`, treat the entire setting as a single executable path. If arguments are genuinely needed, implement a more secure and robust method for parsing and validating the path and arguments, avoiding shell-based parsing and command injection vulnerabilities.
    - **Sandboxing or Integrity Verification:**  Explore using a sandboxed environment to execute CMake commands or implement mechanisms to verify the integrity of the CMake executable before execution.

- **Preconditions:**
    - The victim must have the "CMake for Visual Studio Code" extension installed and activated in VSCode.
    - The victim opens a malicious workspace provided by an attacker. This can be achieved through:
        - Opening a project repository from an untrusted source that contains a malicious `.vscode/settings.json`.
        - Receiving a specially crafted workspace via email or other means and opening it in VSCode.
        - Contributing to or cloning from a public repository that has been compromised with malicious workspace settings.
    - The malicious workspace must contain a `.vscode/settings.json` file that sets the `cmake.cmakePath` configuration to a malicious executable or command.
    - The vulnerability is triggered when the CMake extension attempts to execute a CMake command, which can be initiated by various user actions or extension features (e.g., "CMake: Online Help", code completion, hover information, or other CMake-related operations).

- **Source Code Analysis:**
    1. **Configuration Retrieval (`config` function):** The `config<T>(key: string, defaultValue?: any): T` function is used to retrieve configuration settings, including `cmake.cmakePath`.
    ```typescript
    function config<T>(key: string, defaultValue?: any): T {
        const cmake_conf = workspace.getConfiguration('cmake');
        return cmake_conf.get<T>(key, defaultValue);
    }
    ```
    This function retrieves the `cmake.cmakePath` setting from VSCode's configuration system. No validation is performed at this stage.

    2. **Path Parsing (`commandArgs2Array` function):** The `commandArgs2Array(text: string): string[]` function is intended to parse the `cmake.cmakePath` string into an array of arguments.
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
    This function splits the input string by spaces and attempts to handle quoted arguments. However, it does not sanitize or validate the input to prevent command injection. It is susceptible to exploitation if the input string contains malicious commands.

    3. **CMake Command Execution (`cmake` function):** The `cmake(args: string[]): Promise<string>` function executes the CMake command.
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
    - The function first retrieves the `cmake.cmakePath` configuration using the `config` function.
    - It then uses `commandArgs2Array` to parse the path string into an array of arguments.
    - **Vulnerable Point:** `child_process.spawn(cmake_args[0], ...)` directly uses the first element of the parsed `cmake_args` array as the executable path and the rest as arguments. Since `cmake_args` is derived from the unsanitized `cmake.cmakePath` configuration, an attacker can inject malicious commands by manipulating this setting.  The `spawn` function will execute whatever is provided in `cmake_args[0]`, leading to command injection.

- **Security Test Case:**
    1. **Prepare Malicious Script (Optional, for more complex tests):**
        - Create a file named `malicious.sh` (or similar script file depending on your OS) in a temporary directory.
        - Add malicious commands to the script, for example:
        ```bash
        #!/bin/bash
        echo "PWNED!"
        touch /tmp/cmake_extension_pwned.txt
        whoami > /tmp/cmake_extension_whoami.txt
        ```
        - Make the script executable: `chmod +x malicious.sh`

    2. **Create Malicious Workspace:**
        - Create a new directory, e.g., `cmake-injection-test-workspace`.
        - Navigate into this directory: `cd cmake-injection-test-workspace`.
        - Create a `.vscode` subdirectory: `mkdir .vscode`.
        - Create a `settings.json` file inside the `.vscode` directory: `touch .vscode/settings.json`.
        - Open `.vscode/settings.json` and add the malicious configuration.
            - **Test Case 1 (Direct command injection):**
            ```json
            {
                "cmake.cmakePath": "cmake && touch /tmp/cmake_pwned_direct && echo"
            }
            ```
            - **Test Case 2 (Using malicious script, adjust path to `malicious.sh` accordingly):** Assuming `malicious.sh` is in the workspace root:
            ```json
            {
                "cmake.cmakePath": "./malicious.sh"
            }
            ```
            - **Test Case 3 (Using shell command execution with `/bin/sh -c`):**
            ```json
            {
                "cmake.cmakePath": "/bin/sh -c 'echo PWNED_VIA_SH && touch /tmp/cmake_pwned_sh'"
            }
            ```
        - Create a dummy `CMakeLists.txt` file in the workspace root: `touch CMakeLists.txt`.

    3. **Open Malicious Workspace in VSCode:**
        - Open Visual Studio Code.
        - Open the `cmake-injection-test-workspace` directory as a workspace (File -> Open Folder...).

    4. **Trigger CMake Extension Command:**
        - Open the Command Palette (Ctrl+Shift+P or Cmd+Shift+P).
        - Execute any CMake extension command that triggers CMake execution, for example: "CMake: Online Help".

    5. **Verify Command Execution:**
        - **For Test Case 1:** Check if the file `/tmp/cmake_pwned_direct` has been created. If it exists, command injection is confirmed.
        - **For Test Case 2:** Check if `/tmp/cmake_extension_pwned.txt` and `/tmp/cmake_extension_whoami.txt` have been created and contain the expected output ("PWNED!" in console, and username in `whoami` output file respectively).
        - **For Test Case 3:** Check if `/tmp/cmake_pwned_sh` has been created. If it exists, command injection via shell execution is confirmed. Also, check for "PWNED_VIA_SH" output (it might be in extension logs or developer console if captured).

    By successfully executing these test cases and observing the creation of the expected files or other side effects, you can confirm the CMake Path Command Injection vulnerability. Remember to clean up any test files created in `/tmp` after testing.