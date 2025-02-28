## Combined Vulnerability List

### Command Injection in Terminal Launch (Linux/macOS)

- **Vulnerability Name:** Command Injection in Terminal Launch (Linux/macOS)
- **Description:**
    1. The VS Code PHP Debug extension uses shell commands to launch PHP scripts in external terminals on Linux and macOS. This occurs when using debug configurations like "Launch currently open script" or "Launch Built-in web server".
    2. When launching scripts in a terminal on Linux and macOS, the extension utilizes `bash -c` and `osascript` respectively.
    3. The arguments provided in the `launch.json` configuration, specifically `runtimeArgs` and `args`, along with the program path, are passed to these shell commands without proper sanitization or escaping.
    4. The command to be executed in the terminal is constructed by joining user-provided arguments from the debug configuration (such as `runtimeArgs`, `program`, and `args`) with spaces or within shell command structures.
    5. A malicious user could craft a `launch.json` configuration with specially crafted arguments containing shell metacharacters (e.g., `;`, `|`, `&&`, `||`, `$()`, backticks, quotes, spaces, etc.).
    6. When the extension executes these commands, the shell interprets the metacharacters, allowing the attacker to inject and execute arbitrary commands on the user's system in addition to the intended PHP script execution.

- **Impact:**
    - Remote Code Execution (RCE). An attacker who can influence the `launch.json` configuration can execute arbitrary commands with the privileges of the user running VS Code. This can lead to full system compromise, data theft, malware installation, or other malicious activities.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The code directly passes arguments to shell commands in `LinuxTerminalService` and `MacTerminalService` without any escaping or sanitization. The arguments from `launch.json` are incorporated into shell commands using string concatenation and array joining, making it vulnerable to injection.

- **Missing Mitigations:**
    - **Proper Argument Escaping:** Arguments passed to `CP.spawn` in `LinuxTerminalService` and `MacTerminalService` should be properly escaped to prevent shell injection. Use shell-escape libraries or built-in Node.js functionalities to sanitize arguments before executing shell commands. Parameterized commands or libraries designed for shell argument escaping should be used to ensure that user-provided input is treated as data, not code.
    - **Input Validation:** Implement validation on the `runtimeArgs` and `args` in `launch.json` to restrict characters or patterns that could be used for command injection. While escaping is the primary mitigation, input validation can act as a defense-in-depth measure.
    - **Using Array Format for `CP.spawn`:** Instead of constructing a shell command string, utilize the array format for the `command` and `args` parameters in `CP.spawn`. This can prevent shell interpretation of metacharacters if done correctly, by directly passing arguments without involving a shell interpreter like `bash -c`.

- **Preconditions:**
    - The attacker must be able to influence the `launch.json` configuration used for debugging. This could be achieved by:
        - Compromising a workspace and modifying the `.vscode/launch.json` file.
        - Convincing a user to open a project with a malicious `launch.json` configuration (e.g., through a seemingly harmless repository).
        - Social engineering the user to manually modify their `launch.json` file.
    - The target machine must be running Linux or macOS for the vulnerable code paths in `LinuxTerminalService` and `MacTerminalService` to be executed.
    - The user must use a debug configuration that launches scripts in an external terminal, such as "Launch currently open script" or "Launch Built-in web server".

- **Source Code Analysis:**
    1. **File:** `/code/src/terminal.ts`
    2. **Functions:** `LinuxTerminalService.launchInTerminal` and `MacTerminalService.launchInTerminal`
    3. **Vulnerable Code Snippet (LinuxTerminalService):**
        ```typescript
        const bashCommand = `cd "${dir}"; "${args.join('" "')}"; echo; read -p "${
            LinuxTerminalService.WAIT_MESSAGE
        }" -n1;`

        const termArgs = [
            '--title',
            `"${LinuxTerminalService.TERMINAL_TITLE}"`,
            '-x',
            'bash',
            '-c',
            `''${bashCommand}''`, // wrapping argument in two sets of ' because node is so "friendly" that it removes one set...
        ]

        CP.spawn(LinuxTerminalService.LINUX_TERM, termArgs, options)
        ```
        - **Explanation:** The `bashCommand` is constructed by concatenating `"cd "`, the directory `dir`, and joining the `args` array with `'" "'`. The `args` array comes directly from the `launch.json` configuration. This concatenated string is then passed as an argument to `bash -c`.  If `args` contains shell metacharacters, `bash -c` will interpret them, leading to command injection. The use of `args.join('" "')` attempts to quote arguments, but it is insufficient for robust shell escaping and can be bypassed.

    4. **Vulnerable Code Snippet (MacTerminalService):**
        ```typescript
        const osaArgs = [
            Path.join(__dirname, './TerminalHelper.scpt'),
            '-t',
            MacTerminalService.TERMINAL_TITLE,
            '-w',
            dir,
        ]

        for (const a of args) {
            osaArgs.push('-pa')
            osaArgs.push(a)
        }

        CP.spawn(MacTerminalService.OSASCRIPT, osaArgs)
        ```
        - **Explanation:** In `MacTerminalService`, arguments are appended to the `osaArgs` array in a loop. While this approach of pushing arguments into an array is generally safer than string concatenation, the vulnerability lies in how `osascript` and `TerminalHelper.scpt` handle these arguments. If `TerminalHelper.scpt` (or `osascript` itself) does not properly sanitize or handle the arguments passed via `-pa`, command injection vulnerabilities can still arise. Further analysis of `TerminalHelper.scpt` would be needed to confirm the exact injection vector in macOS, but the principle of unsanitized user-controlled input leading to shell command execution remains.

    5. **Visualization:**
       ```
       launch.json (runtimeArgs/args) --> terminal.ts (LinuxTerminalService/MacTerminalService.launchInTerminal) --> CP.spawn (with vulnerable command construction) --> Shell Command Execution
       ```

- **Security Test Case:**
    1. **Create a PHP file:** Create a PHP file named `test.php` with the following content in your project directory:
       ```php
       <?php
       echo "Test PHP script";
       ?>
       ```
    2. **Modify `launch.json` for Command Injection (runtimeArgs):** Open VS Code and create or modify the debug configuration (launch.json) for PHP "Launch currently open script" to include a malicious command in `runtimeArgs`:
       ```json
       {
           "version": "0.2.0",
           "configurations": [
               {
                   "type": "php",
                   "request": "launch",
                   "name": "Launch Script with Injection (runtimeArgs)",
                   "program": "${file}",
                   "runtimeArgs": [
                       "-dxdebug.start_with_request=yes",
                       "; touch /tmp/pwned_runtime_args"
                   ],
                   "cwd": "${fileDirname}",
                   "port": 9003,
                   "externalConsole": true
               }
           ]
       }
       ```
    3. **Modify `launch.json` for Command Injection (args):** Create another debug configuration in `launch.json` for PHP "Launch currently open script" to include a malicious command in `args`:
       ```json
       {
           "version": "0.2.0",
           "configurations": [
               {
                   "type": "php",
                   "request": "launch",
                   "name": "Launch Script with Injection (args)",
                   "program": "${file}",
                   "args": [
                       "test",
                       "argument",
                       "$(touch /tmp/pwned_args)"
                   ],
                   "cwd": "${fileDirname}",
                   "externalConsole": true
               }
           ]
       }
       ```
    4. **Save `launch.json` and open `test.php`** in the editor.
    5. **Start debugging using "Launch Script with Injection (runtimeArgs)" configuration.**
    6. **After debugging session starts and terminates**, execute the following command in the terminal to check if the malicious command from `runtimeArgs` was executed:
       ```bash
       ls -l /tmp/pwned_runtime_args
       ```
    7. **Start debugging using "Launch Script with Injection (args)" configuration.**
    8. **After debugging session starts and terminates**, execute the following command in the terminal to check if the malicious command from `args` was executed:
       ```bash
       ls -l /tmp/pwned_args
       ```
    9. **Verification:** If the files `/tmp/pwned_runtime_args` and/or `/tmp/pwned_args` exist, it confirms that the command injection vulnerability is present via `runtimeArgs` and/or `args` respectively.


### Command Injection in `terminateProcess.sh` via Process ID

- **Vulnerability Name:** Command Injection in `terminateProcess.sh` via Process ID
- **Description:**
    The `terminateProcess.sh` script is used to terminate a process tree based on a given process ID (PID). The script is executed to kill debug processes when a debug session ends. The script directly uses the provided PID in shell commands (`pgrep -P $1`, `kill -9 $1`) without proper sanitization. If an attacker could somehow influence the PID argument passed to this script, they might be able to inject arbitrary shell commands. While direct external control over the PID is unlikely in typical VSCode extension usage, any indirect influence that bypasses expected validation could lead to command injection.

- **Impact:** Successful command injection allows an attacker to execute arbitrary commands with the privileges of the user running VSCode. This could lead to data exfiltration, system compromise, or other malicious activities, potentially triggered when a user stops a debug session.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:** None in `terminateProcess.sh` itself. The calling code in `terminal.ts` passes `pid.toString()` as an argument, which mitigates simple direct injection but might not be sufficient against advanced techniques if the `pid` source is compromised or if complex injection payloads are used.

- **Missing Mitigations:**
    - **Input validation and sanitization in `terminateProcess.sh`:**  Ensure that the input PID is strictly a numerical process ID and does not contain any shell metacharacters or commands.  Validate the input `$1` to confirm it's an integer before using it in `pgrep` and `kill`.
    - **Stronger validation of the process ID in `terminal.ts`:** Before calling `terminateProcess.sh` in `terminal.ts`, rigorously validate the process ID to ensure it originates from a trusted source and context. Consider verifying the process ownership or lineage if possible.

- **Preconditions:**
    - An attacker needs to find a way to influence the `processId` argument passed to `Terminal.killTree` in `terminal.ts`. This might involve exploiting other vulnerabilities or weaknesses in VSCode or the extension's interaction with the operating system to manipulate process IDs.  While directly influencing the PID from outside is hard, a vulnerability in how PIDs are managed or retrieved within the extension could be exploited.
    - The target system must be running a Unix-like operating system where `terminateProcess.sh` is executed.

- **Source Code Analysis:**
    ```bash
    #!/bin/bash

    terminateTree() {
        for cpid in $(pgrep -P $1); do # Line A: Vulnerable command
            terminateTree $cpid
        done
        kill -9 $1 > /dev/null 2>&1 # Line B: Vulnerable command
    }

    for pid in $*; do # Line C: Input from command line arguments
        terminateTree $pid
    done
    ```
    - **Line C:** The script iterates through all command-line arguments `$*` and assigns each to the `pid` variable. This is where the PID is taken as input.
    - **Line A and B:** Inside the `terminateTree` function, the `$1` parameter (which corresponds to `pid` from the loop in Line C) is used directly in `pgrep -P $1` and `kill -9 $1`.  The lack of quoting or sanitization around `$1` in these commands is the core vulnerability.
    - **Vulnerability Explanation:** If an attacker can inject a malicious string as part of the process ID argument, they could potentially break out of the intended command and execute arbitrary commands. For example, if a PID is crafted as `123; malicious_command`, the shell might interpret `;` as a command separator, leading to the execution of `malicious_command`.

    ```typescript
    // File: /code/src/terminal.ts
    class DefaultTerminalService implements ITerminalService {
        public killTree(pid: number): Promise<any> {
            return new Promise<any | void>((resolve, reject) => {
                try {
                    const cmd = Path.join(__dirname, './terminateProcess.sh')
                    const result = CP.spawnSync(cmd, [pid.toString()]) // Line D: Calling terminateProcess.sh with pid
                    if (result.error) {
                        reject(result.error)
                    } else {
                        resolve(undefined)
                    }
                } catch (err) {
                    reject(err)
                }
            })
        }
    }
    ```
    - **Line D:** The `killTree` function in `DefaultTerminalService` calls `terminateProcess.sh` using `CP.spawnSync` and passes `pid.toString()` as an argument. While `pid.toString()` itself is unlikely to be directly injectable from `launch.json`, the script `terminateProcess.sh` is vulnerable if it receives a crafted PID. The vulnerability lies in the shell script itself, not directly in how the PID is passed from TypeScript code, but rather in the script's insecure handling of its input.

- **Security Test Case:**
    1. **Modify `terminal.ts` to inject payload:**  Modify the `DefaultTerminalService.killTree` function in `/code/src/terminal.ts` temporarily to pass a malicious payload as the PID argument to `terminateProcess.sh`.  This simulates a scenario where a crafted PID is somehow provided to the `killTree` function. For example, change line `const result = CP.spawnSync(cmd, [pid.toString()]);` to `const result = CP.spawnSync(cmd, ["123; touch /tmp/pwned_terminate_process"]);`. **(Note: This is for testing purposes only and should be reverted after testing.)**
    2. **Trigger `killTree` function:** Run a debug session in VSCode that would trigger the `killTree` function. A simple way to do this is to start any debug session that uses a terminal (e.g., "Launch currently open script") and then stop the debug session. Stopping the debug session should call `killTree` to terminate the debug process.
    3. **Check for file creation:** After the debug session is stopped, check if the file `/tmp/pwned_terminate_process` exists.
    4. **Verification:** If `/tmp/pwned_terminate_process` exists, it confirms that the command injection in `terminateProcess.sh` was successful, demonstrating the vulnerability.  This test proves that if a malicious payload were to reach `terminateProcess.sh` as a PID argument, it would be executed.