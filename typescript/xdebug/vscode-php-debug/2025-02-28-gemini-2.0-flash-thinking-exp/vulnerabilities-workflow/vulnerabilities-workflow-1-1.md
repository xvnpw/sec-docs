### Vulnerability List

- Vulnerability Name: Command Injection in Terminal Launch (Linux/macOS)
- Description:
    1. The VS Code PHP Debug extension uses shell commands to launch PHP scripts in external terminals on Linux and macOS.
    2. The arguments provided in the `launch.json` configuration, specifically `runtimeArgs` and `args`, are passed to these shell commands without proper sanitization or escaping.
    3. A malicious user could craft a `launch.json` configuration with specially crafted arguments containing shell metacharacters.
    4. When the extension executes these commands, the shell metacharacters are interpreted, allowing the attacker to inject and execute arbitrary commands on the user's system.
- Impact:
    - Remote Code Execution (RCE). An attacker who can influence the `launch.json` configuration (e.g., through a compromised workspace or project settings) can execute arbitrary commands with the privileges of the user running VS Code. This can lead to full system compromise, data theft, or other malicious activities.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly passes arguments to shell commands without any escaping or sanitization.
- Missing Mitigations:
    - **Proper Argument Escaping:** Arguments passed to `CP.spawn` in `LinuxTerminalService` and `MacTerminalService` should be properly escaped to prevent shell injection. Use shell-escape libraries or built-in Node.js functionalities to sanitize arguments before executing shell commands. For example, use parameterized commands or libraries designed for shell argument escaping to ensure that user-provided input is treated as data, not code.
    - **Input Validation:** Implement validation on the `runtimeArgs` and `args` in `launch.json` to restrict characters or patterns that could be used for command injection. While escaping is the primary mitigation, input validation can act as a defense-in-depth measure.
- Preconditions:
    - The attacker must be able to influence the `launch.json` configuration used for debugging. This could be achieved by:
        - Compromising a workspace and modifying the `.vscode/launch.json` file.
        - Convincing a user to open a project with a malicious `launch.json` configuration.
- Source Code Analysis:
    1. File: `/code/src/terminal.ts`
    2. Function: `LinuxTerminalService.launchInTerminal` and `MacTerminalService.launchInTerminal`
    3. Vulnerable Code Snippet (LinuxTerminalService):
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
    4. Vulnerable Code Snippet (MacTerminalService):
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
    5. Visualization:
       ```
       launch.json (runtimeArgs/args) --> terminal.ts (LinuxTerminalService/MacTerminalService.launchInTerminal) --> CP.spawn (without escaping) --> Shell Command Execution
       ```
    6. Explanation: The `args.join('" "')` in `LinuxTerminalService` and the loop pushing arguments in `MacTerminalService` do not properly escape shell-sensitive characters. If an attacker injects characters like `;`, `|`, `&&`, `||`, `$()`, backticks, etc., they can break out of the intended command structure and execute arbitrary commands.

- Security Test Case:
    1. Create a PHP file named `test.php` with the following content:
       ```php
       <?php
       echo "Test PHP script";
       ?>
       ```
    2. Open VS Code and create a new debug configuration (launch.json) for PHP "Launch currently open script" and modify it to include a malicious command in `runtimeArgs`:
       ```json
       {
           "version": "0.2.0",
           "configurations": [
               {
                   "type": "php",
                   "request": "launch",
                   "name": "Launch Script with Injection",
                   "program": "${file}",
                   "runtimeArgs": [
                       "-dxdebug.start_with_request=yes",
                       "; touch /tmp/pwned_by_vscode_php_debug"
                   ],
                   "cwd": "${fileDirname}",
                   "port": 9003
               }
           ]
       }
       ```
    3. Save `launch.json` and open `test.php` in the editor.
    4. Start debugging using the "Launch Script with Injection" configuration.
    5. After debugging session starts and terminates, execute the following command in the terminal to check if the malicious command was executed:
       ```bash
       ls -l /tmp/pwned_by_vscode_php_debug
       ```
    6. If the file `/tmp/pwned_by_vscode_php_debug` exists, it confirms that the command injection vulnerability is present.