- Vulnerability Name: Command Injection in Terminal Launch on Linux/macOS
- Description:
    1. The VSCode PHP Debug extension allows users to launch PHP scripts in an external terminal on Linux and macOS systems using the "Launch currently open script" or "Launch Built-in web server" configurations.
    2. When launching scripts in a terminal on Linux and macOS, the extension utilizes `bash -c` and `osascript` respectively.
    3. The command to be executed in the terminal is constructed by joining user-provided arguments from the debug configuration (such as `runtimeArgs`, `program`, and `args`) with spaces.
    4. If a malicious user crafts a `launch.json` configuration containing shell metacharacters (e.g., backticks, semicolons, command substitution) within these arguments, it can lead to command injection.
    5. When the extension executes this command, the shell interprets the metacharacters, allowing the attacker to execute arbitrary commands on the user's machine in addition to the intended PHP script.
- Impact:
    - Arbitrary command execution on the machine running VS Code with the privileges of the VS Code user.
    - An attacker could potentially gain unauthorized access to sensitive data, modify system configurations, install malware, or perform other malicious actions.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    - None. The current implementation directly passes user-controlled arguments to the shell without proper sanitization or escaping within `LinuxTerminalService.ts` and `MacTerminalService.ts`.
- Missing Mitigations:
    - Input sanitization or escaping of arguments before passing them to `bash -c` in `LinuxTerminalService.ts` and `osascript` in `MacTerminalService.ts`.
    - Ideally, the extension should utilize `child_process.spawn` with the command and arguments provided as separate array elements to avoid shell interpretation of metacharacters.
- Preconditions:
    - The target machine must be running Linux or macOS.
    - The user must have the VSCode PHP Debug extension installed and be using a debug configuration that launches scripts in an external terminal, such as "Launch currently open script" or "Launch Built-in web server".
    - An attacker needs to control the arguments passed to the PHP script or runtime. This can be achieved by:
        - Convincing a user to open and debug a project containing a malicious `launch.json` configuration.
        - Social engineering the user to modify their `launch.json` to include malicious arguments.
- Source Code Analysis:
    1. File: `/code/src/terminal.ts`
    2. Function: `LinuxTerminalService.launchInTerminal`
    3. Vulnerable code snippet:
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

    const cmd = CP.spawn(LinuxTerminalService.LINUX_TERM, termArgs, options)
    ```
    4. The `bashCommand` is constructed by joining the `args` array with `" "`. The `args` array originates from the `launch.json` configuration, which is user-controlled.
    5. When `CP.spawn` executes `bash -c ''${bashCommand}''`, the shell interprets the metacharacters within `bashCommand`, leading to command injection if malicious arguments are present in `args`.
    6. A similar vulnerability might exist in `MacTerminalService.launchInTerminal` where arguments are passed to `osascript`. While not analyzed in depth here, it's worth further investigation.
- Security Test Case:
    1. Create a PHP file named `test.php` with the following content:
    ```php
    <?php
    echo "Hello World\n";
    ?>
    ```
    2. Create a `launch.json` file in the `.vscode` folder of your project with the following configuration:
    ```json
    {
      "version": "0.2.0",
      "configurations": [
        {
          "type": "php",
          "request": "launch",
          "name": "Launch currently open script - Command Injection Test",
          "program": "${file}",
          "cwd": "${fileDirname}",
          "runtimeArgs": ["-r", "'echo vulnerable';", "`touch /tmp/pwned`"],
          "externalConsole": true
        }
      ]
    }
    ```
    3. Open the `test.php` file in VS Code.
    4. Start debugging using the "Launch currently open script - Command Injection Test" configuration.
    5. Observe that a new terminal window opens and the script executes.
    6. After the debug session ends, check if the file `/tmp/pwned` exists on your system.
    7. If the file `/tmp/pwned` exists, it confirms that the command injection vulnerability is present, as the `touch /tmp/pwned` command was executed by the shell.