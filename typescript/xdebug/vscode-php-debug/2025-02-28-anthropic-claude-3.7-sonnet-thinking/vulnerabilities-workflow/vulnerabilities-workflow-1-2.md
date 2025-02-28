# Vulnerability List

- **Vulnerability Name:** Insecure Command Construction in Terminal Launch (Windows/Linux)
  - **Description:**
    The extension's terminal–launching functions in both the Windows and Linux code paths build a shell command by concatenating an array of runtime arguments (supplied via the debug configuration) into a single command string without rigorous sanitization. An attacker who supplies a manipulated repository (for example, one with a malicious `launch.json` that contains specially crafted `runtimeArgs`) can inject additional shell commands. The attack proceeds as follows:
    
    1. The attacker prepares a repository in which the debug configuration (launch.json) includes a malicious entry in the `runtimeArgs` array. For instance, on Windows the payload might be:
       ```json
       [
         "-dxdebug.start_with_request=yes",
         "innocent_arg\"; cmd.exe /c calc.exe; \""
       ]
       ```
       (On Linux a similar payload could be used, such as substituting `calc.exe` with a benign command like `gnome-calculator` or a harmless command that writes to a file.)
    
    2. When a victim opens this repository in VS Code, the extension's configuration provider reads the debug configuration without validating the runtime arguments.
    
    3. In the Windows implementation (in `src/terminal.ts`), the code concatenates the array as follows:
       ```js
       const command = `""${args.join('" "')}" & pause"`
       ```
       In the Linux version, the command is formed with:
       ```js
       const bashCommand = `cd "${dir}"; "${args.join('" "')}"; echo; read -p "${LinuxTerminalService.WAIT_MESSAGE}" -n1;`
       ```
       Because no additional sanitization is applied, any special characters (for example an embedded `";` sequence) can break out of the quoted context.
    
    4. The resulting command string—including any injected commands—is then passed to the system shell (via `cmd.exe` on Windows or Bash on Linux) through a call to `child_process.spawn`. Flags such as `windowsVerbatimArguments` (on Windows) do not mitigate the risk of command injection.
    
    5. As a result, the injected payload executes additional (malicious) command(s) with the privileges of the user running VS Code.
  
  - **Impact:**
    Exploitation of this vulnerability results in remote code execution (RCE). An attacker can run arbitrary system commands on the victim's machine, potentially gaining complete control over the system and leading to data and persistent compromise of the host environment.
  
  - **Vulnerability Rank:** Critical
  
  - **Currently Implemented Mitigations:**
    - The code performs only a basic join of the runtime arguments (using `args.join('" "')`) with an assumption that configuration values are trusted.
    - There is an inherent trust placed on configuration data from the repository, although in the real world an attacker can supply a manipulated repository.
  
  - **Missing Mitigations:**
    - **Proper Input Validation and Escaping:** The extension should rigorously sanitize user–supplied arguments (for example, by whitelisting acceptable characters) or use APIs that avoid passing concatenated strings to a shell.
    - **Avoid Shell-Based Concatenation:** Rather than forming a single command string subject to shell parsing, the extension should pass the command and its arguments directly (using the non–shell form of spawn or properly escaped arguments) to avoid unintended command execution.
    - **Strict Trust Boundaries:** Since repository configuration (such as launch configurations) can be attacker–controlled, incoming values must be validated against a secure schema rather than assumed safe.
  
  - **Preconditions:**
    - The victim is using the extension with external console launching enabled (on either Windows or Linux).
    - The attacker is able to supply or manipulate a repository that contains a malicious launch configuration (for example, via a compromised or unsuspecting repository).
    - The manipulated configuration supplies a value in `runtimeArgs` (or another parameter subsequently used in terminal command construction) that includes shell metacharacters.
  
  - **Source Code Analysis:**
    - **Windows Case (in `src/terminal.ts` – WindowsTerminalService.launchInTerminal):**
      - The code sets a window title and constructs a command string:
        ```js
        const title = `"${dir} - ${WindowsTerminalService.TERMINAL_TITLE}"`
        const command = `""${args.join('" "')}" & pause"`
        ```
      - This `command` is then included in the command array:
        ```js
        const cmdArgs = ['/c', 'start', title, '/wait', 'cmd.exe', '/c', command]
        ```
      - Because special characters (like `";` or `&`) within the user–supplied `args` are not neutralized, an attacker–controlled argument can break out of the intended command context.
    
    - **Linux Case (in `src/terminal.ts` – LinuxTerminalService.launchInTerminal):**
      - A bash command is constructed by concatenating the user–supplied arguments:
        ```js
        const bashCommand = `cd "${dir}"; "${args.join('" "')}"; echo; read -p "${LinuxTerminalService.WAIT_MESSAGE}" -n1;`
        ```
      - As in the Windows case, if any element within `args` contains shell metacharacters, it can alter the command line to execute unintended shell commands.
    
    - **Overall Observation:**
      - Both OS-specific implementations rely on unsanitized concatenation of runtime arguments into a shell command string. This method creates an exploitable vector for command injection since no additional escaping or safe API usage is applied.
  
  - **Security Test Case:**
    1. **Setup:**
       - Create a malicious `launch.json` in a test repository with a debug configuration that includes a payload in `runtimeArgs`. For example, on Windows:
         ```json
         {
           "version": "0.2.0",
           "configurations": [
             {
               "name": "Malicious Debug",
               "type": "php",
               "request": "launch",
               "program": "test.php",
               "cwd": "${workspaceFolder}",
               "runtimeArgs": [
                 "-dxdebug.start_with_request=yes",
                 "safeArg\"; cmd.exe /c calc.exe; \""
               ],
               "externalConsole": true
             }
           ]
         }
         ```
         (On Linux, you may substitute `calc.exe` with a benign command such as `gnome-calculator` or any harmless command that writes to a file.)
       
    2. **Execution:**
       - Open the repository in VS Code with the PHP Debug Adapter extension installed.
       - Start debugging using the "Malicious Debug" configuration.
       
    3. **Observation:**
       - On Windows, an external console is launched. The injected payload causes the command string to include an extra `cmd.exe /c calc.exe` command (or its Linux equivalent), triggering execution of the Calculator (or corresponding benign program).
       
    4. **Verification:**
       - Document the command–injected behavior (e.g., via screenshots or logged output from the external console) to demonstrate that arbitrary commands are executed.
       
    5. **Cleanup:**
       - Remove or fix the malicious configuration after testing.