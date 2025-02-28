## Vulnerability Report

- Vulnerability Name: Command Injection in CMake Script Debugger via `scriptPath`
- Description:
    1. An attacker can craft a malicious CMake script file and convince a victim to debug it using the CMake Tools extension's "CMake: CMake Script" debug configuration.
    2. The attacker provides a path to this malicious CMake script file, potentially hosted on a network share or disguised within a seemingly benign project.
    3. When the victim initiates a debug session using the "CMake: CMake Script" configuration and selects the attacker-provided script, the extension executes CMake with the `-P` flag, directly passing the script path.
    4. If the script path is not properly sanitized, and contains shell-escaped characters or malicious commands, these commands can be injected and executed by the system shell during the CMake script execution within the debugging context.
- Impact:
    - High: Successful exploitation allows an attacker to achieve arbitrary command execution on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data exfiltration, malware installation, or other malicious activities.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - No: The code directly uses the `scriptPath` from the debug configuration without any sanitization or validation before passing it to the `proc.execute` function in `executeScriptWithDebugger`.
    - Mitigation Location: None.
- Missing Mitigations:
    - Input Sanitization: The `scriptPath` from the debug configuration should be strictly validated and sanitized to prevent command injection. Path should be checked to ensure it's a valid CMake script path and does not contain malicious characters or shell commands.
    - Command Construction: Instead of directly passing the unsanitized `scriptPath` to `proc.execute`, the command should be constructed in a safe manner, possibly using parameterized execution or by ensuring that the script path is treated as a literal argument and not interpreted by the shell.
- Preconditions:
    - The victim must have the CMake Tools extension installed and enabled in VSCode.
    - The victim must be tricked into debugging a malicious CMake script provided by the attacker. This could be achieved through social engineering, phishing, or by hosting the malicious script on a seemingly legitimate but attacker-controlled location.
- Source Code Analysis:
    - File: `/code/src/debug/cmakeDebugger/debuggerScriptDriver.ts`
    - Function: `executeScriptWithDebugger(scriptPath: string, scriptArgs: string[], scriptEnv: Map<string, string>, debuggerInformation: DebuggerInformation)`
    ```typescript
    export async function executeScriptWithDebugger(scriptPath: string, scriptArgs: string[], scriptEnv: Map<string, string>, debuggerInformation: DebuggerInformation): Promise<void> {
        // ...
        if (cmakeProject && cmakePath) {
            const cmakeExe = await getCMakeExecutableInformation(cmakePath);
            if (cmakeExe.isDebuggerSupported) {
                const concreteArgs = ["-P", scriptPath]; // Vulnerable line - scriptPath is directly used as argument
                concreteArgs.push(...scriptArgs);
                concreteArgs.push("--debugger");
                concreteArgs.push("--debugger-pipe");
                concreteArgs.push(`${debuggerInformation.pipeName}`);
                if (debuggerInformation.dapLog) {
                    concreteArgs.push("--debugger-dap-log");
                    concreteArgs.push(debuggerInformation.dapLog);
                }

                cmakeLogger.info(localize('run.script', "Executing CMake script: \"{0}\"", scriptPath));

                const env = EnvironmentUtils.merge([process.env, EnvironmentUtils.create(scriptEnv)]);
                const child = proc.execute(cmakeExe.path, concreteArgs, outputConsumer, { environment: env}); // Execution of command with unsanitized scriptPath
                // ...
            }
        }
    }
    ```
    - The `scriptPath` variable, which is derived from `session.configuration.scriptPath`, is directly concatenated into the `concreteArgs` array without any form of sanitization.
    - This array is then passed to `proc.execute`, which executes the CMake command. If `scriptPath` contains shell metacharacters or malicious commands, these can be interpreted by the shell, leading to command injection.
- Security Test Case:
    1. **Setup**:
        - Create a malicious CMake script file named `evil_script.cmake` with the following content:
          ```cmake
          execute_process(COMMAND /bin/bash -c "touch /tmp/pwned.txt") # For Linux/macOS
          # execute_process(COMMAND cmd.exe /c "type nul > %TEMP%/pwned.txt") # For Windows - alternative test case
          message(STATUS "Script executed")
          ```
        - Host this `evil_script.cmake` file on a web server accessible to the victim, or deliver it to the victim through other means (e.g., email attachment, shared drive).
    2. **Attacker Action**:
        - Trick the victim into opening a folder in VS Code.
        - Convince the victim to use "CMake: CMake Script" debug configuration.
        - Instruct the victim to set `scriptPath` in the debug configuration to the URL or local path of the `evil_script.cmake` file (e.g., `http://attacker.com/evil_script.cmake` or `/path/to/evil_script.cmake`).
    3. **Trigger Vulnerability**:
        - The victim initiates the debug session by pressing F5 or clicking "Start Debugging".
    4. **Verify Impact (Vulnerable Version)**:
        - After the debug session starts and (presumably) fails, check if the file `/tmp/pwned.txt` (or `%TEMP%/pwned.txt` on Windows) exists on the victim's system.
        - If the file exists, it indicates successful command injection and execution, confirming the vulnerability.
    5. **Verify Mitigation (Mitigated Version)**:
        - Apply proper sanitization to the `scriptPath` in `debuggerScriptDriver.ts` to prevent command injection.
        - Repeat steps 1-3 with the same malicious `evil_script.cmake` and debug configuration.
        - Verify that the `evil_script.cmake` execution fails safely, and the file `/tmp/pwned.txt` (or `%TEMP%/pwned.txt` on Windows) is **not** created, indicating that the command injection vulnerability has been mitigated.

This vulnerability is currently not mitigated and poses a high security risk. Mitigation is needed to sanitize the `scriptPath` input to prevent command injection.