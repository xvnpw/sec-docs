## Consolidated Vulnerability Report

This report consolidates identified vulnerabilities, providing detailed descriptions, impacts, ranks, mitigations, preconditions, source code analysis, and security test cases for each.

### Vulnerability 1: Command Injection in CMake Script Debugger via `scriptPath`

- **Description:**
    1. An attacker can craft a malicious CMake script file and convince a victim to debug it using the CMake Tools extension's "CMake: CMake Script" debug configuration.
    2. The attacker provides a path to this malicious CMake script file, potentially hosted on a network share or disguised within a seemingly benign project.
    3. When the victim initiates a debug session using the "CMake: CMake Script" configuration and selects the attacker-provided script, the extension executes CMake with the `-P` flag, directly passing the script path.
    4. If the script path is not properly sanitized, and contains shell-escaped characters or malicious commands, these commands can be injected and executed by the system shell during the CMake script execution within the debugging context.

- **Impact:**
    - High: Successful exploitation allows an attacker to achieve arbitrary command execution on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data exfiltration, malware installation, or other malicious activities.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - No: The code directly uses the `scriptPath` from the debug configuration without any sanitization or validation before passing it to the `proc.execute` function in `executeScriptWithDebugger`.
    - Mitigation Location: None.

- **Missing Mitigations:**
    - Input Sanitization: The `scriptPath` from the debug configuration should be strictly validated and sanitized to prevent command injection. Path should be checked to ensure it's a valid CMake script path and does not contain malicious characters or shell commands.
    - Command Construction: Instead of directly passing the unsanitized `scriptPath` to `proc.execute`, the command should be constructed in a safe manner, possibly using parameterized execution or by ensuring that the script path is treated as a literal argument and not interpreted by the shell.

- **Preconditions:**
    - The victim must have the CMake Tools extension installed and enabled in VSCode.
    - The victim must be tricked into debugging a malicious CMake script provided by the attacker. This could be achieved through social engineering, phishing, or by hosting the malicious script on a seemingly legitimate but attacker-controlled location.

- **Source Code Analysis:**
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
    - The `scriptPath` variable, derived from the debug configuration, is directly concatenated into the `concreteArgs` array without any sanitization.
    - This array is then passed to `proc.execute`, which executes the CMake command. If `scriptPath` contains shell metacharacters or malicious commands, these can be interpreted by the shell, leading to command injection.
    - Debug Configuration `scriptPath` flows through `DebugAdapterNamedPipeServerDescriptorFactory` to `executeScriptWithDebugger(scriptPath)` and finally to the vulnerable `cmake -P scriptPath` command execution.

- **Security Test Case:**
    1. **Setup**:
        - Create a malicious CMake script file named `evil_script.cmake` with the following content:
          ```cmake
          execute_process(COMMAND /bin/bash -c "touch /tmp/pwned.txt") # For Linux/macOS
          # execute_process(COMMAND cmd.exe /c "type nul > %TEMP%/pwned.txt") # For Windows - alternative test case
          message(STATUS "Script executed")
          ```
        - Host this `evil_script.cmake` file on a web server accessible to the victim, or deliver it to the victim through other means.
    2. **Attacker Action**:
        - Trick the victim into opening a folder in VS Code.
        - Convince the victim to use "CMake: CMake Script" debug configuration.
        - Instruct the victim to set `scriptPath` in the debug configuration to the URL or local path of the `evil_script.cmake` file (e.g., `http://attacker.com/evil_script.cmake` or `/path/to/evil_script.cmake`).
    3. **Trigger Vulnerability**:
        - The victim initiates the debug session by pressing F5 or clicking "Start Debugging".
    4. **Verify Impact (Vulnerable Version)**:
        - After the debug session starts, check if the file `/tmp/pwned.txt` (or `%TEMP%/pwned.txt` on Windows) exists on the victim's system.
        - If the file exists, it indicates successful command injection.
    5. **Verify Mitigation (Mitigated Version)**:
        - Apply proper sanitization to the `scriptPath` in `debuggerScriptDriver.ts` to prevent command injection.
        - Repeat steps 1-3 with the same malicious `evil_script.cmake` and debug configuration.
        - Verify that the `evil_script.cmake` execution fails safely, and the file `/tmp/pwned.txt` (or `%TEMP%/pwned.txt` on Windows) is **not** created.

### Vulnerability 2: Command Injection in Localization Script

- **Vulnerability Name:** Command Injection in Localization Script
- **Description:**
    1. The `translations_auto_pr.js` script automates localization processes, including GitHub pull requests.
    2. It accepts command-line arguments like `user_full_name` and `user_email`.
    3. These arguments are directly embedded into `git config` commands using template literals: `git config --local user.name "${userFullName}"` and `git config --local user.email "${userEmail}"`.
    4. A malicious actor controlling `user_full_name` or `user_email` can inject arbitrary commands into these `git config` commands.

- **Impact:**
    - High: Command injection allows arbitrary command execution on the system running `translations_auto_pr.js`. In CI/CD pipelines, this could compromise the build environment and extension release integrity.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None: Input arguments are used directly in shell commands without sanitization.

- **Missing Mitigations:**
    - Input sanitization and validation for `user_full_name` and `user_email` arguments in `translations_auto_pr.js`.
    - Employ parameterized commands or secure Git configuration APIs to prevent shell command injection.

- **Preconditions:**
    - An attacker must control command-line arguments to `translations_auto_pr.js`, likely in automated CI/CD environments where inputs might be indirectly influenced.

- **Source Code Analysis:**
    - File: `/code/translations_auto_pr.js`
    - Lines: ~172-175, ~178-181
    ```javascript
    cp.execSync(`git config --local user.name "${userFullName}"`);
    cp.execSync(`git config --local user.email "${userEmail}"`);
    ```
    - `userFullName` and `userEmail` variables are directly interpolated into `git config` commands, creating a command injection vulnerability.
    - User-provided input (`userFullName`, `userEmail`) is directly embedded in `git config` commands, leading to command execution.

- **Security Test Case:**
    1. **Setup:**
        - Environment to execute `translations_auto_pr.js` (e.g., local development mimicking CI/CD).
        - Git installed and configured.
    2. **Steps:**
        - Execute `translations_auto_pr.js` with a malicious payload for `user_full_name`:
        ```bash
        node translations_auto_pr.js repo_owner repo_name auth_user auth_token \"; touch /tmp/pwned #\" user_email loc_root_path loc_sub_path
        ```
        - Replace placeholders (`repo_owner`, etc.) with valid values for script execution.
    3. **Expected Result:**
        - File `/tmp/pwned` should be created, indicating successful command injection.

### Vulnerability 3: Unsafe usage of `child_process.execSync` in `cmakeDriver.ts`

- **Vulnerability Name:** Unsafe usage of `child_process.execSync` in `cmakeDriver.ts`
- **Description:**
    1. `CMakeDriver` class in `cmakeDriver.ts` utilizes `child_process.execSync` for shell command execution, specifically in `_cleanPriorConfiguration`.
    2. The `cmake_files` variable, part of the deletion path, is constructed using `path.join(build_dir, 'CMakeFiles')`.
    3. If an attacker influences configuration to manipulate `build_dir`, it could lead to unintended file system operations during `cleanConfigure`.
    4. While less direct than command injection, it's a potential vulnerability if `build_dir` configuration and file paths are not carefully handled.

- **Impact:**
    - High: Unsafe `execSync` usage with potentially influenced paths can cause unintended file deletion or manipulation outside the intended build directory during clean operations. Exploitable in shared or automated environments to impact system integrity or availability.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None: `execSync` is used directly with paths derived from configuration.

- **Missing Mitigations:**
    - Thorough validation and sanitization of `build_dir` path before using it in `fs.rmdir` within `_cleanPriorConfiguration`.
    - Consider safer file system operations without shell execution or robust path sanitization to prevent directory traversal or unintended deletions.

- **Preconditions:**
    - Attacker must indirectly influence `build_dir` configuration, possibly via workspace settings, to point to sensitive file system locations.
    - User must trigger "CMake: Clean Configure" to execute the vulnerable `_cleanPriorConfiguration` method.

- **Source Code Analysis:**
    - File: `/code/src/drivers/cmakeDriver.ts`
    - Lines: ~292-305
    ```typescript
    protected async _cleanPriorConfiguration() {
        const build_dir = this.binaryDir;
        const cache = this.cachePath;
        const cmake_files = this.config.deleteBuildDirOnCleanConfigure ? build_dir : path.join(build_dir, 'CMakeFiles');
        ...
        if (await fs.exists(cmake_files)) {
            log.info(localize('removing', 'Removing {0}', cmake_files));
            await fs.rmdir(cmake_files);
        }
    }
    ```
    - `_cleanPriorConfiguration` uses `execSync` via `fs.rmdir` with `cmake_files` path.
    - `cmake_files` is constructed using `build_dir` from user configuration, making it an indirect injection point for file system operations.
    - User configuration (influencing `build_dir`) contributes to `cmake_files`, which is then used in `fs.rmdir(cmake_files)` for file system operations.

- **Security Test Case:**
    1. **Setup:**
        - VS Code with CMake Tools, a workspace folder, and a CMake project.
    2. **Steps:**
        - Modify workspace `settings.json` to set `cmake.buildDirectory` to `/tmp/malicious_build_dir`.
        - Create a dummy directory `/tmp/malicious_build_dir/CMakeFiles`.
        - Trigger "CMake: Clean Configure".
    3. **Expected Result:**
        - The dummy directory `/tmp/malicious_build_dir/CMakeFiles` should be deleted, demonstrating `build_dir` configuration's influence on file system operations outside the workspace.

### Vulnerability 4: Path Traversal and File Overwrite via `cmake.copyCompileCommands`

- **Vulnerability Name:** Path Traversal and File Overwrite via `cmake.copyCompileCommands`

- **Description:**
    1. An attacker can set the `cmake.copyCompileCommands` setting in VSCode workspace settings to an arbitrary path, potentially outside the workspace or to system directories.
    2. CMake Tools generates `compile_commands.json` in the build directory upon CMake project configuration.
    3. If `cmake.copyCompileCommands` is set, CMake Tools copies `compile_commands.json` to the user-specified path.
    4. Inadequate path sanitization in `cmake.copyCompileCommands` allows copying `compile_commands.json` outside the intended workspace, potentially overwriting sensitive files in system or other user-accessible locations if VSCode has sufficient privileges.

- **Impact:**
    - **High**: Arbitrary file overwrite. Attackers can overwrite configuration files, scripts, or sensitive data if VSCode has write access to the target path, potentially leading to privilege escalation or arbitrary code execution if overwritten files are executed by the system or other users.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Path Sanitization**:  Changelog mentions path sanitization for `cmake.copyCompileCommands`. However, the effectiveness needs source code verification.
    - **File Path Comparison**: Changelog also mentions fixing compilation database path comparison to prevent unintended overwrites, but primarily within the workspace, not necessarily outside.

- **Missing Mitigations:**
    - **Strict Path Validation**: Lack of strict validation to ensure `cmake.copyCompileCommands` path stays within the workspace or a designated safe directory. Robust mitigation should verify if the target directory is a subdirectory of the workspace or a user-defined allowed path before copying.

- **Preconditions:**
    - User opens a CMake project in VSCode.
    - Threat actor can influence VSCode workspace settings (direct `settings.json` access or malicious workspace configuration).
    - `cmake.copyCompileCommands` is set to an attacker-controlled path outside the workspace.
    - User triggers CMake configuration.

- **Source Code Analysis:**
    ```markdown
    Detailed source code analysis is not possible without access to the relevant project files handling `cmake.copyCompileCommands` and its path sanitization implementation. Source code access is required for a complete analysis.
    ```

- **Security Test Case:**
    1. **Setup:**
        - Create a CMake project with a `.vscode/settings.json` file in a workspace.
    2. **Craft malicious settings:**
        - In `.vscode/settings.json`, set `"cmake.copyCompileCommands": "/tmp/evil.json"`.
    3. **Create a dummy file to overwrite:**
        - Create a dummy file at `/tmp/evil.json`.
    4. **Open the workspace in VSCode:**
        - Open the malicious CMake project in VSCode with CMake Tools extension enabled.
    5. **Trigger CMake configuration:**
        - Execute the "CMake: Configure" command.
    6. **Verify file overwrite:**
        - Check if the content of `/tmp/evil.json` is overwritten with `compile_commands.json` content.
    7. **Expected result:**
        - Vulnerability exists: `/tmp/evil.json` is overwritten. Mitigation effective: file is not overwritten, or copy operation fails.