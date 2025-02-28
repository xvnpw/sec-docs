### Vulnerability List

- Vulnerability Name: Command Injection via Script Path in CMake Debugger
- Description:
    1. The `DebugConfigurationProvider.ts` and `DebugAdapterNamedPipeServerDescriptorFactory.ts` allow debugging CMake scripts via the "CMake: CMake Script" debug configuration.
    2. The `scriptPath` configuration option, intended to specify the path to the CMake script, is passed directly to `executeScriptWithDebugger` in `debuggerScriptDriver.ts`.
    3. In `debuggerScriptDriver.ts`, the `scriptPath` is used as an argument to the `cmake -P` command without proper sanitization.
    4. If an attacker can control the `scriptPath` value in the debug configuration (e.g., through a crafted workspace configuration or a malicious extension), they can inject arbitrary shell commands into the `cmake -P` execution.
- Impact:
    - High. Successful command injection allows an attacker to execute arbitrary commands on the system where VS Code is running when a user initiates debugging of a CMake script with a maliciously crafted `scriptPath`. This could lead to arbitrary code execution with the privileges of the VS Code user.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The `scriptPath` is directly used in command execution without sanitization.
- Missing Mitigations:
    - Input sanitization and validation for the `scriptPath` debug configuration option.
    - Ensure that the `scriptPath` argument is treated as a file path and not directly executed as a command. Parameterize the `cmake -P` command to avoid shell injection.
- Preconditions:
    - An attacker needs to be able to influence the debug configuration of the "CMake: CMake Script" debug configuration, specifically the `scriptPath` option. This could be achieved by:
        - Contributing a malicious VS Code extension that modifies debug configurations.
        - Social engineering or tricking a user into opening a workspace with a malicious debug configuration.
- Source Code Analysis:
    1. File: `/code/src/debug/debugConfigurationProvider.ts`
    2. Lines: ~15-21, ~44-45, ~60-61
    3. The `DynamicDebugConfigurationProvider` and `DebugConfigurationProvider` define and resolve the "CMake: CMake Script" debug configuration, taking `scriptPath` from the configuration.
    4. File: `/code/src/debug/cmakeDebugger/debugAdapterNamedPipeServerDescriptorFactory.ts`
    5. Lines: ~62-69
    6. The `DebugAdapterNamedPipeServerDescriptorFactory` calls `executeScriptWithDebugger` with `session.configuration.scriptPath`.
    7. File: `/code/src/debug/debuggerScriptDriver.ts`
    8. Lines: ~31-32, ~36
    9. The `executeScriptWithDebugger` function directly uses `scriptPath` in the `cmake -P` command:
    ```typescript
    const concreteArgs = ["-P", scriptPath];
    const child = proc.execute(cmakeExe.path, concreteArgs, outputConsumer, { environment: env});
    ```
    10. Visualization:
    ```
    Debug Configuration (scriptPath) --> DebugAdapterNamedPipeServerDescriptorFactory --> executeScriptWithDebugger(scriptPath) --> cmake -P scriptPath --> command execution
    ```
    11. A malicious actor could set `scriptPath` to a value like `"$(echo pwned > /tmp/pwned) & script.cmake"`. When `cmake -P` is executed, it will interpret `$(echo pwned > /tmp/pwned) &` as a shell command to be executed before running `script.cmake`.
- Security Test Case:
    1. Setup:
        - VS Code with the CMake Tools extension installed.
        - A workspace folder open.
    2. Steps:
        - Create a new debug configuration of type "cmake" and request "launch". Set `cmakeDebugType` to "script".
        - Set the `scriptPath` in the debug configuration to a malicious command, for example: `"; touch /tmp/pwned #"` or on Windows `"; type nul > C:\\pwned.txt #"`
        - Start debugging this configuration ("CMake: CMake Script").
    3. Expected Result:
        - A file named `pwned` should be created in `/tmp` (or `C:\pwned.txt` on Windows), indicating successful command injection. VS Code should not show an error message related to script execution failure as the injected command is executed before CMake attempts to process a (likely non-existent or invalid) CMake script.

- Vulnerability Name: Command Injection in Localization Script
- Description:
    1. The `translations_auto_pr.js` script is used for automating the process of localization, including pushing changes to a GitHub repository via a pull request.
    2. The script takes several command-line arguments, including `repo_owner`, `repo_name`, `auth_user`, `auth_token`, `user_full_name`, `user_email`, `loc_root_path`, and `loc_sub_path`.
    3. Specifically, `user_full_name` and `user_email` arguments are directly incorporated into git commands: `git config --local user.name "${userFullName}"` and `git config --local user.email "${userEmail}"`.
    4. If a malicious actor can control the `user_full_name` or `user_email` arguments passed to the script, they can inject arbitrary commands into the `git config` commands.
- Impact:
    - High. Successful command injection can allow an attacker to execute arbitrary commands on the system where the `translations_auto_pr.js` script is executed. In the context of a CI/CD pipeline, this could compromise the build environment and potentially the integrity of the extension release.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly uses the input arguments in shell commands without sanitization.
- Missing Mitigations:
    - Input sanitization and validation for `user_full_name` and `user_email` arguments in `translations_auto_pr.js`.
    - Use parameterized commands or a secure API for git configuration to avoid shell command injection.
- Preconditions:
    - An attacker needs to be able to control the command-line arguments passed to the `translations_auto_pr.js` script. This is more likely in automated environments (like CI/CD) where input might be indirectly influenced.
- Source Code Analysis:
    1. File: `/code/translations_auto_pr.js`
    2. Lines: ~172-175, ~178-181
    3. The script constructs git commands using template literals, directly embedding the `userFullName` and `userEmail` variables:
    ```javascript
    cp.execSync(`git config --local user.name "${userFullName}"`);
    cp.execSync(`git config --local user.email "${userEmail}"`);
    ```
    4. Visualization:
    ```
    user provided input --> userFullName, userEmail --> string interpolation in `git config` commands --> command execution
    ```
    5. A malicious user could provide a payload like `"; touch /tmp/pwned #` as `user_full_name`. When the script executes `git config --local user.name "; touch /tmp/pwned #"`, it will first execute `git config --local user.name ";` and then execute `touch /tmp/pwned #"` as a separate command injection.
- Security Test Case:
    1. Setup:
        - Access to an environment where `translations_auto_pr.js` can be executed (e.g., a local development environment mimicking the CI/CD pipeline).
        - Ensure `git` is installed and configured.
    2. Steps:
        - Execute the `translations_auto_pr.js` script with a malicious payload for the `user_full_name` argument. For example:
        ```bash
        node translations_auto_pr.js repo_owner repo_name auth_user auth_token \"; touch /tmp/pwned #\" user_email loc_root_path loc_sub_path
        ```
        - Replace `repo_owner`, `repo_name`, `auth_user`, `auth_token`, `user_email`, `loc_root_path`, `loc_sub_path` with valid placeholder values for the script to run without other errors.
        - Check if the command injection was successful. In this example, verify if the file `/tmp/pwned` was created.
    3. Expected Result:
        - The file `/tmp/pwned` should be created, indicating successful command injection.

- Vulnerability Name: Unsafe usage of `child_process.execSync` in `cmakeDriver.ts`
- Description:
    1. The `CMakeDriver` class in `cmakeDriver.ts` uses `child_process.execSync` to execute shell commands, specifically within the `_cleanPriorConfiguration` method.
    2. The `cmake_files` variable, which is part of the path being deleted, is constructed using `path.join(build_dir, 'CMakeFiles')`. While `build_dir` itself is derived from configuration, if a malicious actor could influence the configuration in a way that leads to an unexpected or attacker-controlled `build_dir`, it could potentially lead to unintended file system operations during the `cleanConfigure` process.
    3. Although the direct risk is lower compared to command injection as the attacker's control is indirect and dependent on manipulating configuration and file system paths, it still presents a potential vulnerability if not handled carefully.
- Impact:
    - High. While not direct command injection, unsafe usage of `execSync` with paths derived from potentially influenceable configurations could lead to unintended file deletion or manipulation outside the intended build directory during clean operations. In a shared or automated environment, this could be exploited to impact system integrity or availability.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. `execSync` is used directly with paths constructed from configuration.
- Missing Mitigations:
    - Thorough validation and sanitization of the `build_dir` path before using it in `fs.rmdir` within `_cleanPriorConfiguration`.
    - Consider using safer file system operations that do not involve shell execution if possible, or implement robust path sanitization to prevent directory traversal or deletion of unexpected paths.
- Preconditions:
    - An attacker needs to be able to influence the `build_dir` configuration indirectly, potentially through workspace settings or other configuration mechanisms, to point to a sensitive location on the file system.
    - The user must trigger the "Clean Configure" command, which executes the vulnerable `_cleanPriorConfiguration` method.
- Source Code Analysis:
    1. File: `/code/src/drivers/cmakeDriver.ts`
    2. Lines: ~292-305
    3. The `_cleanPriorConfiguration` method uses `execSync` to execute `fs.rmdir`:
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
    4. The `cmake_files` path is constructed using `path.join`, but the `build_dir` is derived from user configuration, making it a potential indirect injection point.
    5. Visualization:
    ```
    user configuration (indirectly influences build_dir) --> path.join(build_dir, 'CMakeFiles') --> cmake_files --> fs.rmdir(cmake_files) --> command execution (file system operation)
    ```
    6. While not direct command injection, if an attacker can manipulate the configuration such that `build_dir` points outside the intended workspace build directory, `fs.rmdir` could potentially delete unintended directories.
- Security Test Case:
    1. Setup:
        - VS Code with the CMake Tools extension installed.
        - A workspace folder open with a CMake project.
    2. Steps:
        - Modify the workspace `settings.json` to set `cmake.buildDirectory` to a location outside the workspace, for example, `/tmp/malicious_build_dir`.
        - Create a dummy file or directory in `/tmp/malicious_build_dir/CMakeFiles` to simulate a CMake build structure.
        - Trigger the "CMake: Clean Configure" command.
        - Check if the dummy file or directory in `/tmp/malicious_build_dir/CMakeFiles` has been deleted.
    3. Expected Result:
        - The dummy file or directory in `/tmp/malicious_build_dir/CMakeFiles` should be deleted, demonstrating that the `build_dir` configuration can influence file system operations outside the workspace.