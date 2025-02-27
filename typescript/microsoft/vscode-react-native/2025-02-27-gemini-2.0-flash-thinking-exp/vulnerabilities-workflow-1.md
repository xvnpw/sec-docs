## Vulnerability Report

### Vulnerability Name: Command Injection in `executeCommand`, `ChildProcess.spawn`, and `killPort` Command

- **Description:**
    The `executeCommand` function in `/code/tools/gulp-extras.js`, `ChildProcess.spawn` in `/code/src/common/node/childProcess.ts`, and implicitly `ChildProcess.exec` use `child_process.spawn` with `shell: true`. This configuration allows for command injection vulnerabilities if the `command` or `args` parameters are influenced by user-controlled input. Build scripts (`gulpfile.js`, `test/smoke/gulpfile.js`) and extension code (e.g., `/code/src/extension/commands/killPort.ts`, `/code/src/extension/commands/expoDoctor.ts`) use these functions.  Specifically, the 'Kill Port' command in the extension directly uses user-provided input without sanitization in `killPort.ts`, making it vulnerable. If these scripts or functions are ever modified to accept external input (e.g., from environment variables, command-line arguments during build process or extension settings that are user-controlled or indirectly controlled), a command injection vulnerability could be introduced. An attacker can inject arbitrary shell commands via the 'Kill Port' command input field.

- **Impact:**
    An attacker who can control the arguments passed to the build scripts or extension code that use the vulnerable `spawn` or `exec` functions could execute arbitrary commands on the system where the build process or extension runtime is running. In the context of the 'Kill Port' command, this allows for arbitrary command execution directly on the user's machine. This can lead to sensitive data exposure, malware installation, system compromise, and other malicious activities. While less directly exploitable by an external attacker targeting the extension itself at runtime in a general case, the 'Kill Port' command provides a direct entry point. However, if a developer is tricked into using a malicious build script or if the build environment becomes compromised, this could lead to significant harm, including code execution and data exfiltration within the build environment.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None in the `executeCommand`, `ChildProcess.spawn`, and `ChildProcess.exec` functions themselves. Reliance is on developers not to pass user-controlled input to the `command` or `args` parameters within the build scripts and extension code. Specifically, there is no input validation or sanitization for the port input in the 'Kill Port' command.

- **Missing Mitigations:**
    - Avoid using `shell: true` in `child_process.spawn` and `ChildProcess.spawn`.
    - If shell is necessary, sanitize and validate the `command` and `args` parameters to prevent command injection. Use parameterized execution where possible to separate commands from arguments.
    - Implement input validation and sanitization for user inputs, especially in commands like 'Kill Port'.
    - Use safer command execution methods that do not involve shell interpretation when possible.

- **Preconditions:**
    User must execute the 'Kill Port' command or an attacker needs to find a way to influence the arguments passed to the build scripts or extension code that use the vulnerable `executeCommand` or `ChildProcess.spawn`/`exec` function. For the 'Kill Port' command, the precondition is simply that a user executes the command. For build scripts, this might involve compromising the build environment or tricking a developer into using a malicious configuration that injects commands during the build process or extension runtime.

- **Source Code Analysis:**
    - File: `/code/tools/gulp-extras.js`
    ```javascript
    function executeCommand(command, args, callback, opts) {
        const proc = child_process.spawn(command + (process.platform === "win32" ? ".cmd" : ""), args, Object.assign({}, opts, { shell: true })); // Vulnerable line
        // ... rest of the function
    }
    ```
    - File: `/code/src/common/node/childProcess.ts`
    ```javascript
    public spawn(
        command: string,
        args: string[] = [],
        options: ISpawnOptions = {},
        showStdOutputsOnError: boolean = false,
    ): ISpawnResult {
        const spawnedProcess = this.childProcess.spawn(
            command,
            args,
            Object.assign({}, options, { shell: true }), // Vulnerable line
        );
        // ... rest of the function
    }
    ```
    - File: `/code/src/extension/commands/killPort.ts`
    ```javascript
    const res = await new ChildProcess().exec(`npx kill-port ${value}`); // Uses ChildProcess.exec with unsanitized user input 'value'
    ```
    - File: `/code/src/extension/commands/expoDoctor.ts`
    ```javascript
    const res = await new ChildProcess().exec("npx expo-doctor", { cwd: projectRootPath }); // Uses ChildProcess.exec
    ```
    The `shell: true` option in `executeCommand`, `ChildProcess.spawn` and implicitly in `ChildProcess.exec` functions executes the command through a shell interpreter. This allows shell metacharacters to be interpreted, which can be exploited for command injection if the `command` or `args` are not carefully handled. If an attacker can control any part of the `command` or `args` parameters, they could inject malicious shell commands. The `killPort` command is directly vulnerable because it takes user input `value` and passes it into the command string without sanitization.

- **Security Test Case:**
    1. Execute the "React Native: Kill Port" command in VSCode.
    2. In the input box, enter a malicious payload like: `8081 & touch /tmp/pwned`. Alternatively, use `; touch vulnerable;`.
    3. Observe if the file `/tmp/pwned` or `vulnerable` is created after the command execution.
    4. If the file is created, it confirms the command injection vulnerability in `killPort` command.

### Vulnerability Name: Arbitrary File Overwrite via Path Traversal in `writeFileToFolder` function

- **Description:**
    The `writeFileToFolder` function in `/code/src/common/node/fileSystem.ts` does not properly sanitize the `basename` parameter. If an attacker can control the `basename`, they could potentially use path traversal sequences (like `../`) within the `basename` to write files outside the intended `folder`, leading to arbitrary file overwrite. While the current extension code doesn't directly expose this function to external user input at runtime, if future features or modifications to the extension or its build scripts incorporate user-provided filenames or paths that are passed to this function without validation, this vulnerability could become exploitable.

- **Impact:**
    Arbitrary file overwrite can have severe consequences, including:
    - Configuration file manipulation: Overwriting configuration files of the VS Code extension or other system components could alter their behavior, potentially leading to further security compromises.
    - Code injection: In certain scenarios, overwriting executable files or scripts could lead to code injection and arbitrary code execution.
    - Data corruption or loss: Overwriting important data files could lead to data corruption or loss.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. The function directly uses `path.join` with the provided `folder` and `basename` without any sanitization.

- **Missing Mitigations:**
    - Sanitize the `basename` parameter to prevent path traversal sequences.
    - Validate the `basename` against a whitelist of allowed characters and patterns.
    - Use secure file path handling techniques to ensure that files are always written within the intended directory.

- **Preconditions:**
    An attacker needs to find a way to control the `basename` parameter passed to the `writeFileToFolder` function. This could potentially happen if user-provided filenames or paths are incorporated into the extension's functionality without proper validation in future updates.

- **Source Code Analysis:**
    - File: `/code/src/common/node/fileSystem.ts`
    ```javascript
    public static writeFileToFolder(folder: string, basename: string, data: any): Promise<void> {
        if (!nodeFs.existsSync(folder)) {
            mkdirp.sync(folder);
        }
        return nodeFs.promises.writeFile(path.join(folder, basename), data); // Vulnerable line
    }
    ```
    The vulnerability lies in the `path.join(folder, basename)` part. If `basename` contains path traversal sequences (e.g., `../../`), `path.join` will resolve the path, potentially leading to a file path outside the intended `folder`.

- **Security Test Case:**
    1. Modify a part of the extension's code or a build script to use `FileSystem.writeFileToFolder` and make the `basename` parameter controllable by an attacker. For example, introduce a setting in `package.json` that, when set, passes a malicious basename to this function during a build task.
    2. Set the malicious basename to a path traversal payload, for example: `"../../../tmp/pwned_file"`.
    3. Run the modified code or build task.
    4. Check if the file `pwned_file` is created in the `/tmp` directory (or another location outside the intended folder, depending on the payload).
    5. If the file is created outside the intended folder, it confirms the arbitrary file overwrite vulnerability.

### Vulnerability Name: Potential Arbitrary File Read via Path Traversal in `findFileInFolderHierarchy` function

- **Description:**
    The `findFileInFolderHierarchy` function in `/code/src/common/extensionHelper.ts` searches for a file (`filename`) by traversing up the directory hierarchy from a given starting directory (`dir`). While not directly allowing arbitrary file *write*, a path traversal vulnerability could arise if the starting `dir` is user-controlled or influenced by user input and not properly validated. An attacker could potentially manipulate the starting `dir` to initiate the search from a sensitive location and, if the extension logic processes the found file without sufficient security checks, it could lead to unintended access to files outside the intended project workspace.

- **Impact:**
    Arbitrary file read could lead to:
    - Information disclosure: An attacker could read sensitive files, including source code, configuration files, or data files, potentially revealing secrets, credentials, or other confidential information.
    - Source code theft: Access to source code could aid in understanding the extension's logic and finding other vulnerabilities.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. The function performs path traversal based on the provided `dir` and `filename` without explicit sanitization or validation of the starting directory.

- **Missing Mitigations:**
    - Validate and sanitize the starting `dir` parameter to ensure it remains within the expected project workspace or a safe directory.
    - If the starting `dir` is derived from user input, implement strict validation to prevent path traversal manipulation.
    - Consider using more secure alternatives to file searching if possible, or limit the search scope to predefined safe directories.

- **Preconditions:**
    An attacker needs to find a way to influence the `dir` parameter of the `findFileInFolderHierarchy` function to point to a directory outside the intended project workspace. This could potentially happen if future features expose this function to user-controlled paths without proper validation.

- **Source Code Analysis:**
    - File: `/code/src/common/extensionHelper.ts`
    ```javascript
    export function findFileInFolderHierarchy(dir: string, filename: string): string | null { // Vulnerable parameter 'dir'
        let parentPath: string;
        let projectRoot: string = dir; // 'projectRoot' is derived from potentially attacker-controlled 'dir'

        while (!fs.existsSync(path.join(projectRoot, filename))) {
            // Navigate up one level until either config.xml is found
            parentPath = path.resolve(projectRoot, "..");
            if (parentPath !== projectRoot) {
                projectRoot = parentPath;
            } else {
                // we have reached the filesystem root
                return null;
            }
        }

        return path.join(projectRoot, filename);
    }
    ```
    The vulnerability lies in the function's design, which allows traversing up from a potentially attacker-controlled `dir`. If `dir` is manipulated to be a sensitive location, the function might find and return paths to files outside the intended scope.

- **Security Test Case:**
    1. Modify a part of the extension's code or a build script to use `findFileInFolderHierarchy` and make the `dir` parameter controllable by an attacker. For example, introduce a setting in `package.json` that, when set, passes a malicious directory path as the `dir` argument.
    2. Set the malicious `dir` to a sensitive directory, for example: `"/"` (root directory).
    3. Set the `filename` parameter to a sensitive file name, for example: `".bash_history"`.
    4. Run the modified code or build task.
    5. Check if the function returns a path to the sensitive file (e.g., `/root/.bash_history` or `/home/<user>/.bash_history` if run as non-root, assuming the file exists and permissions allow reading).
    6. If the function returns a path to the sensitive file, and if the extension further processes and potentially exposes the content of this file, it confirms the arbitrary file read vulnerability.