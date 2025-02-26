### Vulnerability List for js-beautify for VS Code

* Vulnerability Name: Uncontrolled Configuration Lookup Scope Leading to Potential Project-Wide or Global Configuration Injection
* Description:
    The js-beautify extension searches for `.jsbeautifyrc` configuration files in the directory of the file being beautified and recursively up through its parent directories. This search extends beyond the current VSCode workspace, potentially reaching the user's home directory or even the system root. An attacker who can place a malicious `.jsbeautifyrc` file in a parent directory of a user's workspace (e.g., in the user's home directory) could have this configuration file loaded and applied to the user's projects opened within that workspace, without the user's explicit knowledge or consent. This can lead to unexpected and potentially harmful code formatting across different projects, as the malicious configuration would override project-specific or default settings.

    Steps to trigger vulnerability:
    1. Attacker creates a malicious `.jsbeautifyrc` file (e.g., setting extreme indentation or other disruptive formatting rules) and places it in a common parent directory of potential victim workspaces, such as the user's home directory (`~/.jsbeautifyrc`).
    2. Victim user opens a VSCode workspace or a file within a workspace whose path is a subdirectory of the directory containing the malicious `.jsbeautifyrc` file.
    3. Victim user triggers the beautify command (e.g., "Beautify File" or "Beautify Selection").
    4. The extension's configuration lookup mechanism searches for `.jsbeautifyrc` files, starting from the file's directory and traversing upwards.
    5. The malicious `.jsbeautifyrc` file in the parent directory (e.g., home directory) is found and its configuration is loaded.
    6. The beautifier applies the settings from the malicious configuration file, leading to unexpected and potentially harmful formatting of the victim's code.

* Impact:
    Unexpected and potentially harmful code formatting changes across multiple projects. This could lead to:
    - Introduction of subtle bugs due to unexpected code modifications.
    - Code obfuscation, making code harder to read and maintain.
    - Developer frustration and reduced productivity due to unexpected beautifier behavior.
    - Potential supply chain issues if developers unknowingly commit unintentionally modified code into version control systems.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    None. The extension currently implements the configuration lookup as described, without restrictions on the scope or warnings about configurations loaded from outside the workspace.

* Missing Mitigations:
    - **Restrict `.jsbeautifyrc` lookup scope:** Limit the search for `.jsbeautifyrc` files to the current VSCode workspace folder and its subdirectories. Do not search in parent directories outside the workspace.
    - **Workspace-level configuration precedence:** Ensure that workspace-level settings and `.jsbeautifyrc` files within the workspace always take precedence over any configurations found in parent directories outside the workspace (if parent directory lookup is to be retained at all).
    - **User warning for external configurations:** If configuration files are loaded from outside the current workspace (e.g., from the home directory), display a warning message to the user, indicating that a global or external configuration is being applied and from where it is loaded.
    - **Configuration scope setting:** Provide a user setting to control the scope of `.jsbeautifyrc` lookup (e.g., "workspace only", "workspace and parent directories", "workspace and home directory", "system-wide").

* Preconditions:
    1. Attacker has the ability to place a malicious `.jsbeautifyrc` file in a directory that is a parent of the victim's workspace (e.g., user's home directory).
    2. Victim user opens a VSCode workspace or file within such a workspace.
    3. Victim user triggers the beautify command.

* Source Code Analysis:
    1. **`options.js:module.exports`**: This is the main function that determines beautification options.
    2. **`options.js:getWorkspaceRoot(doc)`**: Determines the workspace root. If no workspace, it might return `vscode.workspace.rootPath` (deprecated) or undefined, potentially leading to system root being considered as root in some scenarios if not handled properly in `findRecursive`.
    3. **`options.js:findRecursive(dir, fileName, root)`**: Recursively searches for `.jsbeautifyrc` starting from `dir` and going up to `root`.
        ```javascript
        const findRecursive = (dir, fileName, root) => {
          const fullPath = path.join(dir, fileName);
          const nextDir = path.dirname(dir);
          let result = fs.existsSync(fullPath) ? fullPath : null;
          if (!result && nextDir !== dir && dir !== root) { // Condition `dir !== root` controls the upward traversal limit.
            result = findRecursive(nextDir, fileName, root); // Recursive call to parent directory.
          }
          return result;
        };
        ```
        - The `root` variable, determined in `module.exports`, controls how far up the directory tree the search goes. If `root` is not strictly limited to the workspace, the search can go beyond the intended scope.
        - If `getWorkspaceRoot` returns undefined or falls back to a very high-level directory (or system root in older VSCode versions via `vscode.workspace.rootPath`), the `findRecursive` function might traverse much higher than intended.
    4. **`options.js:module.exports`**: Calls `findRecursive` with the determined `dir`, filename `.jsbeautifyrc`, and `root`. If a `.jsbeautifyrc` is found in a parent directory (potentially outside the workspace), its settings are loaded and applied.

* Security Test Case:
    1. **Setup Malicious Configuration:**
        - Create a directory structure: `/tmp/malicious_config/.jsbeautifyrc` and `/tmp/victim_workspace/test.js`.
        - In `/tmp/malicious_config/.jsbeautifyrc`, place the following malicious configuration:
            ```json
            {
              "indent_size": 8,
              "indent_char": "\t"
            }
            ```
        - Ensure that `/tmp/malicious_config` is a parent directory of `/tmp/victim_workspace` (e.g., if your home dir is `/home/user`, then `/tmp/malicious_config` could be `/home/user`). For this test, using `/tmp/malicious_config` and `/tmp/victim_workspace` is sufficient if the user has permissions to create these directories.
        - Create a test Javascript file `/tmp/victim_workspace/test.js` with the following content:
            ```javascript
            function test(){
              var a = 1;
            }
            ```
    2. **VSCode Setup:**
        - Open VSCode.
        - Open the folder `/tmp/victim_workspace` as a workspace in VSCode (`File -> Open Folder... -> /tmp/victim_workspace`).
        - Open the file `/tmp/victim_workspace/test.js` in the editor.
    3. **Trigger Beautify:**
        - Execute the "Beautify File" command (e.g., via Command Palette or configured shortcut).
    4. **Verify Vulnerability:**
        - Observe the formatted content of `test.js`.
        - **Expected Vulnerable Behavior:** The code in `test.js` will be formatted with an indent size of 8 tabs, as defined in the malicious `.jsbeautifyrc` file located in `/tmp/malicious_config/.jsbeautifyrc` (parent directory).
        - **Expected Secure Behavior (Mitigated):** The code in `test.js` should be formatted using either default settings or workspace-specific settings, but *not* with the settings from the `.jsbeautifyrc` file in `/tmp/malicious_config` if the mitigation is to restrict lookup to workspace only. If the mitigation is to warn, a warning should be displayed, and the formatting may or may not be as per the malicious config depending on precedence rules after mitigation.

---

* Vulnerability Name: Arbitrary File Read via `beautify.config` Workspace Setting
* Description:
    The js-beautify extension allows users to specify a configuration file path using the `beautify.config` setting in VSCode's workspace or user settings. This setting is intended to point to a `.jsbeautifyrc` file. However, the extension does not sufficiently validate or restrict the file path provided in `beautify.config`. A malicious actor, by compromising workspace settings (e.g., through a crafted workspace configuration shared via a repository or social engineering), could set `beautify.config` to an absolute path pointing to any file on the user's file system that the VSCode process has permissions to read. When the extension attempts to load beautifier settings, it will read the file specified in `beautify.config`, leading to an arbitrary file read vulnerability.

    Steps to trigger vulnerability:
    1. Attacker crafts a malicious workspace configuration (e.g., `settings.json` in `.vscode` folder) that sets the `beautify.config` setting to point to a sensitive file on the user's system, such as `/etc/passwd` or a private key file (assuming VSCode process has read permissions). Example malicious setting: `"beautify.config": "/etc/passwd"`.
    2. Attacker distributes this malicious workspace (e.g., by hosting it in a public repository or sending it to the victim).
    3. Victim user opens the malicious workspace in VSCode. VSCode automatically loads the workspace settings, including the malicious `beautify.config` value.
    4. Victim user triggers the beautify command on any file within the workspace.
    5. The extension attempts to load beautifier options. It reads the `beautify.config` setting, which now points to the attacker-specified file (e.g., `/etc/passwd`).
    6. The extension attempts to read and parse the content of the file specified in `beautify.config`. Although parsing might fail if the target file is not a valid JSON, the file content is still read by the extension.
    7. While the extension might show an error message about parsing failure, the arbitrary file read has already occurred. The attacker, if they can monitor system calls or extension behavior, could potentially confirm that the file was accessed. In a more sophisticated attack, if the file content (even if not JSON) is further processed or logged, it might leak the file content.

* Impact:
    Arbitrary file read. An attacker can potentially read any file on the user's system that the VSCode process has permissions to access. This could lead to the disclosure of sensitive information, such as:
    - System configuration files (e.g., `/etc/passwd`, `/etc/shadow` - if permissions allow).
    - Private keys, API keys, or credentials stored in files.
    - Source code or intellectual property.
    - User data and personal information.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - `options.js`: Checks if the configured path exists using `fs.existsSync(configFile)`. However, this only verifies existence and does not prevent reading arbitrary files if the path is valid and accessible to the VSCode process.

* Missing Mitigations:
    - **Path validation and sanitization:** Validate the `beautify.config` path to ensure it is within the workspace directory or a designated safe configuration directory. Prevent absolute paths or paths that traverse outside the allowed scope.
    - **Path restriction:** Restrict the `beautify.config` setting to only accept relative paths within the workspace. Resolve these paths relative to the workspace root to prevent access to locations outside the workspace.
    - **User warning for external paths:** If an absolute path or an external path is provided in `beautify.config`, display a warning message to the user, indicating the potential security risk of loading configurations from arbitrary locations.
    - **Input sanitization:** Sanitize the input path to prevent path traversal attacks (e.g., by resolving and canonicalizing paths).

* Preconditions:
    1. Attacker can influence the `beautify.config` workspace setting (e.g., by providing a malicious workspace configuration).
    2. Victim user opens the malicious workspace in VSCode.
    3. Victim user triggers the beautify command.

* Source Code Analysis:
    1. **`options.js:module.exports`**: Retrieves the `beautify.config` setting using `vscode.workspace.getConfiguration('beautify').config`.
    2. **`options.js:module.exports`**: Handles the `beautify_config` string case:
        ```javascript
        if (typeof beautify_config === 'string') {
            if (path.isAbsolute(beautify_config)) configFile = beautify_config; // If absolute, directly use it. VULNERABLE!
            else configFile = path.resolve(root, beautify_config); // If relative, resolve against workspace root.

            configFile = fs.existsSync(configFile) ? configFile : null; // Check if file exists, but doesn't prevent reading if path is malicious.
        }
        ```
        - If `beautify_config` is a string and is an absolute path, it's directly assigned to `configFile` without validation. This allows specifying any absolute file path.
        - `fs.existsSync` only checks for file existence, not path security.

* Security Test Case:
    1. **Setup Malicious Workspace Configuration:**
        - Create a new directory, e.g., `/tmp/malicious_workspace`.
        - Inside `/tmp/malicious_workspace`, create a `.vscode` directory.
        - Inside `.vscode`, create a `settings.json` file with the following content. Replace `/etc/passwd` with a path to a sensitive file accessible to your VSCode process if `/etc/passwd` is not readable.
            ```json
            {
              "beautify.config": "/etc/passwd"
            }
            ```
        - Create a dummy Javascript file in `/tmp/malicious_workspace`, e.g., `test.js` with any Javascript content.
    2. **VSCode Setup:**
        - Open VSCode.
        - Open the folder `/tmp/malicious_workspace` as a workspace in VSCode (`File -> Open Folder... -> /tmp/malicious_workspace`).
        - Open the file `test.js` in the editor.
    3. **Trigger Beautify:**
        - Execute the "Beautify File" command.
    4. **Verify Vulnerability:**
        - While you might see an error message in VSCode about failing to parse `/etc/passwd` as a JSON file (because `/etc/passwd` is not JSON), the vulnerability is confirmed if the extension attempts to read the content of `/etc/passwd`.
        - To more directly verify file read, you can use system monitoring tools (like `strace` on Linux or `Process Monitor` on Windows) to observe file system access by the VSCode process when beautifying. Look for file access to `/etc/passwd` or the file you specified in `beautify.config`.
        - Alternatively, modify `options.js` temporarily to log the `configFile` path before `fs.readFile` to confirm that the path is indeed set to `/etc/passwd`.