- **Vulnerability Name:** Arbitrary File Read via Malicious Beautify Config Path
  **Description:**
  The extension obtains configuration settings by reading the value of the workspace setting “beautify.config.” When this setting is a string, the code checks whether the string is an absolute path (using `path.isAbsolute`) and, if so, directly assigns it to the configuration file path. An attacker supplying a malicious workspace settings file (for example, via a project’s `.vscode/settings.json`) can set “beautify.config” to point to an arbitrary file (for example, “/etc/passwd” on Unix or “C:\Windows\system.ini” on Windows). When the extension loads that configuration, it will read the targeted file with no further validation and attempt to parse its contents as JSON. Even if the file does not produce valid JSON (in which case a warning is shown), an attacker can manipulate the file (or provide one that is valid JSON) so that unexpected or attacker‐controlled configuration values are merged into the options used by js‑beautify.
  **Impact:**
  An attacker who controls the workspace configuration can force the extension to load configuration from arbitrary locations. This may lead to the inadvertent disclosure of sensitive file contents or cause unintended formatting behavior by injecting malicious configuration values that alter how files are beautified.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The code verifies that a file exists using `fs.existsSync` before attempting to read it.
  - The file is read only if the workspace setting (“beautify.config”) is provided.
  **Missing Mitigations:**
  - No validation or sanitization is performed on the file path supplied via “beautify.config.”
  - There is no restriction to limit allowed configuration files only to the workspace or to a whitelisted directory.
  - The extension does not check whether the file is located in a trusted directory.
  **Preconditions:**
  - The user opens a workspace that includes a malicious or tampered `.vscode/settings.json` with a setting such as:
    ```json
    {
      "beautify": {
        "config": "/etc/passwd"
      }
    }
    ```
  - The targeted file exists and is accessible by the user’s account.
  - The workspace is trusted or the security model does not enforce strict workspace–trust validation.
  **Source Code Analysis:**
  - In `options.js`, the code retrieves the configuration via:
    ```js
    let beautify_config = vscode.workspace.getConfiguration('beautify').config;
    ```
  - If this value is a string, the following check is made:
    ```js
    if (typeof beautify_config === 'string') {
      if (path.isAbsolute(beautify_config))
        configFile = beautify_config;
      else
        configFile = path.resolve(root, beautify_config);
      configFile = fs.existsSync(configFile) ? configFile : null;
    }
    ```
  - No further checks ensure that the supplied file path is within an allowed directory. As a result, an attacker–controlled absolute path is accepted and then read using `fs.readFile`.
  **Security Test Case:**
  1. Create a malicious workspace directory and add a `.vscode/settings.json` file containing:
     ```json
     {
       "beautify": {
         "config": "/etc/passwd"
       }
     }
     ```
  2. (On Windows, substitute an appropriate sensitive file path.)
  3. Open the workspace in Visual Studio Code.
  4. Open any supported file and trigger the beautification process (using the command palette to run “HookyQR.beautifyFile”).
  5. Observe that the extension attempts to read the file `/etc/passwd` and, if its contents are (even accidentally) valid JSON or modified to become valid JSON, the configuration values will be merged. At a minimum a warning message will be displayed such as:
     > “Found a .jsbeautifyrc file [/etc/passwd], but it didn't parse correctly.”
  6. Verify that the formatting behavior of the file is altered or that sensitive file content (or error details) might be indirectly exposed.

- **Vulnerability Name:** Symlink Attack on .jsbeautifyrc Resolution
  **Description:**
  The extension looks for a beautifier configuration file by recursively searching for a file named “.jsbeautifyrc” starting from the directory of the open document. This search is performed by the helper function `findRecursive` in `options.js` using standard file existence checks (via `fs.existsSync`). However, no check is made to verify that the found “.jsbeautifyrc” is a regular file (or even that it resides within the expected workspace boundaries). An attacker who controls a repository can include a symbolic link named “.jsbeautifyrc” that points to an arbitrary file outside of the workspace (for example, a system file or another sensitive configuration file). When the extension loads this file, the symlink is followed and the external file’s contents are read and parsed.
  **Impact:**
  Reading unintended external files may lead to the leakage of sensitive information or injection of untrusted configuration into the beautifier process. The resulting configuration could cause unexpected behavior in the formatting process.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The extension uses `fs.existsSync` and `fs.readFile` without checking file metadata (such as whether the found file is a symlink).
  - The search logic in `findRecursive` is simple and does not distinguish between regular files and symlinks.
  **Missing Mitigations:**
  - No verification is performed to ensure that the discovered “.jsbeautifyrc” file is not a symbolic link.
  - There is no enforcement of a safe path boundary (for example, the workspace root) when loading configuration files.
  **Preconditions:**
  - The attacker must be able to influence the repository file structure (for example, in a malicious project) to include a symlink named “.jsbeautifyrc.”
  - The symlink must point to a file outside of the expected configuration directory (e.g., to “/etc/passwd” or another sensitive file).
  - The victim opens the malicious repository in Visual Studio Code while the extension is active.
  **Source Code Analysis:**
  - The function `findRecursive` in `options.js` is defined as:
    ```js
    const findRecursive = (dir, fileName, root) => {
      const fullPath = path.join(dir, fileName);
      const nextDir = path.dirname(dir);
      let result = fs.existsSync(fullPath) ? fullPath : null;
      if (!result && nextDir !== dir && dir !== root) {
        result = findRecursive(nextDir, fileName, root);
      }
      return result;
    };
    ```
  - Because `fs.existsSync(fullPath)` returns true for symlinks and there is no subsequent check (for example, using `fs.lstatSync`) to reject them, an attacker–provided symlink is accepted as valid.
  - The file is then read using `fs.readFile`, which follows the symlink and loads the contents of an arbitrary file.
  **Security Test Case:**
  1. In a controlled test repository, create a symbolic link in the project root named “.jsbeautifyrc” that points to a file outside the workspace (for example, on Unix, create a symlink pointing to `/etc/passwd` or, on Windows, to a sensitive file).
  2. Open the repository in Visual Studio Code.
  3. Open a supported document and trigger beautification (using “HookyQR.beautifyFile” or “HookyQR.beautify”).
  4. Observe that the extension locates the “.jsbeautifyrc” via the recursive search and reads the external file’s content.
  5. If the external file’s content is (or is manipulated to be) valid JSON, verify that its values become merged into the configuration used for formatting. Otherwise, a warning message is issued.
  6. Confirm that the file used for configuration was not expected to come from outside the project directory and that its content (or the error details revealing its location) could disclose unwanted information.