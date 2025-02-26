**• Vulnerability Name:** Malicious Package Name Code Injection

  - **Description:**
    The extension reads dependency names directly from a project’s package.json (via functions in `provide.ts` and later used by the auto import command in `command-import.ts`). An attacker who controls a repository’s package.json can provide a specially crafted dependency key (for example, one containing embedded quotes and code payloads) that, when interpolated into the auto import statement template, creates a malformed or malicious statement.
    **Steps to trigger:**
    1. An attacker creates a malicious repository whose package.json contains a dependency with a name such as:
       ```json
       {
         "dependencies": {
           "\"; process.exit();//": "1.0.0"
         }
       }
       ```
    2. A developer opens this repository in VSCode with the npm Intellisense extension enabled.
    3. The extension (via the `getNpmPackages` function in `provide.ts`) parses package.json and extracts the dependency names without sanitization.
    4. When the developer triggers the auto import command (via the command palette), the extension constructs an import statement in either ES6 or CommonJS style by directly interpolating the dependency name into a template string (see `command-import.ts`).
    5. The generated import statement contains the attack payload (for example,
       ```javascript
       import {} from '"; process.exit();//'
       ```
       if ES6 is enabled) which can disrupt the developer’s code or lead to further injection issues if later processed.

  - **Impact:**
    The unsanitized dependency name is injected directly into source code. This can cause arbitrary code fragments to be inserted into developer files, resulting in unexpected behavior or even potential code execution when the code is built or run. It compromises the integrity of the developer’s source code and can facilitate further exploitation steps.

  - **Vulnerability Rank:**
    High

  - **Currently Implemented Mitigations:**
    • No sanitization or validation is performed on dependency names after reading them from package.json.
    • The code uses `Object.keys(packageJson.dependencies || {})` which does no filtering of non-alphanumeric or special characters.

  - **Missing Mitigations:**
    • Validate and sanitize dependency names before using them to construct auto import statements.
    • Escape or remove characters that could interfere with the syntax of generated import statements.
    • Enforce a strict naming pattern that matches valid npm module name rules before accepting a dependency name.

  - **Preconditions:**
    • The attacker must control the workspace’s package.json file, for example by luring a user into opening a malicious repository.
    • The extension’s auto import command is triggered (with configuration options such as `importES6` enabled).

  - **Source Code Analysis:**
    1. In `provide.ts` the function `getNpmPackages` calls:
       ```javascript
       fsf.readJson(getPackageJson(state, config, fsf))
         .then(packageJson => [
             ...Object.keys(packageJson.dependencies || {}),
             ...Object.keys(config.scanDevDependencies ? packageJson.devDependencies || {} : {}),
             ...(config.showBuildInLibs ? getBuildInModules() : [])
         ])
         .catch(() => []);
       ```
       This produces an array of dependency names directly from the parsed JSON.
    2. In `command-import.ts`, when the import command is invoked, the dependency name appears (as `item.label`) in the following template without any escaping:
       ```javascript
       const statementES6 = `import {} from ${config.importQuotes}${item.label}${config.importQuotes}${config.importLinebreak}`;
       ```
       Similarly for CommonJS import formats.
    3. Because no filtering occurs on `item.label`, a name with quotes and special characters (e.g. `"; process.exit();//`) is injected verbatim into the output statement.

  - **Security Test Case:**
    1. **Setup:** Create a test workspace that contains a package.json with a dependency key that includes an injection payload, for example:
       ```json
       {
         "dependencies": {
           "\"; process.exit();//": "1.0.0"
         }
       }
       ```
    2. **Execution:**
       - Open the test workspace in VSCode with the npm Intellisense extension installed.
       - Trigger the auto import command (e.g. via the command palette, “npm-intellisense.import”).
    3. **Verification:**
       - Examine the auto import suggestion(s) to verify that the dependency name appears unsanitized.
       - Check that the generated import statement exactly contains the malicious payload (e.g.,
         ```javascript
         import {} from '"; process.exit();//'
         ```
         or equivalent in the require form).
       - The test passes if the malicious name is reflected verbatim in the output (indicating the vulnerability), and fails if proper escaping or filtering is implemented.

---

**• Vulnerability Name:** Symlink Traversal Leading to Sensitive File Disclosure

  - **Description:**
    The extension recursively scans the workspace and its subdirectories to provide auto import suggestions. It does so using functions like `readFilesFromDir` (in `util.ts`), which uses Node’s `readdir` and `stat` without checking whether a directory is a symbolic link. An attacker who controls a repository’s file structure may include a symbolic link that points to a directory outside the workspace (for example, a system folder with sensitive files). The extension will follow the symlink blindly and enumerate files beyond the workspace’s intended boundaries.

    **Steps to trigger:**
    1. In a malicious repository, the attacker creates a symlink (e.g., `./malicious_link`) that points to a sensitive system directory such as `/etc` on Linux (or another directory on Windows).
    2. The repository is opened in VSCode with the extension active.
    3. When the extension calls `readFilesFromDir` (and also indirectly through `getQuickPickItems` and `readFilesFromPackage`), it follows the symlink and reads files from the target directory.
    4. The discovered file paths are then included in the auto import suggestions, exposing names and possibly details of files outside the project.

  - **Impact:**
    An attacker may trick a developer into opening a repository with these malicious symlinks, thereby causing the extension to disclose sensitive file system information (including system configuration files or other sensitive documents) via the auto import dropdown. This information disclosure could assist in further targeted attacks or compromises.

  - **Vulnerability Rank:**
    High

  - **Currently Implemented Mitigations:**
    • The recursive file scan in `readFilesFromDir` excludes directories named exactly `'node_modules'` to avoid unnecessary scanning of dependency folders.
    • No explicit check exists to verify whether a scanned directory is a symlink or whether it lies within the workspace boundaries.

  - **Missing Mitigations:**
    • Validate and restrict scanned directory paths to ensure that they reside within the workspace root.
    • Before recursing into a directory, check (using methods such as `lstat` or by resolving the real path) whether the directory is a symbolic link—and if so, either ignore it or ensure its target is within an allowed boundary.
    • Implement safe traversal measures to prevent path traversal beyond the intended workspace.

  - **Preconditions:**
    • The attacker must be able to include or commit a symlink in the repository that points outside the workspace (e.g., via a malicious Git repository).
    • The extension’s auto import completion is invoked so that the recursive directory scan is executed.

  - **Source Code Analysis:**
    1. In `util.ts`, the function `readFilesFromDir` is defined as follows:
       ```javascript
       export const readFilesFromDir = (dir: string): Promise<Array<string>> => {
         return new Promise<Array<string>>((resolve, reject) => {
           let paths: Array<string> = [];
           readdir(dir, (error, files) => {
             Promise.all(
               files.map(file => {
                 const path = join(dir, file);

                 if (file === 'node_modules') {
                   return Promise.resolve([]);
                 }

                 return isDirectory(path)
                   .then(isDir => isDir ? readFilesFromDir(path) : Promise.resolve([path]));

               })
             )
               .then((filesPerDir: Array<any>) => {
                 resolve([].concat(...filesPerDir));
               })
               .catch(error => reject(error));
           });
         });
       }
       ```
    2. Notice that there is no check for whether `path` is a symbolic link or whether its resolved absolute path lies outside the intended workspace (root).
    3. As a result, if a symbolic link exists that points to an external directory, `isDirectory` (which calls `stat` and follows symlinks) returns true, and the function recurses into that directory—thereby reading and eventually returning files from outside the workspace.

  - **Security Test Case:**
    1. **Setup:** In a test workspace, create a symbolic link (for example, named `malicious_link`) inside the workspace root that points to a sensitive directory outside the workspace (e.g. on Unix: `/etc` or on Windows: `C:\Windows\System32`).
    2. **Execution:**
       - Open the test workspace in VSCode with the npm Intellisense extension enabled.
       - Trigger auto import completion (by invoking a command such as “npm-intellisense.import” or via code completion that calls `getQuickPickItems`).
    3. **Verification:**
       - Examine the list of completion items returned by the extension.
       - Check whether file paths from the external sensitive directory (e.g., entries with paths from `/etc`) are present in the suggestions.
       - The test passes (i.e. vulnerability is confirmed) if paths from the external directory appear; it fails if the extension correctly restricts file traversal to within the workspace.