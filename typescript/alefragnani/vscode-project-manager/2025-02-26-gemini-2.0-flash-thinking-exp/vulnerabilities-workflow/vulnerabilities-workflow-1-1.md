## Vulnerability List

### 1. Project Settings File Path Manipulation

* Vulnerability Name: Project Settings File Path Manipulation
* Description:
    1. The Project Manager extension allows users to configure the location of the `projects.json` file using the `projectManager.projectsLocation` setting.
    2. An attacker who can control this setting could potentially manipulate the path where the extension reads and writes the `projects.json` file.
    3. By setting `projectManager.projectsLocation` to a path containing directory traversal sequences (e.g., `../`, `..\\`), an attacker might be able to redirect the extension's file operations to locations outside the intended configuration directory.
    4. This could lead to unintended read or write operations in the file system, potentially allowing an attacker to read or modify files they should not have access to, depending on the file system permissions and how the path is used in the code.
    5. Furthermore, when the user opens a project using the Project Manager, the `projectsPicker.ts` module reads the project path from the potentially manipulated `projects.json` file and uses `PathUtils.normalizePath()` to process it before opening the project. If `projects.json` is compromised due to path manipulation, opening a project could lead to accessing files or directories outside the intended project scope, depending on how `PathUtils.normalizePath()` is implemented and how the project path is used in subsequent operations by VS Code's `vscode.openFolder` command.
* Impact:
    - **Information Disclosure (Medium):** An attacker might be able to read sensitive files if path traversal allows reading outside the intended directory and if sensitive files are located in the traversed paths. This is possible when the extension reads project paths from a manipulated `projects.json` and uses them to access files.
    - **Data Manipulation (Medium):** An attacker might be able to overwrite the `projects.json` file in an unintended location. While the direct impact on the extension's functionality might be limited, this could be a stepping stone for more complex attacks. If the attacker can manipulate the content of `projects.json` through path traversal, they might be able to inject malicious project paths. When these projects are opened, it could lead to further vulnerabilities, depending on how VS Code handles project paths and extensions interact with them.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None apparent from the provided files. The code uses `PathUtils.expandHomePath()` which handles `~` and `$home` but doesn't seem to sanitize against directory traversal sequences in `projectsLocation`.  `PathUtils.normalizePath()` is used in `quickpick/projectsPicker.ts`, but its implementation is not provided in the given files, and it's unclear if it provides sufficient sanitization against path traversal.
* Missing Mitigations:
    - **Path Sanitization:** The extension should sanitize the `projectManager.projectsLocation` setting and any project paths read from `projects.json` to prevent directory traversal attacks. This could involve:
        - Validating that the path is within an expected base directory.
        - Removing or normalizing directory traversal sequences from the path.
        - Using secure path manipulation functions that prevent traversal.
    - **Input Validation:** Implement strict validation on the `projectsLocation` setting and project paths in `projects.json` to ensure they conform to expected path formats and do not contain malicious characters or sequences.
* Preconditions:
    - The attacker must be able to modify the VS Code user settings, specifically the `projectManager.projectsLocation` setting. This is typically achievable if the attacker has access to the user's machine or through some form of settings injection if such a vulnerability exists in VS Code itself.
* Source Code Analysis:
    1. **File: `/code/src/extension.ts`**
    2. **Function: `getProjectFilePath()`**
    3. This function retrieves the `projectsLocation` setting:
       ```typescript
       const projectsLocation: string = vscode.workspace.getConfiguration("projectManager").get<string>("projectsLocation");
       ```
    4. It then constructs the path to `projects.json` by joining `projectsLocation` with `PROJECTS_FILE`:
       ```typescript
       if (projectsLocation !== "") {
           projectFile = path.join(PathUtils.expandHomePath(projectsLocation), PROJECTS_FILE);
       } else {
           projectFile = PathUtils.getFilePathFromAppData(PROJECTS_FILE);
       }
       ```
    5. **File: `/code/vscode-project-manager-core/src/utils/path.ts`**
    6. **Function: `expandHomePath(filepath: string)`**
    7. This function expands `~` and `$home` in the path, but it doesn't sanitize or validate against directory traversal sequences like `../`.
       ```typescript
       public static expandHomePath(filepath: string): string {
           if (!filepath) {
               return filepath;
           }

           if (filepath[0] === '~') {
               filepath = process.env.HOME + filepath.slice(1);
           }

           if (filepath.indexOf('$home') > -1) {
               filepath = filepath.replace('$home', process.env.HOME);
           }

           return filepath;
       }
       ```
    8. The `getProjectFilePath()` function in `/code/src/extension.ts` uses the potentially attacker-controlled path from settings without further sanitization when performing file operations (e.g., reading and writing `projects.json`).
    9. **File: `/code/src/quickpick/projectsPicker.ts`**
    10. **Function: `pickProjects()` and `openPickedProject()`**
    11. When a user picks a project, the `item.description` which represents the project root path, is processed by `PathUtils.normalizePath()`:
        ```typescript
        resolve(<Picked<Project>>{
            item: {
                name: item.label,
                rootPath: PathUtils.normalizePath(item.description),
                profile: item.profile,
            }, button: undefined
        });
        ```
    12. If `projects.json` is manipulated via the `projectManager.projectsLocation` vulnerability to contain malicious paths with traversal sequences, and `PathUtils.normalizePath()` does not sanitize these sequences, then opening such a project might lead to path traversal when VS Code handles the `vscode.openFolder` command with the potentially manipulated path.

* Security Test Case:
    1. Open VS Code.
    2. Go to Settings (JSON) and add or modify the `projectManager.projectsLocation` setting to point to a directory outside the intended configuration location using a path traversal sequence. For example, if the default configuration directory is `/home/user/.config/Code/User/`, set `projectManager.projectsLocation` to `"/tmp/../../.config/Code/User"`.  (Note: the target path should be chosen carefully to avoid system instability and respect OS path conventions. For testing, a safer approach would be to target a sub-directory within `/tmp` or similar temporary directory). A safer test value would be something like `"/tmp/test_project_manager_traversal"`.
    3. Open any folder in VS Code.
    4. Execute the command `Project Manager: Save Project`. Provide a project name and save it. This should save the `projects.json` file in the manipulated location.
    5. Modify the saved `projects.json` file (located in the manipulated path from step 2) and change the `rootPath` of one of the projects to a path outside the workspace using traversal sequences, for example, `"rootPath": "/tmp/../../../../etc/passwd"`.
    6. Execute the command `Project Manager: List Projects to Open`.
    7. Select the project you modified in step 5.
    8. Check if VS Code attempts to open the manipulated path (e.g., `/etc/passwd`). While VS Code might not directly open `/etc/passwd` as a workspace, observe if there are any unexpected file system access attempts or errors related to the manipulated path. For a more controlled test, you can target a path within `/tmp` that you can monitor for file access. For example, set `"rootPath": "/tmp/test_traversal_target/../../../../etc/passwd"` and monitor `/tmp/test_traversal_target` for access attempts.
    9. **Expected Result (Vulnerable):** VS Code attempts to open or access files in the manipulated path, indicating that path traversal is possible when opening projects from a manipulated `projects.json` file.
    10. **Expected Result (Mitigated):** VS Code either fails to open the project with the manipulated path or correctly sanitizes the path, preventing traversal and only attempting to open projects within expected boundaries.