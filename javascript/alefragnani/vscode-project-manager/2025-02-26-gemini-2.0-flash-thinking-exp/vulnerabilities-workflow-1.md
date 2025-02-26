## Vulnerability List

### Arbitrary File Access via Misconfigured `projectsLocation` Setting

**Vulnerability Name:** Arbitrary File Access via Misconfigured `projectsLocation` Setting

**Description:**
1. An attacker can modify the user or workspace configuration setting `projectManager.projectsLocation`. This could be achieved if the attacker has access to the user's settings file, or in shared environments if user settings are not properly isolated.
2. The attacker sets `projectManager.projectsLocation` to an arbitrary directory path outside of the intended application storage, potentially using relative paths like `"../../../sensitive-data"` or absolute paths like `/tmp` or `C:\Windows`.
3. The extension retrieves this user-provided path from the configuration.
4. When the extension needs to access the `projects.json` file (for example, to edit projects, list projects, or save project data), it constructs the full path by joining the user-provided `projectsLocation` with the fixed filename `projects.json` using `path.join` and `PathUtils.expandHomePath`.
5. Due to the lack of validation or sanitization of the `projectsLocation` setting, the resulting file path can point to an arbitrary location on the user's file system.
6. The extension then performs file system operations (read, write, watch) at this attacker-controlled location, potentially leading to arbitrary file access.

**Impact:**
This vulnerability can lead to both reading and writing arbitrary files on the user's system, depending on file system permissions.
- **Reading:** An attacker could read sensitive files by setting `projectsLocation` to a directory containing such files. When the extension tries to read `projects.json`, it would read the file at the attacker-specified location, potentially disclosing sensitive data if a symbolic link or a specially crafted file is placed at that location with the name `projects.json`.
- **Writing:** If the attacker has write permissions in the target directory, they could overwrite critical system or configuration files by manipulating the `projects.json` file through the extension's file operations. This could lead to further system compromise or denial of service.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
None. The extension retrieves the `projectsLocation` setting and directly uses it to construct the path to the `projects.json` file without any validation or sanitization beyond simple home path expansion. The code uses `path.join` and `PathUtils.expandHomePath` but does not restrict or validate the resulting path.

**Missing Mitigations:**
- **Input validation and sanitization:** The extension should validate the `projectManager.projectsLocation` setting.
- **Path restriction:** Restrict the `projectsLocation` to a predefined safe location, such as within the user's VS Code settings storage or a dedicated application data folder.
- **Path canonicalization:** Canonicalize and normalize the path to prevent path traversal via techniques like symbolic links or `..`.
- **Secure file operations:** Implement secure file system operations that validate and sanitize paths before accessing files.

**Preconditions:**
- An attacker must be able to modify the user or workspace settings, specifically the `projectManager.projectsLocation` setting. This could occur in scenarios where:
    - The attacker has direct access to the user's settings file.
    - The application is used in a shared or remote environment where user settings are not properly isolated.
    - Another vulnerability exists that allows settings manipulation.
    - The user can be socially engineered into importing malicious settings.

**Source Code Analysis:**
- In `src/extension.ts`, the `getProjectFilePath()` function is responsible for determining the location of the `projects.json` file:

```typescript
function getProjectFilePath() {
    let projectFile: string;
    const projectsLocation: string = vscode.workspace.getConfiguration("projectManager").get<string>("projectsLocation");
    if (projectsLocation !== "") {
        projectFile = path.join(PathUtils.expandHomePath(projectsLocation), PROJECTS_FILE);
    } else {
        projectFile = PathUtils.getFilePathFromAppData(PROJECTS_FILE);
    }
    return projectFile;
}
```

**Step-by-step analysis:**
1. `vscode.workspace.getConfiguration("projectManager").get<string>("projectsLocation")`: This line retrieves the value of the `projectManager.projectsLocation` setting from the VS Code configuration. This value is directly controlled by the user through VS Code settings.
2. `PathUtils.expandHomePath(projectsLocation)`: This expands the home directory shortcut `~` or environment variables like `$HOME` in the provided path. While useful, this does not prevent path traversal or restrict the path to a safe location.
3. `path.join(PathUtils.expandHomePath(projectsLocation), PROJECTS_FILE)`: This uses the `path.join` function to combine the expanded `projectsLocation` with the fixed filename `PROJECTS_FILE` (which is likely `projects.json`).  Critically, `path.join` itself does not sanitize or validate the path. If `projectsLocation` is an absolute path like `/etc` or `C:\Windows`, `path.join` will simply concatenate them, resulting in a path like `/etc/projects.json` or `C:\Windows\projects.json`.
4. **Vulnerability:** The lack of any validation after retrieving `projectsLocation` allows an attacker to control where the extension attempts to read and write the `projects.json` file. The extension proceeds to use `projectFile` in file system operations without ensuring it points to an intended and safe location.

**Security Test Case:**
1. **Open VS Code User Settings (JSON):** Open the VS Code settings editor and switch to the JSON view for user settings.
2. **Set Malicious `projectsLocation`:** Add or modify the `projectManager.projectsLocation` setting to point to a sensitive or arbitrary directory. For example:
   ```json
   "projectManager.projectsLocation": "/tmp"  // Linux/macOS
   // or
   "projectManager.projectsLocation": "C:\\Temp" // Windows
   // or for more sensitive location (exercise caution and understand permissions):
   "projectManager.projectsLocation": "/etc"   // Linux/macOS (read-only test recommended)
   // or
   "projectManager.projectsLocation": "C:\\Windows" // Windows (read-only test recommended, requires admin for writes)
   ```
   **Caution:** Testing with `/etc` or `C:\Windows` should be done carefully and ideally in a controlled test environment to avoid unintended system modifications. Focus on read operations first to verify the vulnerability without attempting to write to protected system directories unless you fully understand the implications and have appropriate permissions.
3. **Reload VS Code:** Reload the VS Code window to ensure the new setting is applied.
4. **Execute "Edit Projects" Command:** Open the Command Palette (Ctrl+Shift+P or Cmd+Shift+P) and execute the command "Project Manager: Edit Projects".
5. **Observe File Path:** Observe the file path of the opened `projects.json` file. It should now be located in the directory you specified in `projectsLocation` (e.g., `/tmp/projects.json` or `C:\Temp\projects.json`), instead of the expected application data directory. This confirms path traversal.
6. **Attempt File Operations (Read/Write):**
   - **Read Test:** Verify that the extension successfully reads (and potentially displays) the content of `projects.json` from the specified location. If you used `/etc`, and there's a `projects.json` (unlikely, but possible), its content might be displayed. If `/tmp`, an empty or newly created `projects.json` might be opened.
   - **Write Test (Exercise Caution):** Make a change in the opened `projects.json` editor (e.g., add a new project) and save the file. Check if a `projects.json` file is created or modified in the directory you specified in `projectsLocation` (e.g., `/tmp`). If you used a protected directory like `/etc` or `C:\Windows`, write operations might fail due to permissions, but the attempt itself demonstrates the vulnerability.
7. **Expected Result:** The extension will attempt to read and potentially write the `projects.json` file in the user-specified directory, demonstrating that the `projectManager.projectsLocation` setting allows controlling the file path and thus enables arbitrary file access.


### Unvalidated Project Path Leading to Arbitrary Folder Access

**Vulnerability Name:** Unvalidated Project Path Leading to Arbitrary Folder Access

**Description:**
1. An attacker gains the ability to modify the `projects.json` file. This could be achieved through local file access, or by crafting a malicious workspace file that includes a modified `projects.json`.
2. Within the `projects.json` file, the attacker modifies the `rootPath` property of a saved project entry. The attacker sets this `rootPath` to point to an arbitrary directory on the file system, potentially a sensitive system directory (e.g., `/etc`, `/var/log`, `C:\Windows`).
3. The user, at a later time, uses the Project Manager extension to list and open projects.
4. The extension reads the project data from `projects.json`, including the attacker-modified `rootPath`.
5. When the user selects the malicious project to open, the extension uses the stored `rootPath` to construct a URI.
6. The extension then calls the VS Code command `vscode.openFolder` with this URI, instructing VS Code to open the folder specified by the attacker-controlled `rootPath`.
7. VS Code opens the arbitrary folder specified by the attacker.

**Impact:**
This vulnerability allows an attacker to force a user to open arbitrary folders within VS Code.
- **Information Disclosure:** In a remote or shared environment, an attacker can trick a user into opening sensitive directories, potentially revealing file system structure and file names.
- **Local Exploitation:** By forcing the user to open folders containing malicious files (e.g., scripts, executables), the attacker could potentially leverage further vulnerabilities or trick the user into executing malicious code within the context of VS Code or the opened folder.
- **Denial of Service/Confusion:** Opening unexpected or system-critical folders could lead to user confusion, accidental modification of system files (if write access is available), or performance issues if large or numerous files are loaded.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- **Path Existence Check:** The project picking UI in `src/quickpick/projectsPicker.ts` checks if the supplied project path exists on disk using `fs.existsSync` before allowing project selection.
- **No Path Validation for Safety:** However, there is no validation to ensure that the path is within a safe or expected area. The existence check only verifies that the path points to a valid location, not that it is a safe or intended location.

**Missing Mitigations:**
- **Input Validation and Sanitization:** Project paths loaded from `projects.json` should undergo validation and sanitization.
- **Path Normalization and Canonicalization:** Paths should be normalized and canonicalized to prevent bypasses using path manipulation techniques.
- **Restricted Base Directory:** Implement a check to ensure that project paths fall within a restricted base directory or a set of trusted base directories. Any path outside these allowed directories should be rejected.
- **User Confirmation/Warning:** Before opening a folder, especially if it's outside a typical project directory, a confirmation dialog or warning could be displayed to the user, highlighting the unusual folder location and asking for explicit permission to open it.

**Preconditions:**
- An attacker must be able to modify the `projects.json` file. This can be achieved if:
    - The attacker has local access to the user's file system.
    - The user loads a workspace that contains a maliciously crafted `projects.json` file.
    - Another vulnerability allows modification of the `projects.json` file (e.g., the `projectsLocation` vulnerability described above could be a vector to write to a malicious `projects.json`).

**Source Code Analysis:**
- In `src/extension.ts`, the command `_projectManager.open` is responsible for opening projects:

```typescript
vscode.commands.registerCommand("_projectManager.open", async (projectPath: string, projectName: string, profile: string) => {
    const uri = buildProjectUri(projectPath);
    if (!await canSwitchOnActiveWindow(CommandLocation.SideBar)) {
        return;
    }
    vscode.commands.executeCommand("vscode.openFolder", uri, { forceProfile: profile, forceNewWindow: false } )
        .then(
            value => ({}),
            value => vscode.window.showInformationMessage(l10n.t("Could not open the project!"))
        );
});
```

**Step-by-step analysis:**
1. `vscode.commands.registerCommand("_projectManager.open", ...)`: This registers the command `_projectManager.open` which is used to open a project. It receives `projectPath`, `projectName`, and `profile` as arguments. Importantly, `projectPath` originates from the `projects.json` file.
2. `const uri = buildProjectUri(projectPath);`: This line calls `buildProjectUri` to convert the `projectPath` (which is a string from `projects.json`) into a URI.  While `buildProjectUri` might perform basic URI construction, it does not validate the *path* itself for security.
3. `vscode.commands.executeCommand("vscode.openFolder", uri, ...)`: This is the crucial line. It calls the core VS Code command `vscode.openFolder` and passes the constructed `uri`.  VS Code will then attempt to open the folder represented by this URI.
4. **Vulnerability:** The `projectPath` is taken directly from the `projects.json` file, which is user-modifiable (or attacker-modifiable). There is no sanitization or validation of this `projectPath` before it is passed to `vscode.openFolder`.  This allows an attacker to inject an arbitrary file system path into the `projects.json` and force the user to open any folder they choose when the user selects that project.

**Security Test Case:**
1. **Modify `projects.json` (Simulate Attacker):**
   - Locate your `projects.json` file. Its location depends on your OS and `projectsLocation` setting, but typically it's within your VS Code user data directory or the location specified by `projectsLocation`.
   - Open `projects.json` in a text editor.
   - Find an existing project entry or create a new one.
   - Modify the `"rootPath"` property of a project to point to a sensitive directory. For example:
     ```json
     {
         "name": "Malicious Project",
         "rootPath": "/etc"  // Linux/macOS
         // or
         "rootPath": "C:\\Windows" // Windows
     }
     ```
     **Caution:** Use `/etc` or `C:\Windows` for testing purposes only and be aware of potential side effects. It's safer to test with less critical directories first, like `/tmp` or `C:\Temp`.
2. **Open VS Code.**
3. **List Projects to Open:** Open the Command Palette and execute "Project Manager: List Projects to Open".
4. **Select Malicious Project:** In the project list, select the project you modified to have the malicious `rootPath` (e.g., "Malicious Project").
5. **Observe Opened Folder:** Observe which folder VS Code opens. It should open the folder you specified in the `rootPath` (e.g., `/etc` or `C:\Windows`), demonstrating that the extension has instructed VS Code to open an arbitrary folder.
6. **Verify Folder Contents (If Possible):** If VS Code successfully opens the folder, you might be able to browse its contents within VS Code, confirming that arbitrary folder access has been achieved.  Permissions might restrict access to some system directories, but even attempting to open them is a demonstration of the vulnerability.
7. **Expected Result:** VS Code will open the folder specified in the malicious `rootPath` from `projects.json`, confirming that the unvalidated project path allows arbitrary folder access.