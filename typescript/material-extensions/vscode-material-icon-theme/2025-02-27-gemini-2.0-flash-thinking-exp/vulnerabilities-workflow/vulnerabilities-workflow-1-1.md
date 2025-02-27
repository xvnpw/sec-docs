### Vulnerability List

- Vulnerability Name: Directory Traversal in Custom Icon Paths

- Description:
  1. An attacker can modify the user settings for the Material Icon Theme to include a malicious custom icon association.
  2. In the user settings, the attacker provides a file association with an icon path that uses directory traversal sequences (e.g., `../../`) to point outside the intended `extensions` directory within the `.vscode` folder.
  3. When VS Code attempts to display an icon based on this association, the extension uses the provided path to load the SVG icon.
  4. Due to insufficient validation, the extension might traverse the directory structure outside the intended scope and attempt to read arbitrary files from the user's file system, depending on VS Code's file access permissions in extensions.
  5. If VS Code extension process has enough permissions, this could lead to information disclosure if the attacker crafts a path to a sensitive file like `/etc/passwd` (on Linux/macOS) or sensitive configuration files.

- Impact:
  Information Disclosure. An attacker could potentially read arbitrary files from the user's system if the VS Code extension process has sufficient file system permissions. This could expose sensitive information like configuration files, credentials, or other user data, depending on the attacker's path and the system's file permissions.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  None. The code only checks if the path starts with `./` or `../` to identify custom paths but doesn't validate if the path stays within the intended `extensions` directory.

- Missing Mitigations:
  - Path validation: Implement robust path validation to ensure that custom icon paths are strictly limited to a specific directory within the extension's context (e.g., within the `extensions` directory of the `.vscode` folder). Use path canonicalization to resolve symbolic links and prevent traversal attempts.
  - Input sanitization: Sanitize user-provided paths to remove or neutralize directory traversal sequences like `../` and `..\/`.
  - Sandboxing or isolation: Ensure the extension operates with minimal file system permissions to limit the impact of potential directory traversal vulnerabilities. VS Code extension security policies should be reviewed and applied.

- Preconditions:
  1. The user must have the Material Icon Theme extension installed in VS Code.
  2. The attacker needs to be able to influence the user to add a malicious configuration to their VS Code `settings.json` file. This could be achieved through social engineering, phishing, or by compromising a workspace configuration that the user loads.

- Source Code Analysis:
  1. File: `/code/src/core/helpers/customIconPaths.ts`
  ```typescript
  import { dirname } from 'node:path';
  import { resolvePath } from './resolvePath';

  export const getCustomIconPaths = (
    filesAssociations: Record<string, string> = {}
  ) => {
    return Object.values(filesAssociations)
      .filter((fileName) => fileName.match(/^[.\/]+/)) // <- custom dirs have a relative path to the dist folder
      .map((fileName) => dirname(resolvePath(fileName)));
  };
  ```
  - The `getCustomIconPaths` function extracts custom icon paths from `filesAssociations`.
  - It uses a regex `fileName.match(/^[.\/]+/)` to filter paths that start with `./` or `../`, considering them as relative paths.
  - It then uses `dirname(resolvePath(fileName))` to resolve the path relative to the extension's `dist` folder.
  - **Vulnerability:** The validation is insufficient. It only checks if the path *starts* with `.` or `/` but does not prevent directory traversal beyond the intended directory. It does not enforce that the resolved path stays within the allowed `.vscode/extensions` directory.

- Security Test Case:
  1. Open VS Code with the Material Icon Theme extension activated.
  2. Open the User Settings (JSON) in VS Code (`Ctrl+Shift+P` or `Cmd+Shift+P` and type "Open Settings (JSON)").
  3. Add the following configuration to your `settings.json` to create a malicious file association (replace `/path/to/icon` with `..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/etc/passwd` for Linux/macOS or similar sensitive file for Windows like `..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/`..`/Windows/win.ini`):
     ```json
     "material-icon-theme.files.associations": {
         "test_file_traversal.txt": "../../../../../../../../../../../../../../etc/passwd"
     }
     ```
  4. Create a new file named `test_file_traversal.txt` in your workspace.
  5. Observe if VS Code attempts to load an icon. In a vulnerable scenario, the extension might try to read the `/etc/passwd` file (or `win.ini` on Windows) when rendering the icon for `test_file_traversal.txt`.
  6. **Expected Result (Vulnerable):** If the extension is vulnerable, and if VS Code extension process has sufficient permissions, no error might be immediately visible in VS Code UI, but in an actual attack scenario, the extension would have attempted to read the contents of `/etc/passwd` or `win.ini`. You might observe errors in the extension's logs if logging is enabled, or by monitoring file system access.
  7. **Expected Result (Mitigated):** If the vulnerability is mitigated, the extension should either:
     - Refuse to load the custom icon and potentially log an error due to invalid path.
     - Successfully load a default icon without attempting directory traversal.
     - Throw an error and prevent the extension from activating or functioning correctly if secure path handling is enforced strictly during extension initialization.