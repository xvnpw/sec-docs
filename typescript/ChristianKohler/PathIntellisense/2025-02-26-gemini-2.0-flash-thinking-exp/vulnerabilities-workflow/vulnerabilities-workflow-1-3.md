### Vulnerability List

- Vulnerability Name: Information Disclosure via Malicious Workspace Mapping/absolutePathTo

- Description:
    1. An attacker opens a VSCode workspace.
    2. The attacker configures the `path-intellisense.mappings` setting in the workspace settings to map a key, for example `/sensitive`, to an absolute path outside the workspace, such as `/etc/`. Alternatively, the attacker sets `absolutePathTo` to `/etc/` and `absolutePathToWorkspace` to `false`.
    3. The attacker opens a file within the workspace (e.g., a JavaScript file).
    4. In the opened file, the attacker triggers path completion by typing an import statement starting with the mapped key or an absolute path if `absolutePathToWorkspace` is false, for example: `import {} from "/sensitive/"` or `import {} from "/"` if `absolutePathTo` is set to `/etc/` and `absolutePathToWorkspace` is false.
    5. The Path Intellisense extension uses the malicious mapping or `absolutePathTo` configuration to resolve the path. This results in attempting to list the directory specified in the mapping or `absolutePathTo` (e.g., `/etc/`).
    6. The completion suggestions provided by the extension will now include files and folders from the mapped directory (e.g., `/etc/`). If the attacker can view these suggestions, they can potentially gain knowledge of the file structure and filenames within the sensitive directory, leading to information disclosure.

- Impact:
    Information disclosure. An attacker can potentially list files and folders from arbitrary locations on the file system that the VS Code process has access to. This could expose sensitive information such as system configuration files, application secrets, or user data, depending on the configured mapping or `absolutePathTo` and the file system permissions.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    No specific mitigations are implemented in the project to prevent listing of directories outside the workspace or restrict user-defined mappings.

- Missing Mitigations:
    - Input validation and sanitization for user-provided mappings and the `absolutePathTo` setting. The extension should validate that these paths are within the workspace or explicitly allowed directories.
    - Restrict file system access operations (`vscode.workspace.fs.readDirectory`, `vscode.workspace.fs.stat`) to the workspace folder by default. If access outside the workspace is necessary, implement strict controls and user consent mechanisms.
    - Implement a warning mechanism to inform users about the security risks associated with using absolute paths and custom mappings, especially when pointing outside the workspace.
    - Consider using VS Code's security context and APIs to ensure that file system operations are performed with the appropriate permissions and restrictions.

- Preconditions:
    - The attacker must have the ability to configure workspace settings in VS Code. This is typically possible if the attacker can open a workspace and modify its settings (e.g., if they can contribute to a shared workspace or are using their own).
    - The user must have the Path Intellisense extension installed and activated in VS Code.
    - The user must trigger path completion within a workspace that has been configured with malicious mappings or `absolutePathTo` settings.

- Source Code Analysis:
    1. `src/configuration/configuration.service.ts`: The `getConfiguration` function retrieves configuration settings, including `path-intellisense.mappings` and `path-intellisense.absolutePathTo`, from the VS Code workspace configuration.
    2. `src/utils/file-utills.ts`: The `getPathOfFolderToLookupFiles` function utilizes these mappings and `absolutePathTo` settings to determine the directory path for file lookup. Specifically, if a mapping is found that matches the beginning of the input path string, the `rootFolder` is set to the mapped `value`. If `absolutePathToWorkspace` is `false` and the path starts with a `/`, `rootFolder` becomes the configured `absolutePathTo` or the disk root if `absolutePathTo` is not set.
    3. `src/utils/file-utills.ts`: The `getChildrenOfPath` function uses `vscode.workspace.fs.readDirectory(vscode.Uri.file(path))` to read the contents of the directory determined in the previous steps. The `path` variable here is directly derived from user configurations (`mappings`, `absolutePathTo`).
    4. `src/providers/javascript/javascript.provider.ts` and `src/providers/nixos/nixos.provider.ts`: These provider files use `getConfiguration`, `createContext`, `getPathOfFolderToLookupFiles`, and `getChildrenOfPath` in their `provide` functions to generate completion items based on the file system content at the resolved path.
    ```mermaid
    graph LR
        subgraph Configuration Loading
            A[getConfiguration (configuration.service.ts)] --> B(Read workspace config);
            B --> C{Extract mappings, absolutePathTo};
        end

        subgraph Path Resolution
            C --> D[getPathOfFolderToLookupFiles (file-utills.ts)];
            D --> E{Use mappings/absolutePathTo as rootFolder};
            E --> F[Construct lookup path];
        end

        subgraph File System Access
            F --> G[getChildrenOfPath (file-utills.ts)];
            G --> H(vscode.workspace.fs.readDirectory);
            H --> I[File/Folder list];
        end

        subgraph Completion Items
            I --> J[JavascriptProvider/NixosProvider];
            J --> K[createCompletionItem];
            K --> L[Provide Completion Items];
        end
    ```

- Security Test Case:
    1. Create a new VS Code workspace and open it.
    2. Create a workspace settings file at `.vscode/settings.json` with the following JSON content to configure a malicious mapping:
       ```json
       {
           "path-intellisense.mappings": {
               "/sensitive": "/etc"
           },
           "path-intellisense.showOnAbsoluteSlash": true
       }
       ```
    3. Create a new JavaScript file named `test.js` in the root of the workspace.
    4. Open `test.js` and insert the following line: `import {} from "/sensitive/`; (ensure the cursor is immediately after the last `/` to trigger completion).
    5. Observe the completion suggestions that appear.
    6. **Expected Result:** The completion list should display a list of directories and files from the `/etc/` directory of the system, indicating that the malicious mapping is being used and the extension is listing content from outside the intended workspace scope. This confirms the information disclosure vulnerability.