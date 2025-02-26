### Vulnerability List

- Vulnerability Name: Path Traversal via `absolutePathTo` setting

- Description:
    1. An attacker can craft a malicious VS Code workspace configuration and trick a user into opening this workspace. This could be achieved by sending a user a link to a Git repository containing the malicious workspace configuration.
    2. The malicious workspace configuration, specifically the `.vscode/settings.json` file, will contain a setting to override the `path-intellisense.absolutePathTo` configuration. This setting will be set to a path outside the intended workspace, for example, pointing to the root directory or a parent directory using path traversal sequences like `"../../../"`.
    3. When the user opens a file within this workspace and triggers the Path Intellisense extension (e.g., by typing an import statement and then a forward slash to trigger path completion), the extension reads the workspace configuration, including the attacker-controlled `absolutePathTo` setting.
    4. The extension's path resolution logic uses the `absolutePathTo` setting as the root directory for resolving file paths.
    5. If the user, either intentionally or unintentionally, types path traversal characters (like `../` or `/`) in their import statement or path, the extension will interpret these relative to the attacker-specified `absolutePathTo` path.
    6. This allows the extension to suggest files and directories from locations outside the intended workspace directory, effectively enabling path traversal. If the attacker sets `absolutePathTo` to the root directory (`/`), the extension could potentially provide suggestions for any file on the user's file system, limited by the permissions of the VS Code process.

- Impact:
    - **Information Disclosure**: A successful path traversal attack can allow the attacker to list and potentially read files and directories outside the intended workspace scope. This could lead to the disclosure of sensitive information such as source code, configuration files, private keys, or personal documents, depending on the user's file system and the permissions of the VS Code process.
    - **Further Exploitation**: While the extension itself might not directly execute code, the information disclosed could be used to plan further attacks. For instance, exposed configuration files might contain credentials, or source code might reveal other vulnerabilities in related systems or applications.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None. The code does not sanitize or validate the `absolutePathTo` configuration value to prevent path traversal.

- Missing mitigations:
    - **Input Sanitization and Validation**: The extension should sanitize and validate the `absolutePathTo` configuration value. This could include:
        - Checking if the provided path is within the workspace directory.
        - Removing or escaping path traversal characters (e.g., `../`, `..\\`).
        - Using secure path manipulation functions that prevent traversal.
    - **Workspace Scope Enforcement**: The extension should enforce that path suggestions are always within the intended workspace scope, regardless of the `absolutePathTo` setting. This might involve resolving paths relative to the workspace root and preventing users from traversing above it.

- Preconditions:
    - The user must have the Path Intellisense extension installed and activated in VS Code.
    - The user must open a workspace that contains a malicious `.vscode/settings.json` file crafted by the attacker.
    - The `path-intellisense.absolutePathToWorkspace` setting must be enabled (or implicitly default to true).
    - The user must trigger path completion within a file in the malicious workspace, typically by typing an import statement and then initiating path suggestions (e.g., by typing `/`, `"`, or `'`).

- Source code analysis:
    - **`src/configuration/configuration.service.ts`**:
        - The `resolveAbsolutePathTo` function retrieves the `absolutePathTo` setting from the workspace configuration:
        ```typescript
        function resolveAbsolutePathTo(
          cfgPath?: string,
          workfolder?: vscode.WorkspaceFolder
        ): string | null {
          const rootPath = workfolder?.uri.path;

          return rootPath && cfgPath
            ? replaceWorkspaceFolderWithRootPath(cfgPath, rootPath)
            : null;
        }
        ```
        - This function then calls `replaceWorkspaceFolderWithRootPath` without any sanitization of `cfgPath`.
    - **`src/utils/file-utills.ts`**:
        - The `getPathOfFolderToLookupFiles` function uses the potentially attacker-controlled `rootPath` (which is derived from `absolutePathTo`) and combines it with user-provided `text` using `path.join`:
        ```typescript
        export function getPathOfFolderToLookupFiles(
          fileName: string,
          text: string | undefined,
          rootPath?: string, // <--- Attacker controlled rootPath
          mappings?: Mapping[]
        ): string {
          // ...
          rootFolder = isPathAbsolute ? rootPath || "" : path.dirname(fileName);
          pathEntered = normalizedText;
          // ...
          return path.join(rootFolder, pathEntered); // <--- path.join with attacker controlled rootFolder and user input
        }
        ```
        - `path.join` itself does not prevent path traversal if `rootFolder` is set to a directory allowing access outside the workspace and `pathEntered` contains traversal elements.
    - **Visualization:**

      ```
      User Input (in import statement) --> createContext --> JavaScriptProvider/NixProvider --> provideCompletionItems
                                                                  |
                                                                  V
      getConfiguration --> reads path-intellisense.absolutePathTo from .vscode/settings.json (ATTACKER CONTROLLED)
                                                                  |
                                                                  V
      resolveAbsolutePathTo --> replaceWorkspaceFolderWithRootPath (NO SANITIZATION) --> rootPath
                                                                  |
                                                                  V
      getPathOfFolderToLookupFiles(..., rootPath, ...) --> path.join(rootPath, user_path_input) --> file system path for suggestions
      ```

- Security test case:
    1. **Setup Malicious Workspace:**
        - Create a new directory, e.g., `path-traversal-test`.
        - Inside `path-traversal-test`, create a `.vscode` directory.
        - Inside `.vscode`, create a `settings.json` file with the following content:
          ```json
          {
            "path-intellisense.absolutePathTo": "${workspaceFolder}/../../../"
          }
          ```
        - Open the `path-traversal-test` directory as a workspace in VS Code.
        - Create a JavaScript file named `test.js` in the `path-traversal-test` workspace.
    2. **Trigger Path Completion:**
        - In `test.js`, type the following import statement: `import {} from "/../../` (without closing quote). This will trigger path completion after typing the last `/`.
    3. **Observe Completion Suggestions:**
        - Observe the completion suggestions provided by Path Intellisense.
        - **Expected Vulnerability**: The suggestions should include directories and files from outside the `path-traversal-test` workspace. If `absolutePathTo` is correctly traversed to the root directory, you might see top-level directories like `Applications`, `Users`, `etc`, etc., depending on your OS and file system structure. This confirms the path traversal vulnerability as the extension is now suggesting files from outside the intended workspace scope due to the maliciously configured `absolutePathTo` setting.
    4. **Mitigation Verification (After Mitigation is Implemented):**
        - After implementing sanitization and validation for `absolutePathTo`, repeat steps 1-3.
        - **Expected Mitigation**: The completion suggestions should now be restricted to files and directories within the `path-traversal-test` workspace, or a safe, predefined scope. Suggestions from outside the workspace (e.g., from the root directory or parent directories) should no longer be presented, indicating that the path traversal vulnerability has been successfully mitigated.