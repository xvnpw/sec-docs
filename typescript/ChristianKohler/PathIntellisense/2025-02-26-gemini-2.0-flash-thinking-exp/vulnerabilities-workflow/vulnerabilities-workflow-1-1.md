### Vulnerability List:

- Vulnerability Name: Path Traversal via Malicious Workspace Mapping

- Description:
    1. An attacker can configure a malicious workspace mapping in VSCode settings for the Path Intellisense extension.
    2. This malicious mapping can contain path traversal characters (e.g., `../`) in the `value` field.
    3. When the extension resolves paths using these mappings, it will traverse outside the intended workspace directory.
    4. This allows the attacker to gain file path suggestions for directories and files outside the workspace, potentially exposing sensitive information about the file system structure and existence of files to an attacker observing the suggestions.

- Impact:
    - Information Disclosure: An attacker can potentially discover the existence of files and directories outside the intended workspace, including sensitive configuration files, source code, or data, by observing the path suggestions provided by the extension.
    - Increased Attack Surface: Knowledge of the file system structure outside the workspace can aid an attacker in planning further attacks, such as exploiting other vulnerabilities or gaining unauthorized access.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The extension currently does not perform any sanitization or validation on user-defined mapping paths.

- Missing Mitigations:
    - Input Validation: The extension should validate user-defined mapping paths to prevent path traversal sequences (e.g., `../`, `..\\`).
    - Path Sanitization: Sanitize the mapping `value` by resolving it against the workspace root and ensuring it stays within the workspace boundaries.
    - Restrict Path Resolution: Ensure that path resolution for mappings is limited to within the workspace directory and does not allow traversal to parent directories.

- Preconditions:
    - The attacker must have the ability to configure workspace settings for VSCode. In typical scenarios, this means the attacker needs to convince a developer to open a workspace with a malicious `.vscode/settings.json` file or to manually add a malicious mapping in their user settings that applies to the workspace.

- Source Code Analysis:
    1. **File: `/src/utils/file-utills.ts` Function: `getPathOfFolderToLookupFiles`**:
        ```typescript
        export function getPathOfFolderToLookupFiles(
          fileName: string,
          text: string | undefined,
          rootPath?: string,
          mappings?: Mapping[]
        ): string {
          // ...
          const mapping = // ... mapping is selected based on `text` and `mappings`
          // ...
          let rootFolder, pathEntered;
          if (mapping) {
            rootFolder = mapping.value; // Vulnerable point: mapping.value is directly used as rootFolder
            pathEntered = normalizedText.slice(
              path.normalize(mapping.key).length,
              normalizedText.length
            );
          } else {
            // ...
            rootFolder = isPathAbsolute ? rootPath || "" : path.dirname(fileName);
            pathEntered = normalizedText;
          }

          return path.join(rootFolder, pathEntered); // Vulnerable point: path.join with unsanitized rootFolder
        }
        ```
        - The `getPathOfFolderToLookupFiles` function calculates the path to lookup files for autocompletion.
        - If a mapping is used, the `mapping.value` from user configuration is directly assigned to `rootFolder`.
        - The function then uses `path.join(rootFolder, pathEntered)` to construct the final lookup path.
        - If `mapping.value` contains path traversal sequences, `path.join` will resolve them, potentially leading to path traversal outside the workspace.

    2. **File: `/src/configuration/configuration.service.ts` Function: `getMappings`**:
        ```typescript
        async function getMappings(
          configuration: vscode.WorkspaceConfiguration,
          workfolder?: vscode.WorkspaceFolder
        ): Promise<Mapping[]> {
          const mappings = parseMappings(configuration["mappings"]); // User mappings are parsed
          // ...
          return replaceWorkspaceFolder(allMappings, workfolder); // Workspace folder placeholder is replaced, but no path sanitization
        }
        ```
        - The `getMappings` function retrieves mappings from the configuration.
        - `parseMappings` simply converts the configuration object to an array of `Mapping` objects.
        - `replaceWorkspaceFolder` replaces workspace folder placeholders but does not sanitize path traversal sequences in the `value`.

    3. **File: `/src/configuration/mapping.service.ts` Function: `replaceWorkspaceFolderWithRootPath`**:
        ```typescript
        export function replaceWorkspaceFolderWithRootPath(
          value: string,
          rootPath: string
        ) {
          return value
            .replace("${workspaceRoot}", rootPath)
            .replace("${workspaceFolder}", rootPath); // Only placeholder replacement, no sanitization
        }
        ```
        - `replaceWorkspaceFolderWithRootPath` only replaces placeholders and does not perform any path sanitization to prevent traversal.

    **Visualization:**

    ```
    User Settings (Malicious Mapping):
    {
      "path-intellisense.mappings": {
        "malicious": "${workspaceFolder}/../sensitive-directory"
      }
    }

    getCodeCompletion() --> getPathOfFolderToLookupFiles(fileName, text, rootPath, mappings)
                                  |
                                  | mapping.value = "${workspaceFolder}/../sensitive-directory" (Unsanitized)
                                  |
                                  v
    path.join(rootFolder, pathEntered)  --> path.join("${workspaceFolder}/../sensitive-directory", "file.txt")
                                  |
                                  | Path Traversal to "${workspaceFolder}/../sensitive-directory/file.txt"
                                  v
    getChildrenOfPath(traversedPath) -->  Lists files in "${workspaceFolder}/../sensitive-directory"

    Completion Items include files from outside workspace!
    ```

- Security Test Case:
    1. Create a new VSCode workspace.
    2. Create a folder named `sensitive-directory` at the same level as your workspace root directory (i.e., parent directory of the workspace root).
    3. Inside `sensitive-directory`, create a file named `sensitive.txt` with some sensitive content.
    4. Inside the workspace root, create a file (e.g., `test.js`).
    5. Open the `test.js` file in VSCode editor.
    6. Open VSCode settings (File -> Preferences -> Settings -> Settings or Code -> Settings -> Settings).
    7. Go to Workspace settings and search for "path-intellisense mappings".
    8. Add a new mapping with:
        - Key: `sensitive`
        - Value: `${workspaceFolder}/../sensitive-directory`
    9. In `test.js`, type `import {} from "sensitive/` (or any other import statement and trigger character that activates path completion).
    10. Observe the completion suggestions.
    11. **Expected Result (Vulnerable):** The completion list will include `sensitive.txt` from the `sensitive-directory` which is located outside the workspace root, demonstrating path traversal.
    12. **Expected Result (Mitigated):** The completion list should only include files and directories within the workspace, and should not list `sensitive.txt` or any content from outside the workspace root when using the malicious mapping.