- Vulnerability Name: Path Traversal via Malicious Workspace Mappings
- Description:
    1. An attacker crafts a malicious VS Code workspace configuration. This configuration includes custom path mappings for the Path Intellisense extension.
    2. The attacker sets up a mapping that points to a sensitive directory on the user's file system, for example, mapping a key like `/sensitive-files` to the root directory `/` or a user's home directory.
    3. The attacker distributes this malicious workspace (e.g., via a public repository or by tricking a user into opening it).
    4. A victim user opens the malicious workspace in VS Code with the Path Intellisense extension installed.
    5. When the user starts typing a path in a supported file type (like JavaScript, Nix, or any file due to the default provider) that begins with the malicious mapping key (e.g., `/sensitive-files/`), the Path Intellisense extension uses the configured mapping.
    6. The extension resolves the path based on the malicious mapping, effectively changing the root directory for path completion to the attacker-specified sensitive directory.
    7. The extension then reads the directory contents of the sensitive location and suggests files and folders from that directory in the autocompletion list.
    8. This allows the attacker to indirectly browse the victim's file system through the Path Intellisense extension and potentially discover sensitive file paths and names.
- Impact:
    - Information Disclosure: A malicious workspace can be crafted to expose the file structure and filenames from sensitive directories on a victim's system. This can aid in further attacks by revealing configuration files, internal scripts, or other sensitive information.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - None: The extension currently allows users to define arbitrary mappings without restrictions or validation on the target paths.
- Missing mitigations:
    - Input validation and sanitization for user-defined mappings to ensure that they are within safe boundaries (e.g., within the workspace).
    - Restricting mappings to be relative to the workspace folder or a predefined set of allowed directories.
    - Displaying a warning to the user when a mapping points outside the current workspace, especially to sensitive areas like the root directory or home directories.
    - Implementing a permission model for mappings, potentially requiring user confirmation before resolving paths outside the workspace.
- Preconditions:
    - The victim user must have the Path Intellisense extension installed in VS Code.
    - The victim user must open a malicious VS Code workspace that contains crafted settings for the Path Intellisense extension.
    - The malicious workspace settings must define a path mapping that points to a sensitive directory.
    - The user must trigger path completion within a file type supported by the extension (JavaScript, Nix, or any file due to the default provider) and use the malicious mapping prefix.
- Source code analysis:
    1. `src/configuration/configuration.service.ts`: The `getConfiguration` function reads the `path-intellisense.mappings` configuration from VS Code settings:
    ```typescript
    const cfgExtension = getConfig("path-intellisense");
    const mappings = await getMappings(cfgExtension, workspaceFolder);
    ```
    2. `src/configuration/configuration.service.ts`: The `getMappings` function retrieves mappings and passes them to `replaceWorkspaceFolder`:
    ```typescript
    async function getMappings(
      configuration: vscode.WorkspaceConfiguration,
      workfolder?: vscode.WorkspaceFolder
    ): Promise<Mapping[]> {
      const mappings = parseMappings(configuration["mappings"]);
      // ...
      const allMappings = [...mappings, ...tsConfigMappings];
      return replaceWorkspaceFolder(allMappings, workfolder);
    }
    ```
    3. `src/configuration/mapping.service.ts`: The `parseMappings` function directly parses the user-provided mappings without validation:
    ```typescript
    export function parseMappings(mappings: { [key: string]: string }): Mapping[] {
      return Object.entries(mappings).map(([key, value]) => ({ key, value }));
    }
    ```
    4. `src/utils/file-utills.ts`: The `getPathOfFolderToLookupFiles` function uses these mappings. If a typed path starts with a mapping key, it uses the mapping's value as the root folder for file lookup:
    ```typescript
    export function getPathOfFolderToLookupFiles(
      fileName: string,
      text: string | undefined,
      rootPath?: string,
      mappings?: Mapping[]
    ): string {
      // ...
      const mapping =
        mappings &&
        mappings.reduce((prev: any, curr: any) => {
          return (
            prev || (normalizedText.startsWith(path.normalize(curr.key)) && curr)
          );
        }, undefined);

      let rootFolder, pathEntered;
      if (mapping) {
        rootFolder = mapping.value; // Mapping value is directly used as rootFolder
        pathEntered = normalizedText.slice(
          path.normalize(mapping.key).length,
          normalizedText.length
        );
      } else {
        rootFolder = isPathAbsolute ? rootPath || "" : path.dirname(fileName);
        pathEntered = normalizedText;
      }

      return path.join(rootFolder, pathEntered); // Path is joined with the potentially malicious rootFolder
    }
    ```
    5. `src/utils/file-utills.ts`:  `getChildrenOfPath` then reads the directory at the potentially attacker-controlled path:
    ```typescript
    export async function getChildrenOfPath(
      path: string, // Path from getPathOfFolderToLookupFiles
      showHiddenFiles: boolean,
      filesExclude: FilesExclude
    ) {
      try {
        const filesTubles = await vscode.workspace.fs.readDirectory( // Reads directory based on the path
          vscode.Uri.file(path)
        );
        // ...
      } catch (error) {
        return [];
      }
    }
    ```
    **Visualization:**

    ```mermaid
    graph LR
        A[User types path with mapping prefix] --> B(getPathOfFolderToLookupFiles);
        B --> C{Mapping found?};
        C -- Yes --> D[Use mapping.value as rootFolder];
        C -- No --> E[Determine rootFolder based on workspace];
        D --> F[Join rootFolder and typed path];
        E --> F;
        F --> G(getChildrenOfPath);
        G --> H[vscode.workspace.fs.readDirectory(path)];
        H --> I[Return file suggestions from potentially sensitive path];
    ```

- Security test case:
    1. Create a new directory named `path-intellisense-test-workspace`.
    2. Inside `path-intellisense-test-workspace`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content. This configuration maps `/sensitive` to the root directory `/`:
    ```json
    {
        "path-intellisense.mappings": {
            "/sensitive": "/"
        }
    }
    ```
    4. Inside `path-intellisense-test-workspace`, create a file named `test.js` with the following content:
    ```javascript
    import {} from "/sensitive/et
    ```
    5. Open VS Code and open the `path-intellisense-test-workspace` folder.
    6. Open the `test.js` file.
    7. Place the cursor after `/sensitive/et` in the import statement.
    8. Trigger code completion (e.g., by pressing Ctrl+Space or just waiting for it to appear).
    9. Observe the completion suggestions. Verify that the suggestions include files and directories from the root directory `/` (like `etc`, `usr`, `var`, etc.), which are outside the workspace. This confirms that the mapping is working and allows access outside the intended workspace scope.