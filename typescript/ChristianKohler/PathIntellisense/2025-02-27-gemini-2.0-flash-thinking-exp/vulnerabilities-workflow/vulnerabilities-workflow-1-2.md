### Vulnerability List:

* Vulnerability Name: Path Traversal via Mappings Configuration
* Description:
    1. An attacker can configure malicious path mappings in the Path Intellisense extension settings.
    2. When the extension is activated and a user starts typing a path in a workspace file (e.g., in an import statement), the extension uses these mappings to resolve paths for autocompletion.
    3. By crafting a malicious mapping, such as mapping the root path "/" to the system's root directory "/", an attacker can trick the extension into resolving paths outside the intended workspace scope.
    4. For example, with a mapping like `{"/": "/"}`, if a user types `import "/etc/passwd"`, the extension, using `getPathOfFolderToLookupFiles`, will construct the path `/etc/passwd`.
    5. Subsequently, `getChildrenOfPath` will attempt to read the contents of this arbitrary path using `vscode.workspace.fs.readDirectory`.
    6. This can lead to the extension exposing files from outside the workspace, potentially including sensitive system files, if the VSCode process has the necessary file system permissions.
* Impact:
    - High: An attacker can potentially read arbitrary files from the user's file system, including sensitive information like configuration files, credentials, or source code outside the intended workspace. This is possible if the VSCode process running the extension has sufficient file system permissions to access the targeted files.
* Vulnerability Rank: High
* Currently implemented mitigations:
    - None: The current code does not implement any specific input validation or sanitization to prevent path traversal through mappings.
* Missing mitigations:
    - Input validation for mapping values: The extension should validate the values provided in the `path-intellisense.mappings` setting. It should ensure that the mapped paths are within the workspace or restrict them to a predefined set of allowed paths. Absolute paths should be handled with extreme caution.
    - Path sanitization: Before using the constructed path with `vscode.workspace.fs.readDirectory`, the extension should sanitize the path to prevent traversal outside the workspace. This could involve verifying that the resolved path remains within the workspace boundaries.
    - User warnings: The extension documentation and settings description should clearly warn users about the security risks associated with using absolute paths or mappings that could lead to path traversal.
* Preconditions:
    - The user must have the Path Intellisense extension installed in VSCode.
    - The attacker needs to be able to influence the user's VSCode settings, specifically the `path-intellisense.mappings` configuration. This could be achieved through social engineering, by providing a malicious workspace configuration, or if the user unknowingly imports settings from an untrusted source.
* Source code analysis:
    1. **`src/utils/file-utills.ts:getPathOfFolderToLookupFiles`**: This function is responsible for constructing the path used for file system lookup.
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
        rootFolder = mapping.value; // User-defined mapping value is used directly as rootFolder
        pathEntered = normalizedText.slice(
          path.normalize(mapping.key).length,
          normalizedText.length
        );
      } else {
        rootFolder = isPathAbsolute ? rootPath || "" : path.dirname(fileName); // rootPath can be from absolutePathTo setting (user-defined)
        pathEntered = normalizedText;
      }

      return path.join(rootFolder, pathEntered); // Path is constructed by joining rootFolder and pathEntered
    }
    ```
    - The `rootFolder` can be directly controlled by the user through mappings or the `absolutePathTo` setting.
    - `path.join` is used to combine `rootFolder` and user-provided `pathEntered`. While `path.join` itself is not directly vulnerable, if `rootFolder` is set to "/", and `pathEntered` is "../../../etc/passwd", it can still lead to path traversal. However, in this specific code, `pathEntered` is derived from the user's input text *after* the mapping key, so direct traversal injection via `pathEntered` is less straightforward in the context of mappings. The primary issue is that `rootFolder` from mappings can be an arbitrary path.

    2. **`src/utils/file-utills.ts:getChildrenOfPath`**: This function uses the path constructed by `getPathOfFolderToLookupFiles` to read directory contents.
    ```typescript
    export async function getChildrenOfPath(
      path: string,
      showHiddenFiles: boolean,
      filesExclude: FilesExclude
    ) {
      try {
        const filesTubles = await vscode.workspace.fs.readDirectory( // Uses path to read directory
          vscode.Uri.file(path)
        );
        // ...
      } catch (error) {
        return [];
      }
    }
    ```
    - `vscode.workspace.fs.readDirectory` is used with the potentially attacker-influenced `path`.

    3. **`src/configuration/configuration.service.ts:getMappings`**: This function loads mappings from the configuration.
    ```typescript
    async function getMappings(
      configuration: vscode.WorkspaceConfiguration,
      workfolder?: vscode.WorkspaceFolder
    ): Promise<Mapping[]> {
      const mappings = parseMappings(configuration["mappings"]); // Load mappings from configuration
      // ...
      return replaceWorkspaceFolder(allMappings, workfolder);
    }
    ```
    - Mappings are directly loaded from the `path-intellisense.mappings` setting without validation.

    4. **`src/providers/javascript/javascript.provider.ts` and `src/providers/nixos/nixos.provider.ts`**: These providers use `getPathOfFolderToLookupFiles` and `getChildrenOfPath` to provide completion items based on user input and configuration.

* Security test case:
    1. Install the Path Intellisense extension in VSCode.
    2. Open any folder as a VSCode workspace.
    3. Open the User Settings (JSON) in VSCode (`Ctrl+Shift+P` or `Cmd+Shift+P` and type "Preferences: Open User Settings (JSON)").
    4. Add the following configuration to your User Settings JSON to create a malicious mapping:
        ```json
        "path-intellisense.mappings": {
            "/": "/"
        }
        ```
    5. Create a new JavaScript file (e.g., `test.js`) in your workspace.
    6. In `test.js`, type the following line: `import "///etc/passwd` (or any other system file path you want to attempt to read, like `///C:/Windows/win.ini` on Windows).
    7. Observe the autocompletion suggestions. If the vulnerability is present, you might see file names and directory names from the root directory of your system (depending on permissions). In a successful exploit, you might even see entries from `/etc/passwd` or `C:/Windows/win.ini` being suggested as completion items.
    8. To further verify, select one of the suggestions that looks like it's from outside your workspace. While the extension may not directly display the content, successful completion listing of system files confirms the path traversal vulnerability.