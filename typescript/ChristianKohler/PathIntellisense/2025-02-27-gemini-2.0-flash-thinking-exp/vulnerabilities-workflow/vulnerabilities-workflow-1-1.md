### Vulnerability List:

- Vulnerability Name: Path Traversal via Mappings Configuration
- Description:
    1. An attacker can configure malicious mappings in the VS Code settings for the Path Intellisense extension.
    2. These mappings can be crafted to point to locations outside of the intended workspace folder, potentially granting access to sensitive file system locations.
    3. When the extension uses these mappings to resolve paths for autocompletion, it may inadvertently expose files and directories outside the workspace.
    4. By triggering autocompletion in a workspace with such malicious mappings configured, an attacker can potentially list and infer the existence of files and directories outside the workspace.
- Impact: Information Disclosure. An attacker can potentially discover the existence of files and directories outside the workspace folder, including sensitive information if file names or directory structures reveal such details.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Workspace folder placeholder replacement in mappings: `${workspaceFolder}` and `${workspaceRoot}` are replaced with the workspace root path. This is intended to restrict mappings within the workspace.
    - Filtering mappings without workspace root in non-workspace folders: Mappings that contain workspace root placeholders are filtered out when no workspace folder is available.
- Missing Mitigations:
    - Input validation and sanitization for mapping values: The extension should validate and sanitize the values provided in the mappings configuration to ensure they remain within the intended scope, ideally within the workspace. It should prevent absolute paths outside the workspace or relative paths that can traverse out of the workspace.
    - Workspace boundary enforcement: The extension should strictly enforce workspace boundaries when resolving paths based on mappings, preventing any path resolution that leads outside the workspace.
- Preconditions:
    - The attacker needs to be able to configure workspace settings for a VS Code project where the Path Intellisense extension is active. This could be achieved if the attacker can influence the workspace settings (e.g., by contributing to a shared project or through a compromised development environment).
- Source Code Analysis:
    1. **`src/configuration/mapping.service.ts` - `parseMappings` and `replaceWorkspaceFolder`:**
        ```typescript
        export function parseMappings(mappings: { [key: string]: string }): Mapping[] {
          return Object.entries(mappings).map(([key, value]) => ({ key, value }));
        }

        export function replaceWorkspaceFolder(
          mappings: Mapping[],
          workfolder?: vscode.WorkspaceFolder
        ): Mapping[] {
          const rootPath = workfolder?.uri.path;

          if (rootPath) {
            /** Replace placeholder with workspace folder */
            return mappings.map(({ key, value }) => ({
              key,
              value: replaceWorkspaceFolderWithRootPath(value, rootPath),
            }));
          } else {
            /** Filter items out which contain a workspace root */
            return mappings.filter(({ value }) => !valueContainsWorkspaceFolder(value));
          }
        }
        ```
        - `parseMappings` simply converts the mapping object from settings into an array of `Mapping` objects. No validation is performed here.
        - `replaceWorkspaceFolder` replaces placeholders and filters mappings for non-workspace folders. However, it doesn't prevent malicious values in mappings from being set in the first place if they resolve within the workspace but point outside the intended project directory within the workspace.

    2. **`src/utils/file-utills.ts` - `getPathOfFolderToLookupFiles`:**
        ```typescript
        export function getPathOfFolderToLookupFiles(
          fileName: string,
          text: string | undefined,
          rootPath?: string,
          mappings?: Mapping[]
        ): string {
          const normalizedText = path.normalize(text || "");
          const isPathAbsolute = normalizedText.startsWith(path.sep);

          const mapping =
            mappings &&
            mappings.reduce((prev: any, curr: any) => {
              return (
                prev || (normalizedText.startsWith(path.normalize(curr.key)) && curr)
              );
            }, undefined);

          let rootFolder, pathEntered;
          if (mapping) {
            rootFolder = mapping.value;
            pathEntered = normalizedText.slice(
              path.normalize(mapping.key).length,
              normalizedText.length
            );
          } else {
            rootFolder = isPathAbsolute ? rootPath || "" : path.dirname(fileName);
            pathEntered = normalizedText;
          }

          return path.join(rootFolder, pathEntered);
        }
        ```
        - This function uses the configured mappings. If a mapping key matches the start of the input text, it uses the mapping's value as the `rootFolder`.
        - The `rootFolder` from the mapping value is directly used in `path.join` without further validation. If a malicious mapping like `"malicious": "/"` is configured, and the user types "malicious/", the `rootFolder` will be "/", and the path resolution will start from the root of the file system.

    3. **`src/providers/javascript/javascript.provider.ts` and `src/providers/nixos/nixos.provider.ts` - `provide` function:**
        ```typescript
        async function provide(
          context: Context,
          config: Config
        ): Promise<vscode.CompletionItem[]> {
          const workspace = vscode.workspace.getWorkspaceFolder(context.document.uri);

          const rootPath =
            config.absolutePathTo ||
            (config.absolutePathToWorkspace ? workspace?.uri.fsPath : undefined);

          const path = getPathOfFolderToLookupFiles(
            context.document.uri.fsPath,
            context.fromString,
            rootPath,
            config.mappings
          );

          const childrenOfPath = await getChildrenOfPath(
            path,
            config.showHiddenFiles,
            config.filesExclude
          );

          return [
            ...childrenOfPath.map((child) =>
              createPathCompletionItem(child, config, context)
            ),
          ];
        }
        ```
        - This function calls `getPathOfFolderToLookupFiles` to determine the path to look up files, using the configuration including mappings.
        - The result of `getPathOfFolderToLookupFiles`, which can be influenced by malicious mappings, is then passed to `getChildrenOfPath`, which reads the directory content.

- Security Test Case:
    1. Open VS Code in a workspace (e.g., the `demo-workspace` from the provided files).
    2. Open the workspace settings (File -> Preferences -> Settings, then Workspace tab).
    3. In the settings, search for "path-intellisense.mappings" and edit the settings in `settings.json`.
    4. Add a malicious mapping like this:
        ```json
        "path-intellisense.mappings": {
            "malicious": "/"
        }
        ```
    5. Open any JavaScript file within the workspace (e.g., `demo-workspace/project-one/index.js`).
    6. In the JavaScript file, type `import {} from "malicious/` (or `require("malicious/` or `export * from "malicious/`).
    7. Observe the autocompletion suggestions. If the vulnerability exists, you will see file system root directory contents (e.g., "Applications", "Users", "Program Files" etc. on macOS/Linux/Windows respectively) in the suggestions.
    8. This confirms that the malicious mapping allowed the extension to access and list files from the root directory, which is outside the intended workspace scope.

- Missing Mitigations:
    - Implement validation for mapping values to ensure they are relative paths within the workspace or absolute paths that are explicitly allowed and controlled by the user (and ideally, sanitized).
    - Introduce checks in `getPathOfFolderToLookupFiles` or `getChildrenOfPath` to verify that the resolved path remains within the workspace boundaries before performing file system operations. If the resolved path goes outside the workspace, the extension should refuse to provide autocompletion suggestions for that path.