- Vulnerability name: Workspace Configuration based Path Traversal leading to potential Information Disclosure
- Description:
    1. An attacker crafts a malicious VS Code workspace configuration file (`.code-workspace` or workspace settings).
    2. Within this configuration, the attacker defines a custom path mapping in the `path-intellisense.mappings` setting. The `value` of this mapping is set to an absolute path pointing to a sensitive location outside the intended project workspace, such as the root directory `/`, user's home directory (`~`), or other sensitive system directories.
    3. The attacker then distributes or socially engineers a victim user into opening this malicious workspace in VS Code, ensuring the victim has the "Path Intellisense" extension installed and active.
    4. Once the workspace is opened, and the user is working on a project file (e.g., JavaScript, TypeScript, Nix files), the attacker can trigger the vulnerability by inducing the user to initiate path completion within an import or require statement. This is typically done by typing a forward slash `/` or a configured mapping key, depending on the malicious mapping setup.
    5. The "Path Intellisense" extension, upon triggering, uses the attacker-defined mapping to resolve the base path for autocompletion. Because the mapping points to a sensitive location outside the workspace, the extension starts listing files and directories from this location.
    6. As a result, the victim user is presented with a list of files and directories from the attacker-specified sensitive location, potentially revealing directory structures, filenames, and even sensitive information contained in filenames that they would not normally have access to within the context of their intended project workspace. This information is disclosed directly within the VS Code editor's autocompletion suggestion UI.
- Impact:
    Information Disclosure. A malicious workspace can be crafted to list directory contents from sensitive locations outside the intended workspace. This can reveal sensitive file names and directory structure to the user opening the malicious workspace.
- Vulnerability rank: high
- Currently implemented mitigations:
    None specifically within the extension to prevent this misconfiguration risk. VS Code's workspace trust feature provides a general security boundary for untrusted workspaces but does not specifically address this configuration-based path listing issue within extensions.
- Missing mitigations:
    - Input validation and sanitization for custom mapping values defined in the `path-intellisense.mappings` setting. The extension should validate that the mapped `value` paths are within the workspace or at least provide a warning to the user if a mapping points to an absolute path outside the workspace.
    - Documentation enhancement to explicitly warn users about the security risks of using absolute paths in custom mappings, especially concerning potential information disclosure if mappings are misconfigured or maliciously set by an untrusted workspace.
    - Implementation of a configuration option to restrict custom mappings to only allow workspace-relative paths, preventing the use of absolute paths in mappings altogether.
- Preconditions:
    - The victim user must have the "Path Intellisense" VS Code extension installed.
    - The victim user must open a malicious VS Code workspace crafted by the attacker.
    - The malicious workspace must contain a configuration that sets a path mapping in `path-intellisense.mappings` to a sensitive absolute path (e.g., `/`, `~`, etc.).
    - The `path-intellisense.absolutePathToWorkspace` setting must be set to `false` or not explicitly set (as default is `true`, setting it to `false` increases the risk for absolute paths if mappings are used).
    - The `path-intellisense.showOnAbsoluteSlash` setting should be enabled (`true`) if the mapping key is `/` to trigger completion on typing `/`.
    - The user must trigger path completion in a supported file type (e.g., JavaScript, Nix) within the malicious workspace, typically by typing the mapping key or a trigger character like `/` in an import statement.
- Source code analysis:
    - `src/configuration/configuration.service.ts`: The `getConfiguration` function retrieves the `path-intellisense.mappings` configuration from VS Code settings.
    - `src/configuration/mapping.service.ts`: The `parseMappings` function parses the user-defined mappings, and `replaceWorkspaceFolder` performs placeholder replacement but does not validate the paths. The `value` part of the mapping, which can be an absolute path, is directly used without security checks.
    - `src/utils/file-utills.ts`: The `getPathOfFolderToLookupFiles` function uses the `value` from the mappings as the `rootFolder` to resolve paths. If a mapping points to an absolute path outside the workspace, this function will use that external path as the root for file lookups. `getChildrenOfPath` then uses this potentially attacker-controlled path to read directory contents using VS Code's file system API.
    - `src/providers/javascript/javascript.provider.ts` and `src/providers/nixos/nixos.provider.ts`: These providers use `getPathOfFolderToLookupFiles` and `getChildrenOfPath` to generate completion items, thus being affected by the malicious mappings.
- Security test case:
    1. Create a new directory to serve as a malicious VS Code workspace (e.g., `malicious-workspace`).
    2. Inside `malicious-workspace`, create a `.vscode` directory.
    3. Inside `.vscode`, create a `settings.json` file with the following content:
       ```json
       {
           "path-intellisense.mappings": {
               "/": "/"
           },
           "path-intellisense.absolutePathToWorkspace": false,
           "path-intellisense.showOnAbsoluteSlash": true
       }
       ```
    4. Open VS Code and open the `malicious-workspace` directory as a workspace.
    5. Create a new JavaScript file (e.g., `test.js`) in the `malicious-workspace`.
    6. Open `test.js` and type the following line: `import {} from "/"`.
    7. Observe the autocompletion suggestions that appear. They should list the root directory contents of the file system (e.g., "bin", "boot", "dev", "etc", "home", "lib", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var" on Linux/macOS).
    8. This confirms that the extension, under this workspace configuration, is listing files from the root directory, demonstrating the potential for information disclosure through maliciously crafted workspace settings.