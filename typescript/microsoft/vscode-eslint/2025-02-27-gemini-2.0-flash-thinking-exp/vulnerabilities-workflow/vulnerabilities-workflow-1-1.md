## Vulnerability List

### 1. Insecure ESLint Library Loading via `eslint.nodePath` Bypass

- Description:
    1. An attacker can trick a user into configuring a malicious `eslint.nodePath` setting at the workspace or workspace folder level.
    2. The VS Code ESLint extension, when activated in a workspace with this malicious `eslint.nodePath` setting, will prompt the user for confirmation to use the custom Node path.
    3. If the user approves this request (either by clicking "Allow" or "Allow Everywhere"), the extension will attempt to load and execute the ESLint library from the attacker-controlled path.
    4. The attacker can place a malicious ESLint library (e.g., by creating a fake `eslint` package in the malicious path) that contains arbitrary code.
    5. Upon loading, the malicious ESLint library's code will be executed within the context of the VS Code extension process when the extension tries to validate a file.

- Impact:
    - **Critical**: Arbitrary code execution within the VS Code extension host process. This could allow the attacker to:
        - Steal sensitive information like workspace files, environment variables, and credentials accessible to the VS Code process.
        - Modify workspace files or settings.
        - Install malicious extensions or further compromise the user's system.
        - Potentially gain control over the user's VS Code instance and, by extension, their development environment.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - User Confirmation Dialog: Since version 2.1.17, the extension prompts users for confirmation when a workspace or workspace folder defines `eslint.nodePath` or `eslint.runtime`. This is implemented in `client/src/client.ts` and mentioned in `README.md` and `CHANGELOG.md`.
    - Workspace Trust Model:  The extension adapts to VS Code's workspace trust model (version 2.1.22), which adds a layer of security by requiring users to trust workspaces. However, if a user trusts a workspace and approves the `nodePath`, this mitigation is bypassed.

- Missing Mitigations:
    - Input Validation and Sanitization: The extension lacks robust validation and sanitization of the `eslint.nodePath` setting. It should check if the path is reasonable and potentially block paths that are highly suspicious (e.g., temporary directories, user-writable directories outside the workspace).
    - Sandboxing or Isolation: The extension does not sandbox or isolate the execution of the ESLint library. Running external code within the extension's process directly leads to the code execution vulnerability. A more robust approach would be to execute ESLint in a separate, isolated process with limited permissions.
    - Content Security Policy (CSP): While VS Code extensions have limited CSP capabilities, exploring if any CSP mechanisms can further restrict the actions of loaded libraries could be beneficial.
    - Heuristics and Reputation Checks:  The extension could potentially incorporate heuristics to detect suspicious `nodePath` settings or perform reputation checks on the resolved ESLint library path, although this could be complex and introduce false positives.

- Preconditions:
    1. The attacker needs to convince the user to:
        - Open a workspace or folder controlled by the attacker, or
        - Modify workspace settings to include a malicious `eslint.nodePath`.
    2. The user must approve the execution of the ESLint library from the custom `nodePath` when prompted by the VS Code ESLint extension. This requires the user to click "Allow" or "Allow Everywhere" in the confirmation dialog.

- Source Code Analysis:
    1. **`client/src/client.ts` - `createServerOptions` function:**
        ```typescript
        function createServerOptions(extensionUri: Uri): ServerOptions {
            const serverModule = Uri.joinPath(extensionUri, 'server', 'out', 'eslintServer.js').fsPath;
            const eslintConfig = Workspace.getConfiguration('eslint');
            const debug = sanitize(eslintConfig.get<boolean>('debug', false) ?? false, 'boolean', false);
            const runtime = sanitize(eslintConfig.get<string | null>('runtime', null) ?? undefined, 'string', undefined); // <-- runtime from settings
            const execArgv = sanitize(eslintConfig.get<string[] | null>('execArgv', null) ?? undefined, 'string', undefined); // <-- execArgv from settings
            const nodeEnv = sanitize(eslintConfig.get<string | null>('nodeEnv', null) ?? undefined, 'string', undefined);

            // ...
            const result: ServerOptions = {
                run: { module: serverModule, transport: TransportKind.ipc, runtime, options: { execArgv, cwd: process.cwd(), env } }, // runtime and execArgv are used here
                debug: { module: serverModule, transport: TransportKind.ipc, runtime, options: { execArgv: execArgv !== undefined ? execArgv.concat(debugArgv) : debugArgv, cwd: process.cwd(), env } }
            };
            return result;
        }
        ```
        This code shows that `runtime` setting, which can be influenced by `eslint.nodePath` (indirectly by affecting ESLint library resolution and potentially the Node runtime used to execute it), is used to configure the `ServerOptions`.

    2. **`server/src/eslint.ts` - `resolveSettings` function:**
        ```typescript
        export async function resolveSettings(document: TextDocument): Promise<TextDocumentSettings> {
            // ...
            let nodePath: string | undefined;
            if (settings.nodePath !== null) {
                nodePath = settings.nodePath; // <-- nodePath setting is read
                if (!path.isAbsolute(nodePath) && workspaceFolderPath !== undefined) {
                    nodePath = path.join(workspaceFolderPath, nodePath);
                }
            }
            // ...
            let promise: Promise<string>;
            const eslintPath = settings.experimental?.useFlatConfig ? 'eslint/use-at-your-own-risk' : 'eslint'; // <-- eslint path
            if (nodePath !== undefined) {
                promise = Files.resolve(eslintPath, nodePath, nodePath, trace).then<string, string>(undefined, () => { // <-- Files.resolve using nodePath
                    return Files.resolve(eslintPath, settings.resolvedGlobalPackageManagerPath, moduleResolveWorkingDirectory, trace);
                });
            } else {
                promise = Files.resolve(eslintPath, settings.resolvedGlobalPackageManagerPath, moduleResolveWorkingDirectory, trace); // <-- Files.resolve without nodePath, relying on default resolution
            }
            // ...
            return promise.then(async (libraryPath) => { // libraryPath is the resolved path to eslint library
                let library = path2Library.get(libraryPath);
                if (library === undefined) {
                    library = loadNodeModule(libraryPath); // <-- loadNodeModule loads the library from the resolved path
                    // ...
                    settings.library = library; // <-- loaded library is used
                    path2Library.set(libraryPath, library);
                } else {
                    settings.library = library;
                }
                // ...
                return settings;
            }, () => { // ... error handling
                return settings;
            });
        }
        ```
        This code clearly shows how `eslint.nodePath` is used to resolve the ESLint library path using `Files.resolve`. `loadNodeModule` then loads the library from the resolved path, and this loaded library is used by the extension. If `nodePath` points to a malicious location and the user approves, malicious code will be loaded and executed.

- Security Test Case:
    1. **Setup:**
        - Create a new empty directory, which will be the workspace.
        - Inside this directory, create a subdirectory named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json`.
        - In the root directory, create a subdirectory named `malicious_eslint_path`.
        - Inside `malicious_eslint_path`, create a file named `index.js` with the following content (malicious ESLint library):
            ```javascript
            console.error("Malicious ESLint library loaded!");
            // Simulate ESLint API (minimal for extension to load without immediate error)
            module.exports = {
                ESLint: class ESLint {
                    async lintText(code, options) {
                        console.error("Malicious lintText executed!");
                        // Simulate some ESLint report to avoid extension errors
                        return [{ messages: [], errorCount: 0, warningCount: 0, filePath: options.filePath }];
                    }
                    async isPathIgnored(filePath) {
                        return false;
                    }
                    getRulesMetaForResults() {
                        return {};
                    }
                    calculateConfigForFile() {
                        return {};
                    }
                }
            };
            ```
        - In the `malicious_eslint_path` directory, create a `package.json` file:
            ```json
            {
              "name": "eslint",
              "version": "8.0.0"
            }
            ```
        - Open VS Code and open the empty directory as a workspace.
        - Open the `.vscode/settings.json` and add the following setting:
            ```json
            {
                "eslint.nodePath": "./malicious_eslint_path"
            }
            ```
        - Create a JavaScript file (e.g., `test.js`) in the workspace root.
        - Ensure the ESLint extension is activated.

    2. **Trigger Vulnerability:**
        - Open the `test.js` file.
        - Observe the VS Code ESLint extension status bar item. It should indicate that ESLint is being initialized.
        - A confirmation dialog should appear asking to "Allow or Deny execution of the ESLint library at './malicious_eslint_path'".
        - Click **"Allow Everywhere"**.

    3. **Verify Code Execution:**
        - Open the "Output" panel in VS Code and select "ESLint" in the dropdown.
        - Observe the output. You should see the following lines, indicating that the malicious ESLint library code was executed:
            ```
            [Info  - ESLint] ESLint server is starting.
            [Error - ESLint] Malicious ESLint library loaded!
            [Info  - ESLint] ESLint library loaded from: .../malicious_eslint_path/index.js
            [Error - ESLint] Malicious lintText executed!
            [Info  - ESLint] ESLint server is running.
            ```
        - The "Malicious ESLint library loaded!" and "Malicious lintText executed!" messages confirm that the malicious code from `malicious_eslint_path/index.js` was executed within the VS Code ESLint extension's context after user approval.

This test case demonstrates that by controlling the `eslint.nodePath` and tricking the user to approve its execution, an attacker can achieve code execution within the VS Code ESLint extension.