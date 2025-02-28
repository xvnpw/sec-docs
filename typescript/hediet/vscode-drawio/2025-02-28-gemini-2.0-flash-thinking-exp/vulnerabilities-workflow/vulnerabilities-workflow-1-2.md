### Vulnerability List

#### 1. Vulnerability Name: Code Execution via Malicious Draw.io Plugin

- Description:
    1. An attacker crafts a malicious Draw.io plugin (JavaScript file) containing arbitrary code.
    2. The attacker socially engineers a victim (VSCode user) to configure the "hediet.vscode-drawio.plugins" setting in their workspace. This setting should point to the malicious plugin file. This can be achieved by sending a crafted workspace configuration file or by instructing the user to manually modify their workspace settings.
    3. The victim opens a Draw.io diagram file within the compromised workspace.
    4. The Draw.io extension detects the configured plugin and prompts the user with a dialog box to "allow or disallow loading of the given plugin".
    5. If the victim, unknowingly or through deception, clicks "Allow", the malicious plugin code is loaded and executed within the Draw.io editor's webview context.
    6. The attacker's JavaScript code now runs within the extension's webview, gaining access to the webview's context and potentially VS Code API capabilities exposed to the webview.

- Impact:
    - **Arbitrary Code Execution:** The attacker can execute arbitrary JavaScript code within the VS Code extension's webview.
    - **Information Disclosure:** The malicious plugin can access sensitive information available within the webview context, potentially including workspace files, environment variables, or VS Code settings.
    - **Cross-Site Scripting (in VS Code context):** While not a traditional website XSS, the attacker can manipulate the Draw.io editor UI and potentially interact with VS Code APIs if exposed to the webview, leading to actions performed on behalf of the user.
    - **Workspace Compromise:** Depending on the code's capabilities and exposed VS Code APIs, the attacker might be able to further compromise the user's workspace or even their system.

- Vulnerability Rank: critical

- Currently Implemented Mitigations:
    - **Plugin Approval Dialog:** The extension displays a dialog box prompting the user to allow or disallow loading of a plugin when a new or modified plugin configuration is detected. This dialog shows the plugin path and fingerprint (SHA256 hash).
    - Location: `docs/plugins.md` describes the approval mechanism and `Config.ts` handles known plugins.
    - **Fingerprint Verification:** The extension stores known plugin fingerprints in user settings (`hediet.vscode-drawio.knownPlugins`). It uses SHA256 hash to verify if a plugin has been previously approved.
    - Location: `Config.ts` (`isPluginAllowed`, `addKnownPlugin`).

- Missing Mitigations:
    - **Plugin Code Sandboxing:** The extension lacks a sandbox mechanism to restrict the capabilities of loaded plugins. Plugins run with full privileges within the webview context.
    - **Path Validation and Restriction:** The extension does not prevent users from configuring plugin paths that are outside the workspace folder or point to potentially system-critical files. While `${workspaceFolder}` template helps, it does not enforce workspace-relative paths.
    - **Clearer User Warning:** The warning message in the plugin approval dialog could be more explicit about the security risks of loading untrusted plugins, emphasizing the potential for arbitrary code execution and data access.
    - **Default Disallow Plugins from Workspace:** The extension could default to disallowing plugins from workspace and require explicit user action to enable them, reducing the attack surface.

- Preconditions:
    - The victim must have the Draw.io VS Code extension installed.
    - The attacker must be able to socially engineer the victim into configuring a malicious plugin path in their workspace settings and approving the plugin loading dialog.
    - The victim must open a Draw.io diagram file within the compromised workspace.

- Source Code Analysis:
    1. **Plugin Configuration Loading:**
        - `Config.ts`'s `DiagramConfig.plugins` getter retrieves plugin configurations from VS Code settings.
        - It uses `evaluateTemplate` to resolve paths, which uses `SimpleTemplate.ts` for string replacement and `${workspaceFolder}` variable.
        - `Uri.file(fullFilePath)` is used to create file URIs from the resolved paths.
    2. **Plugin Approval and Fingerprint Check:**
        - `DrawioClientFactory.ts`'s `getPlugins` method iterates through configured plugins.
        - It reads the plugin file content using `workspace.fs.readFile`.
        - It calculates the SHA256 fingerprint of the plugin code.
        - It checks if the plugin is known and allowed using `Config.ts`'s `isPluginAllowed`.
        - If the plugin is unknown, it shows a warning message using `window.showWarningMessage` prompting the user to allow or disallow.
        - User's choice is stored using `Config.ts`'s `addKnownPlugin`.
    3. **Plugin Execution:**
        - `DrawioClientFactory.ts`'s `getOfflineHtml` method constructs the HTML content for the Draw.io webview.
        - It injects the plugin code into the webview via `$$additionalCode$$` replacement in `webview-content.html`.
        - The injected JavaScript code is executed within the Draw.io webview context when the webview is loaded.

- Security Test Case:
    1. **Setup:**
        - Create a new folder named `drawio-plugin-test-workspace`. Open it in VS Code.
        - Inside `drawio-plugin-test-workspace`, create a subfolder named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json`.
        - Create a file named `test.drawio` in `drawio-plugin-test-workspace`.
        - Create a file named `malicious-plugin.js` in `drawio-plugin-test-workspace`.
        - In `malicious-plugin.js`, add the following code:
            ```javascript
            Draw.loadPlugin(function (ui) {
                alert('Malicious Plugin Loaded! Accessing VS Code API...');
                // Attempt to access VS Code API (example: show information message)
                if (window.VsCodeApi) {
                    window.VsCodeApi.postMessage({ command: 'showInfo', text: 'Plugin Code Executed!' });
                } else {
                    alert('VS Code API not accessible directly, but code executed.');
                }
            });
            ```
        - In `.vscode/settings.json`, add the following configuration:
            ```json
            {
                "hediet.vscode-drawio.plugins": [
                    {
                        "file": "${workspaceFolder}/malicious-plugin.js"
                    }
                ]
            }
            ```
        - Ensure you have the Draw.io VS Code extension installed and enabled.

    2. **Trigger Vulnerability:**
        - Open `test.drawio` in VS Code using the Draw.io editor.
        - A dialog box should appear asking to allow or disallow loading the plugin `file:///.../drawio-plugin-test-workspace/malicious-plugin.js`.
        - Click "Allow".

    3. **Verify Impact:**
        - Observe if an alert box `Malicious Plugin Loaded! Accessing VS Code API...` is displayed.
        - Observe if another alert box or VS Code information message `Plugin Code Executed!` is displayed, indicating potential access to VS Code API or successful code execution within the webview context.

This test case demonstrates that arbitrary JavaScript code from a plugin can be executed within the Draw.io webview after user approval, confirming the "Code Execution via Malicious Draw.io Plugin" vulnerability.