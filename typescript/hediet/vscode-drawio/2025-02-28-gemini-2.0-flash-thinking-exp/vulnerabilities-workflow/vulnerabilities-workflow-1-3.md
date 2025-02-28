### Vulnerability List for Draw.io VS Code Integration

* Vulnerability 1: Arbitrary Code Execution via Malicious Draw.io Plugin
    * Description:
        1. An attacker crafts a malicious Draw.io plugin, which is a JavaScript file containing harmful code.
        2. The attacker then socially engineers a victim into opening a VS Code workspace that includes this malicious plugin file. This could be achieved by enticing the victim to clone a repository or open a shared project containing the malicious plugin.
        3. The victim opens the workspace in VS Code and proceeds to open a Draw.io diagram file (e.g., `.drawio`, `.dio`, `.drawio.svg`, or `.drawio.png`) using the Draw.io VS Code extension.
        4. The Draw.io extension, upon loading, detects the plugin configuration within the workspace settings (`hediet.vscode-drawio.plugins`). It then presents a dialog box to the user, prompting them to either "Allow" or "Disallow" the loading of the detected plugin.
        5. If the victim, due to being deceived or unaware of the risks, clicks "Allow", the malicious plugin's JavaScript code is executed within the Draw.io editor's webview context. This webview operates within the security context of the VS Code extension, granting the malicious plugin the ability to execute arbitrary code with the privileges of the extension. This can lead to severe consequences.
    * Impact:
        Successful exploitation allows arbitrary code execution within the VS Code extension's context. This can lead to:
        - Unauthorized access to sensitive data, including workspace files and VS Code settings.
        - Modification or deletion of files within the workspace.
        - Installation of malware or backdoors on the user's system.
        - Further exploitation of the VS Code API to compromise the user's development environment.
    * Vulnerability Rank: critical
    * Currently implemented mitigations:
        - User Prompt: The extension displays a dialog box prompting users to allow or disallow loading of detected plugins. This provides a point of control for users to prevent loading of untrusted plugins.
        - Plugin Fingerprinting and Known Plugins List: The extension calculates the SHA256 fingerprint of each plugin file and maintains a list of known plugins in the user settings (`hediet.vscode-drawio.knownPlugins`). This mechanism is designed to remember user decisions (Allow/Disallow) for specific plugin versions, identified by their fingerprint and file path.
    * Missing mitigations:
        - Plugin Code Sandboxing: The extension lacks a mechanism to sandbox or validate the code within Draw.io plugins. Once a plugin is allowed, it runs with full privileges within the webview, without restrictions.
        - Robust Plugin Verification: The current mitigation relies solely on user discretion after a warning prompt and fingerprint matching for subsequent loads. There is no automated verification of plugin integrity or safety before prompting the user.
        - Social Engineering Countermeasures: The extension does not actively counter social engineering tactics that attackers might use to trick users into allowing malicious plugins. The warning message might not be sufficiently alarming to less security-conscious users.
    * Preconditions:
        - A VS Code workspace must be opened that contains a malicious plugin file.
        - The workspace settings (`.vscode/settings.json`) must be configured to load the malicious plugin using the `hediet.vscode-drawio.plugins` setting.
        - The user must click "Allow" in the plugin loading prompt dialog presented by the Draw.io extension when opening a Draw.io diagram within the compromised workspace.
    * Source code analysis:
        - `/code/docs/plugins.md`: This document describes the plugin feature, explaining how to configure plugins via the `hediet.vscode-drawio.plugins` setting and how the extension prompts users for permission.
        - `/code/Config.ts`: This file manages the extension's configuration, including plugin settings. It includes logic for handling known plugins (`_knownPlugins` setting), checking if a plugin is allowed (`isPluginAllowed`), and adding plugins to the known list (`addKnownPlugin`).
        ```typescript
        // File: /code/src/Config.ts
        public isPluginAllowed(
            pluginId: string,
            fingerprint: string
        ): boolean | undefined {
            const data = this._knownPlugins.get();
            const entry = data.find(
                (d) => d.pluginId === pluginId && d.fingerprint === fingerprint
            );
            if (!entry) {
                return undefined;
            }
            return entry.allowed;
        }

        public async addKnownPlugin(
            pluginId: string,
            fingerprint: string,
            allowed: boolean
        ): Promise<void> {
            const plugins = [...this._knownPlugins.get()].filter(
                (p) => p.pluginId !== pluginId || p.fingerprint !== fingerprint
            );

            plugins.push({ pluginId, fingerprint, allowed });
            await this._knownPlugins.set(plugins);
        }
        ```
        - `/code/DrawioClientFactory.ts`: The `getPlugins` function in this file is responsible for orchestrating the plugin loading process. It reads plugin file contents, calculates fingerprints, checks against the known plugins list, and prompts the user for permission if a plugin is unknown.
        ```typescript
        // File: /code/src/DrawioClient/DrawioClientFactory.ts
        private async getPlugins(
            config: DiagramConfig
        ): Promise<{ jsCode: string }[]> {
            const pluginsToLoad = new Array<{ jsCode: string }>();
            const promises = new Array<Promise<void>>();

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
                if (isAllowed) {
                    pluginsToLoad.push({ jsCode });
                } else if (isAllowed === undefined) {
                    promises.push(
                        (async () => {
                            const result = await window.showWarningMessage(
                                `Found unknown plugin "${pluginId}" with fingerprint "${fingerprint}"`,
                                {},
                                {
                                    title: "Allow",
                                    action: async () => {
                                        pluginsToLoad.push({ jsCode });
                                        await this.config.addKnownPlugin(
                                            pluginId,
                                            fingerprint,
                                            true
                                        );
                                    },
                                },
                                {
                                    title: "Disallow",
                                    action: async () => {
                                        await this.config.addKnownPlugin(
                                            pluginId,
                                            fingerprint,
                                            false
                                        );
                                    },
                                }
                            );

                            if (result) {
                                await result.action();
                            }
                        })()
                    );
                }
            }

            await Promise.all(promises);
            return pluginsToLoad;
        }
        ```
        - `/code/DrawioClientFactory.ts`: The `getOfflineHtml` function constructs the HTML content for the Draw.io webview. It directly injects the JavaScript code of allowed plugins into the HTML, which is then loaded into the webview.
        ```typescript
        // File: /code/src/DrawioClient/DrawioClientFactory.ts
        private getOfflineHtml(
            config: DiagramConfig,
            options: DrawioClientOptions,
            webview: Webview,
            plugins: { jsCode: string }[]
        ): string {
            // ...
            .replace(
                "$$additionalCode$$",
                JSON.stringify(plugins.map((p) => p.jsCode))
            );
            return patchedHtml;
        }
        ```
        - `/code/drawio-custom-plugins/src/index.ts` and other files in `/code/drawio-custom-plugins/src/`: These files contain example custom plugins, demonstrating the functionality and capabilities of plugins, which include arbitrary JavaScript execution within the Draw.io editor context.

        The source code analysis confirms that the extension reads plugin code from files and injects it into the webview upon user approval without further security measures like sandboxing or validation, thus enabling arbitrary code execution.
    * Security test case:
        1. Create a new VS Code workspace.
        2. Create a folder named `.vscode` in the workspace root.
        3. Inside `.vscode`, create a file named `settings.json` with the following content:
        ```json
        {
            "hediet.vscode-drawio.plugins": [
                {
                    "file": "${workspaceFolder}/malicious-plugin.js"
                }
            ]
        }
        ```
        4. Create a file named `malicious-plugin.js` in the workspace root with the following content:
        ```javascript
        Draw.loadPlugin(function (ui) {
            alert('Malicious Plugin Alert! Plugin is running with full extension privileges.');
            // Example malicious action: Attempt to access VS Code API (may be limited in webview context) and log to console
            console.log('VS Code API object:', vscode);
            // Example malicious action: Attempt to read a local file - this will likely be blocked by webview security but worth testing
            fetch('file:///etc/passwd').catch(e => console.error('File access attempt error:', e));
        });
        ```
        5. Create an empty file named `test.drawio` in the workspace root.
        6. Open the `test.drawio` file in VS Code.
        7. The Draw.io extension should detect the plugin and display a warning message prompting to allow or disallow loading "malicious-plugin.js".
        8. Click "Allow" in the dialog prompt.
        9. Observe an alert box with the message "Malicious Plugin Alert! Plugin is running with full extension privileges." appear within the Draw.io editor, confirming code execution.
        10. Open the developer console in VS Code (Help -> Toggle Developer Tools -> Console). Check the console output for logs from the malicious plugin, including the VS Code API object log and any errors from the `fetch` attempt, further verifying plugin code execution within the extension context.

* Vulnerability 2: Potential Cross-Site Scripting (XSS) in Node Labels (Needs Further Investigation)
    * Description:
        Draw.io permits HTML content within node labels. If the VS Code extension fails to properly sanitize or encode these HTML labels when processing or rendering them, it may be susceptible to Cross-Site Scripting (XSS) attacks. An attacker could craft a diagram file where node labels contain malicious JavaScript code embedded within HTML tags. When the extension subsequently processes or renders this diagram—for instance, during operations like code linking or in collaborative Liveshare sessions—the unsanitized HTML labels could be interpreted by the web browser, leading to the execution of the embedded malicious scripts within the webview context.
    * Impact:
        Successful XSS exploitation could lead to:
        - Stealing of session cookies or local storage data from the webview.
        - Redirection of users to attacker-controlled malicious websites.
        - Defacement of the diagram content within the webview.
        - Potentially limited access to the VS Code API depending on the webview's security context, although this is less likely to be a direct and immediate high-impact vulnerability.
    * Vulnerability Rank: medium (potential to be high depending on exploitability and context)
    * Currently implemented mitigations:
        None explicitly identified for XSS prevention in node labels within the provided project files. While Content Security Policy (CSP) is mentioned for webviews, its effectiveness in mitigating label-based XSS specifically needs verification.
    * Missing mitigations:
        - Input Sanitization: Implement robust sanitization of node labels to remove or HTML-encode any potentially harmful HTML or JavaScript code before processing or rendering labels.
        - Context-Aware Output Encoding: Apply context-aware output encoding when rendering labels in different parts of the extension, especially in contexts where HTML content from labels is dynamically inserted into the webview DOM.
        - Content Security Policy (CSP) Enforcement: Verify and enforce a strict Content Security Policy (CSP) for webviews to restrict the execution of inline scripts and the loading of external resources. Ensure CSP effectively mitigates XSS attempts originating from diagram labels.
    * Preconditions:
        - The victim user must open a specifically crafted diagram file that has been created or modified by an attacker.
        - This malicious diagram must contain node labels with embedded JavaScript code within HTML markup.
        - The Draw.io extension must process or render these malicious labels in a vulnerable context, such as during label display, code link processing, or within collaborative Liveshare features.
    * Source code analysis:
        - `/code/drawio-custom-plugins/src/linkSelectedNodeWithData.ts`: The function `getLabelTextOfCell` uses `el.innerHTML = labelHtml` to parse the label content. This method, while intended to extract text, can inadvertently process and potentially execute any JavaScript embedded within the HTML content of `labelHtml` if not handled carefully.
        ```typescript
        // File: /code/drawio-custom-plugins/src/linkSelectedNodeWithData.ts
        function getLabelTextOfCell(cell: any): string {
            const labelHtml = graph.getLabel(cell);
            const el = document.createElement("html");
            el.innerHTML = labelHtml; // label can be html
            return el.innerText;
        }
        ```
        - Further code review is needed to identify all instances where diagram labels are processed or rendered, and to assess if these locations are vulnerable to XSS due to lack of sanitization or encoding of HTML label content. Areas such as Liveshare features, code link rendering, and any custom label processing logic should be examined.
    * Security test case:
        1. Create a new `.drawio` diagram file.
        2. Add a node to the diagram and set its label to the following malicious payload: `<img src=x onerror="alert('XSS Vulnerability Alert!')">`. This payload uses an `<img>` tag with a nonexistent `src` attribute, causing an `onerror` event to trigger, which executes JavaScript to display an alert box.
        3. Save the `.drawio` diagram file.
        4. Reopen the saved `.drawio` diagram file using the Draw.io VS Code extension.
        5. Observe if an alert box with the message "XSS Vulnerability Alert!" appears within the Draw.io editor webview. If the alert box is displayed, it indicates that the JavaScript code embedded in the node label has been executed, confirming a potential XSS vulnerability.
        6. To further investigate the scope, enable the Code Link feature and double-click on the node with the malicious label. Observe if the XSS payload is triggered in this context as well. Also, test within a Liveshare session if applicable, to see if the vulnerability manifests during collaborative diagram editing.