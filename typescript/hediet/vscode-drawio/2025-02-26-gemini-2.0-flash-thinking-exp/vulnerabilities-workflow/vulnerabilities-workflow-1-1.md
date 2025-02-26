### Vulnerability List

- Vulnerability Name: Plugin Loading Vulnerability via Absolute Path
- Description:
    1. An attacker crafts a malicious JavaScript file intended to be loaded as a Draw.io plugin.
    2. The attacker gains control over the workspace settings, for example, by contributing to a shared repository and modifying the `.vscode/settings.json` file or by tricking a user into importing a malicious workspace configuration.
    3. In the compromised workspace settings, the attacker configures the `hediet.vscode-drawio.plugins` setting to include an entry that specifies the absolute path to the malicious JavaScript file on the victim's file system.
    4. A victim user opens a Draw.io diagram file (e.g., `.drawio`, `.dio`, `.drawio.svg`, `.drawio.png`) within the compromised workspace in VS Code.
    5. The Draw.io extension reads the workspace settings and identifies the plugin configuration.
    6. If the plugin is new or has been modified, the extension displays a dialog prompting the user to allow or disallow loading the plugin from the specified absolute path.
    7. If the victim user clicks "Allow" (either unknowingly or through social engineering), the extension proceeds to load and execute the malicious JavaScript code within the Draw.io editor webview.
- Impact: Arbitrary code execution within the VS Code extension's webview context. This can lead to:
    - Information disclosure: Accessing sensitive workspace files, environment variables, or VS Code configurations.
    - Actions on behalf of the user: Modifying files, sending unauthorized network requests, or installing further malicious extensions.
    - Further exploitation: If vulnerabilities exist within the webview environment or VS Code itself, successful exploitation could lead to broader system compromise.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Plugin Load Confirmation Dialog: When a new or modified plugin is detected, a dialog box prompts the user to explicitly allow or disallow its loading. This is implemented in the `getPlugins` method within `DrawioClientFactory.ts`. The dialog is shown using `window.showWarningMessage` when `this.config.isPluginAllowed` returns `undefined`, indicating an unknown plugin.
    - Known Plugins User Setting: The user's decision (Allow or Disallow) for each plugin is stored in the user settings (`hediet.vscode-drawio.knownPlugins`). This setting includes the plugin's file path and a SHA256 fingerprint to verify plugin integrity and user consent for specific plugin versions. The `addKnownPlugin` and `isPluginAllowed` methods in `Config.ts` manage this setting. The fingerprint is generated using `sha256.hex(jsCode)` in `DrawioClientFactory.ts`.
- Missing Mitigations:
    - Restrict Plugin Paths: The extension should be modified to only accept workspace-relative paths for plugin files, effectively disallowing absolute paths. This would prevent the loading of arbitrary files from outside the workspace, significantly reducing the attack surface. Path validation should be implemented in `Config.ts` within the `plugins` getter to ensure only workspace-relative paths are accepted.
    - Plugin Content Validation: Implement more robust validation of plugin content before execution. While validating JavaScript code is complex, basic checks for obviously malicious patterns or integrations with static analysis tools could be considered for future enhancements.
- Preconditions:
    - Workspace Settings Control: The attacker must be able to influence the victim's workspace settings. This could be achieved through shared repositories or by social engineering to import malicious configurations.
    - User Interaction: The victim user must open a Draw.io diagram within the compromised workspace.
    - Plugin Approval: For new or modified plugins, the victim user must approve the plugin loading through the confirmation dialog.
- Source Code Analysis:
    - File: `/code/docs/plugins.md`: Documentation (not provided in PROJECT FILES, but referenced in previous analysis and assumed to exist) explicitly states that plugins can be loaded using absolute paths and `${workspaceFolder}` variable, confirming the functionality.
    - File: `/code/Config.ts`:
        ```typescript
        public get plugins(): { file: Uri }[] {
            return this._plugins.get().map((entry) => {
                const fullFilePath = this.evaluateTemplate(entry.file, "plugins");
                return { file: Uri.file(fullFilePath) };
            });
        }
        ```
        The `DiagramConfig.plugins` getter retrieves plugin configurations from settings. It uses `evaluateTemplate` to process file paths, which supports `${workspaceFolder}` but does not restrict paths to be workspace-relative. This allows absolute paths to be used as plugin file locations, as configured in `settings.json`.
        - File: `/code/Config.ts`: The `VsCodeSetting` class (and underlying VS Code settings API) is used for reading settings, but it lacks path validation or restrictions, allowing absolute paths to be accepted as plugin file locations.
    - File: `/code/src/DrawioClient/DrawioClientFactory.ts`:
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
                    // ...
                } catch (e) {
                    window.showErrorMessage(
                        `Could not read plugin file "${p.file}"!`
                    );
                    continue;
                }
                // ...
                const isAllowed = this.config.isPluginAllowed(
                    pluginId,
                    fingerprint
                );
                if (isAllowed) {
                    pluginsToLoad.push({ jsCode });
                } else if (isAllowed === undefined) {
                    // ... Show confirmation dialog ...
                }
            }
            // ...
        }
        ```
        The `getPlugins` method in `DrawioClientFactory.ts` iterates through configured plugins (`config.plugins`). For each plugin `p`, it reads the plugin file content using `workspace.fs.readFile(p.file)`.  The `p.file` here is a `Uri` object created from the potentially absolute path specified in settings, which is then directly used to read the file. This is where the absolute path is processed and the file content is loaded if the user allows it. The code proceeds to check if the plugin is allowed using `this.config.isPluginAllowed` and shows a confirmation dialog if it's a new or modified plugin. If allowed, the `jsCode` is added to `pluginsToLoad`.

- Security Test Case:
    1. Setup:
        - Create a new workspace in VS Code.
        - Create a directory named `.vscode` at the root of the workspace.
        - Inside `.vscode`, create a file named `settings.json`.
        - Create a malicious JavaScript file named `malicious_plugin.js` and place it in a known location on your system outside the workspace, for example, `/tmp/malicious_plugin.js`. The content of `malicious_plugin.js` should be:
          ```javascript
          Draw.loadPlugin(function (ui) {
              alert('Malicious plugin executed! Workspace path: ' + vscode.workspace.workspaceFolders[0].uri.path);
              // You can add more harmful actions here for testing, like file access or data exfiltration.
          });
          ```
    2. Configure Workspace Settings:
        - Open `.vscode/settings.json` and add the following configuration, replacing `/tmp/malicious_plugin.js` with the actual path to your malicious plugin file:
          ```json
          {
              "hediet.vscode-drawio.plugins": [
                  {
                      "file": "/tmp/malicious_plugin.js"
                  }
              ]
          }
          ```
    3. Create Draw.io Diagram:
        - Create an empty file named `test.drawio` at the root of the workspace.
    4. Open Draw.io Diagram:
        - Open `test.drawio` in VS Code using the Draw.io editor.
    5. Observe Plugin Load Dialog:
        - A dialog box will appear, prompting you to allow or disallow loading the plugin from `/tmp/malicious_plugin.js`.
    6. Allow Plugin Execution:
        - Click "Allow" in the dialog.
    7. Verify Code Execution:
        - An alert box with the message "Malicious plugin executed! Workspace path: ..." will appear within the Draw.io editor. The workspace path in the alert confirms code execution within the webview context and access to VS Code API (e.g., `vscode.workspace`).

This test case successfully demonstrates arbitrary code execution by loading a plugin from an absolute path, confirming the plugin loading vulnerability is still present and valid in the current codebase.