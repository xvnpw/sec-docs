- Vulnerability 1
  - Vulnerability Name: Arbitrary Code Execution via Draw.io Plugins
  - Description: The Draw.io VS Code extension allows users to load custom plugins from workspace folders. By crafting a malicious Draw.io diagram and associated workspace settings that include a malicious plugin, an attacker can achieve arbitrary code execution within the VS Code extension's webview context when a user opens the diagram in VS Code and approves plugin loading.
  - Impact: Critical. Arbitrary code execution within the VS Code extension's webview context, potentially leading to sensitive information access, file modification, data exfiltration, and further system compromise.
  - Vulnerability Rank: critical
  - Currently Implemented Mitigations: User consent dialog prompts users to allow or disallow plugin loading for new or modified plugins. User decisions are stored in user settings based on plugin path and hash, preventing automatic loading from malicious workspaces.
  - Missing Mitigations: Lack of further sandboxing or isolation for plugins. No code review or security analysis of plugins by the extension. Reliance on user vigilance for security.
  - Preconditions:
    - Attacker creates a malicious Draw.io diagram and workspace settings with a malicious plugin.
    - User opens the diagram in VS Code within the malicious workspace.
    - User approves the loading of the malicious plugin.
  - Source Code Analysis:
    - `docs/plugins.md`: Feature documentation, outlines user consent for plugin loading.
    - `Config.ts`: Manages plugin settings (`hediet.vscode-drawio.plugins`) and user approvals (`hediet.vscode-drawio.knownPlugins`), using `isPluginAllowed` and `addKnownPlugin`.
    - `DrawioClientFactory.ts`: `createDrawioClientInWebview` loads plugins based on configuration and approval status. The `getPlugins` function reads plugin code from files and checks for user approval.
    - `DrawioClient.ts`: `loadPlugins` injects plugin code via `configure` action to the webview iframe.
    - Visualization:
      ```mermaid
      graph LR
          A[VS Code Workspace] --> B(settings.json);
          B --> C{DrawioClientFactory.ts: getPlugins()};
          C --> D{Config.ts: isPluginAllowed()};
          D -- Allowed --> E[Read Plugin File];
          E --> F[DrawioClient.ts: configure action];
          F --> G[Draw.io Webview];
          G -- Plugin Code Execution --> H[Arbitrary Code Execution]
      ```
  - Security Test Case:
    1. Create a new VS Code workspace.
    2. Create `.vscode/settings.json` with:
       ```json
       {
           "hediet.vscode-drawio.plugins": [
               {
                   "file": "${workspaceFolder}/malicious-plugin.js"
               }
           ]
       }
       ```
    3. Create `malicious-plugin.js` in workspace root:
       ```javascript
       Draw.loadPlugin(function (ui) {
           alert('Malicious plugin executed!');
           if (typeof vscode !== 'undefined') {
               vscode.postMessage({ command: 'evil', text: 'Plugin code executed' });
           }
       });
       ```
    4. Create `test.drawio` in workspace root (empty file).
    5. Open `test.drawio` in Draw.io editor.
    6. In the prompt, click "Allow" to load the plugin.
    7. Observe the "Malicious plugin executed!" alert.

- Vulnerability 2
  - Vulnerability Name: Potential File Path Traversal and Arbitrary File Opening via Code Link Feature
  - Description: The Code Link feature allows diagram nodes to link to code symbols or files using labels starting with `#`. Insufficient sanitization of these labels could allow path traversal attacks. By crafting a malicious Draw.io diagram with labels like `#../../../sensitive.txt`, an attacker might trick the extension into attempting to open files outside the workspace.
  - Impact: High. Potential information disclosure by opening sensitive files outside the workspace within VS Code's restricted "Open File" capabilities. Limited arbitrary file opening within user-accessible files.
  - Vulnerability Rank: high
  - Currently Implemented Mitigations: Workspace scope of VS Code's API for symbol search and file opening provides some implicit mitigation.
  - Missing Mitigations: Explicit path traversal prevention by sanitizing node labels. Enforcement of workspace boundaries when resolving file paths from code links.
  - Preconditions:
    - Attacker creates a malicious Draw.io diagram with node labels containing path traversal sequences (e.g., `..`).
    - User opens the diagram in VS Code with Code Link enabled.
    - User double-clicks a node with the malicious label.
  - Source Code Analysis:
    - `docs/code-link.md`: Feature documentation, lacks security considerations.
    - `src/features/CodeLinkFeature.ts`: `handleDrawioEditor` processes `onNodeSelected` events. It extracts symbol names and file paths from labels. `revealSelection` uses `workspace.openTextDocument`, `window.showTextDocument`, and `commands.executeCommand("vscode.open", pos.uri, ...)` to open files. Path validation in `CodePosition.deserialize` and `resolveWorkspaceSymbol` needs verification.
    - Visualization:
      ```mermaid
      graph LR
          A[Draw.io Diagram] --> B{Node with malicious label};
          B -- Double Click --> C[CodeLinkFeature.ts: handleDrawioEditor()];
          C --> D[CodePosition.deserialize()];
          D --> E[resolveWorkspaceSymbol()];
          E --> F[vscode.open command];
          F --> G[Attempt to open file (path traversal)]
      ```
  - Security Test Case:
    1. Create a new VS Code workspace.
    2. Create `sensitive.txt` in user's home directory (outside workspace).
    3. Create `test-codelink.drawio` in workspace.
    4. Open `test-codelink.drawio` in Draw.io editor.
    5. Create a node, label it `#../../../sensitive.txt` (adjust `../` count).
    6. Enable Code Link.
    7. Double-click the node.
    8. Observe if `sensitive.txt` opens and displays content.