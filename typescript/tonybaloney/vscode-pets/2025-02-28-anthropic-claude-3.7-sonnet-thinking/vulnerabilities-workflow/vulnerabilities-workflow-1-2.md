# Vulnerability List

- **Vulnerability Name**: Webview Inline Script Injection via Unsanitized Configuration Values

  - **Description**:  
    The extension builds its webview HTML dynamically in the function that generates the inline HTML for the pet panel (via `_getHtmlForWebview` in the extension's TypeScript file). In this process, several configuration-derived values are injected directly into an inline JavaScript call without proper escaping or sanitization. For example, the HTML is generated as follows:
    
    ```
    <script nonce="${nonce}" src="${scriptUri}"></script>
    <script nonce="${nonce}">
         petApp.petPanelApp("${basePetUri}", "${this.theme()}", ${this.themeKind()}, "${this.petColor()}", 
         "${this.petSize()}", "${this.petType()}", ${this.throwBallWithMouse()}, ${this.disableEffects()});
    </script>
    ```
    
    The values (such as those returned by `this.theme()`, `this.petColor()`, `this.petSize()`, and `this.petType()`) come directly from the user's configuration settings (read via `vscode.workspace.getConfiguration('vscode-pets').get(...)`). A threat actor who supplies a malicious repository may provide a ".vscode/settings.json" that sets one or more of these values to strings containing embedded double quotes and JavaScript code (for example, using a payload like `"cat\",alert('Injected'),\""`). This results in an inline script that inadvertently executes the injected code in the webview's context.

  - **Impact**:  
    An attacker controlling the repository configuration can force the webview to execute arbitrary JavaScript code. This Remote Code Execution (RCE) in the webview context may allow the attacker to read or modify sensitive workspace data, interact with the VS Code API with elevated privileges, and fundamentally compromise the developer's session.

  - **Vulnerability Rank**: Critical

  - **Currently Implemented Mitigations**:  
    - The webview uses a strict Content Security Policy (CSP) that includes a nonce to restrict external script loading.  
    - However, the CSP does not mitigate injection within dynamically generated inline scripts when unsanitized configuration values are interpolated.

  - **Missing Mitigations**:  
    - There is no sanitization or escaping applied to the configuration values (e.g., "theme", "petColor", "petSize", "petType") before they are concatenated into the inline JavaScript.  
    - A mitigation would be to JSON‑serialize these values using `JSON.stringify(...)` so that any embedded quotes or special characters are properly escaped.  
    - Alternatively, refactoring the code to avoid constructing inline scripts from dynamic data would prevent the issue entirely.

  - **Preconditions**:  
    - The victim must open a workspace or repository that contains a malicious ".vscode/settings.json" (or similar configuration file) where keys under "vscode-pets" (such as "petType", "petColor", "petSize", or "theme") have been maliciously modified.  
    - When the extension reads these configuration values (typically during startup or when the "Start pet coding session" command is executed), the unsafe values are injected into the webview's HTML.

  - **Source Code Analysis**:  
    - In the extension's source code (for example, in `/code/src/extension/extension.ts`), the function `_getHtmlForWebview(webview)` constructs the HTML for the pet panel.
    - It creates an inline script as shown:
      ```
      <script nonce="${nonce}" src="${scriptUri}"></script>
      <script nonce="${nonce}">
          petApp.petPanelApp("${basePetUri}", "${this.theme()}", ${this.themeKind()}, "${this.petColor()}", "${this.petSize()}", "${this.petType()}", ${this.throwBallWithMouse()}, ${this.disableEffects()});
      </script>
      ```
    - The values such as `this.theme()`, `this.petColor()`, etc., are obtained from user configuration without performing any validation or escaping.
    - Because these values are embedded inside JavaScript string literals in inline code, a payload supplied by a malicious ".vscode/settings.json" can break out of the string context and execute arbitrary code in the webview.

  - **Security Test Case**:  
    1. Create a test workspace and within it add a file `.vscode/settings.json` with the following content:
       ```json
       {
         "vscode-pets.petType": "cat\",alert('Injected'),\""
       }
       ```
    2. Open this test workspace in VS Code so that the extension reads the malicious configuration settings.
    3. Execute the "Start pet coding session" command (i.e. run the command registered as `vscode-pets.start`).
    4. Observe that when the webview is displayed, the inline script executes the injected code (for example, an alert box appears).
    5. The execution of the alert confirms that the unsanitized configuration value led to arbitrary code execution, validating the vulnerability.