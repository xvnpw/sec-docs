- **Vulnerability Name:** Inadequate Content Security Policy (CSP) in Online Mode  
  **Description:**  
  In online mode the extension builds an HTML wrapper (in the `getOnlineHtml` method of the DrawioClientFactory) that embeds an iframe with a very permissive CSP. The meta tag is hard‑coded to allow wildcards and both `'unsafe-inline'` and `'unsafe-eval'` (e.g. `default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; …`). An attacker who controls (or is able to intercept/modify) the remote URL’s content can inject arbitrary JavaScript. When that iframe loads in the VS Code webview, the malicious code executes in a privileged context.  
  **Impact:**  
  • Arbitrary code execution inside the webview can lead to data exfiltration (e.g. access to user documents or workspace information), diagram manipulation, or even triggering undesired VS Code commands.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  • By default the extension uses offline mode (with locally bundled draw.io assets). However, in online mode no additional validation, URL whitelisting, or a stricter CSP is enforced.  
  **Missing Mitigations:**  
  • Implement a much more restrictive CSP that removes wildcards and disallows both `'unsafe-inline'` and `'unsafe-eval'`.  
  • Validate that any externally provided URL belongs to a trusted source (e.g. enforcing a whitelist).  
  **Preconditions:**  
  • The user must configure the extension to use online mode (by setting `"hediet.vscode-drawio.offline": false` and providing an `"online-url"` in settings).  
  • An attacker must either control the remote URL or be able to conduct a man‑in‑the‑middle attack to modify the served content.  
  **Source Code Analysis:**  
  • In `/code/src/DrawioClient/DrawioClientFactory.ts`, the `getOnlineHtml` method returns an HTML document whose `<meta>` tag defines a CSP as follows:  
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; connect-src * 'unsafe-inline'; img-src * data: blob: 'unsafe-inline'; frame-src *; style-src * 'unsafe-inline'; worker-src * data: 'unsafe-inline' 'unsafe-eval'; font-src * 'unsafe-inline' 'unsafe-eval';">
  ```  
  • No verification or restrictions (such as domain validation) are applied before the remote content is embedded into the webview.  
  **Security Test Case:**  
  1. In a controlled test environment, configure the extension settings so that:  
  – `"hediet.vscode-drawio.offline": false`  
  – `"online-url": "https://malicious.example.com/"` (with malicious.example.com serving a page that includes an inline script, such as one that triggers an alert)  
  2. Open a draw.io file using the extension to force the webview to load the online URL.  
  3. Verify that the injected malicious script executes (e.g. an alert dialog or console log appears).  
  4. Apply a tighter CSP in the code and confirm that the injected script is blocked.

---

- **Vulnerability Name:** Arbitrary Plugin Execution via Workspace Plugin Injection  
  **Description:**  
  The extension supports loading custom Draw.io plugins specified in workspace settings using variables like `${workspaceFolder}`. When a plugin is loaded, the extension reads its content from the workspace and computes a SHA‑256 fingerprint. If the plugin is not already recognized, the user is prompted to “allow” or “disallow” the plugin. An attacker who can inject a malicious plugin file into an untrusted workspace can craft a plugin that executes arbitrary JavaScript within the Draw.io webview (and by extension, the VS Code extension). Moreover, once accepted (or if the decision is stored under known plugins), the malicious code executes automatically on subsequent openings.  
  **Impact:**  
  • Arbitrary code execution in the context of the extension can result in data theft, diagram manipulation, or unauthorized triggering of commands within VS Code.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  • The plugin system prompts the user on first load and records the decision in the setting (`hediet.vscode-drawio.knownPlugins`) based solely on a SHA‑256 fingerprint match.  
  **Missing Mitigations:**  
  • There is no sandboxing or strict API boundary to isolate plugin code from core extension functionalities.  
  • Additional verification measures (e.g. code signature verification or deeper integrity checks beyond the simple hash) are needed.  
  • Improve user prompts to better convey the risks of loading unknown plugins, reducing accidental approval.  
  **Preconditions:**  
  • An attacker must be able to inject a malicious plugin file into a workspace (or cause the workspace settings to reference one).  
  • The user must approve the plugin (whether inadvertently or due to an ambiguous prompt) so that it is stored as “allowed”.  
  **Source Code Analysis:**  
  • In `/code/docs/plugins.md` and `/code/DrawioClient/DrawioClientFactory.ts`, the plugin path is defined via workspace settings. The method `getPlugins` iterates through configured plugin entries, reads the file, and computes its hash.  
  • If a plugin’s fingerprint is not already present in `hediet.vscode-drawio.knownPlugins`, the user is prompted (with options “Allow” or “Disallow”) via `window.showWarningMessage` without any further sandboxing or strict validation.  
  **Security Test Case:**  
  1. Create a test workspace that contains a malicious JavaScript file (e.g. `malicious.js`) that triggers an unexpected operation (such as sending data to an external server).  
  2. In the workspace settings, add an entry to load the plugin using the `${workspaceFolder}` variable.  
  3. Open a draw.io file using the extension; when prompted to allow the plugin, choose “Allow”.  
  4. Observe that the malicious plugin code executes (for example, by detecting an external request or alert).  
  5. Confirm that once “allowed”, the malicious plugin is loaded automatically in future sessions without a new prompt.

---

- **Vulnerability Name:** Inadequate Sanitization of Liveshare Session Data Leading to Code Injection  
  **Description:**  
  The extension’s Liveshare integration gathers view state updates from remote peers (such as cursor positions, selected cell IDs, and rectangles) and passes them directly to the Draw.io client via the `updateLiveshareViewState` command. There is no sanitization or validation of these inputs before they are forwarded. An attacker who joins a Liveshare session can craft malicious view state data (for example, inserting payloads like `"<img src=x onerror=alert('XSS')>"` into fields such as `selectedCellIds` or labels) that will be relayed to the Draw.io webview and processed by the Draw.io client potentially in an unsafe manner.  
  **Impact:**  
  • A malicious peer in a Liveshare session can achieve arbitrary code execution within the Draw.io webview context. This may lead to data exfiltration, unauthorized modifications within VS Code, or further compromise of the user’s local environment.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  • No input validation or sanitization is performed on session update data received via the Liveshare API. The raw view state from peers is accepted and forwarded to the Draw.io client.  
  **Missing Mitigations:**  
  • Implement strict validation and sanitization for all Liveshare session data before it is forwarded to the Draw.io client.  
  • Enforce proper escaping or use a whitelist to allow only expected characters and formats in view state fields.  
  • Optionally, incorporate additional verification to ensure that only authenticated and trusted peers’ data is processed.  
  **Preconditions:**  
  • The extension must be operating within a Liveshare session that permits peers to join (using a shared link with insufficient peer verification).  
  • The attacker must join the Liveshare session as a peer and be able to send crafted view state updates.  
  **Source Code Analysis:**  
  • In `SessionModel.ts`, the `apply` method stores incoming session updates directly from the Liveshare API without filtering.  
  • In `LiveshareSession.ts`, the method `updateLiveshareOverlaysInDrawio(editor)` aggregates view state data from `this.sessionModel.viewStatesByPeerId` and passes it to `editor.drawioClient.updateLiveshareViewState` without any sanitization.  
  • Within `CustomizedDrawioClient` (in `/code/src/DrawioClient/CustomizedDrawioClient.ts`), the `updateLiveshareViewState` method simply calls `sendCustomAction` to relay the payload to the webview.  
  **Security Test Case:**  
  1. Start a Liveshare session with two participants (an honest user and an attacker-controlled peer).  
  2. As the attacker, use the Liveshare API to send a crafted session update where one or more view state fields (e.g. `selectedCellIds`) include a malicious payload such as `"<img src=x onerror=alert('XSS')>"`.  
  3. Verify that the malicious update is received by the extension’s Liveshare session handler and then forwarded to the Draw.io client via `updateLiveshareViewState`.  
  4. Observe (within the webview context) that the payload is rendered and the malicious code executes (for example, an alert dialog appears).  
  5. After applying proper sanitization to the view state data, confirm that the malicious payload is neutralized and does not trigger code execution.