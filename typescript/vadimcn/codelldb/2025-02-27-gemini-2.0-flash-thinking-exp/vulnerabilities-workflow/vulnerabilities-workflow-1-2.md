- **Vulnerability Name:** Unauthenticated RPC Debug Configuration Injection  
  **Description:**  
  When the user enables RPC mode (by setting “lldb.rpcServer”), the extension creates a TCP server (implemented in the class `RpcLaunchServer` in *externalLaunch.ts*) that listens for incoming data. The raw request payload is directly decoded and passed to YAML’s parser to merge with a default debug configuration. Although the code checks for a matching token if one is configured, the token is optional. An attacker who can connect to the RPC server’s port (for example, by binding to a non‑localhost interface) and send a crafted YAML payload can inject arbitrary properties into the debug configuration, resulting in an unintended debug session that runs arbitrary executables with custom arguments and environment variables.  
  **Impact:**  
  Exploiting this vulnerability may allow an attacker who can reach the RPC server to inject a debug configuration that launches arbitrary processes under the control of the attacker. In the worst case, this can lead to remote code execution and complete system compromise.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  - When a token is configured, the code compares the payload’s `"token"` property with the server’s token before processing the request.  
  **Missing Mitigations:**  
  - The token is optional, so in many deployments no authentication is enforced.  
  - There’s no restriction on the listening interface (e.g. forcing binding only to localhost).  
  - No whitelist of allowed configuration keys or additional input sanitization is applied before merging the payload with the default debug configuration.  
  **Preconditions:**  
  - The attacker must be able to connect to the TCP port served by the RPC interface—this is possible if the “lldb.rpcServer” setting is misconfigured to bind to an externally reachable interface.  
  **Source Code Analysis:**  
  - In *externalLaunch.ts*, the class `RpcLaunchServer` creates a Node.js net server with `allowHalfOpen: true`.  
  - On receiving a connection, it reads the full request string and passes it to the asynchronous method `processRequest()`.  
  - Inside `processRequest()`, a default debug configuration is defined and then extended via `Object.assign(debugConfig, YAML.parse(request))`.  
  - If a token is configured but the payload does not supply a matching token, the request is rejected—but if no token is set, any payload is accepted.  
  **Security Test Case:**  
  1. Configure a test instance of CodeLLDB with “lldb.rpcServer” enabled but no token set.  
  2. From a remote or network-controlled machine (or using a tool like Netcat), connect to the exposed TCP port and send a YAML payload such as:  
     ```yaml
     program: /bin/sh
     args: ['-c', 'touch /tmp/malicious_triggered']
     env:
       MALICIOUS: true
     ```  
  3. Verify that the extension launches a debug session using the supplied configuration (for instance, check that `/tmp/malicious_triggered` is created).  
  4. Next, set a token via “lldb.rpcServer.token” in your settings and confirm that a payload submitted without the correct token is rejected.

---

- **Vulnerability Name:** Malicious Debug Configuration Injection via Custom URI Handler  
  **Description:**  
  The extension registers a custom URI handler (in *externalLaunch.ts*, class `UriLaunchServer`) that processes “vscode://…” URLs to start a debug session. Depending on the URI path (for example, `/launch/config` or `/launch/command`), the handler decodes the query string and either passes it to YAML’s parser or tokenizes it using `stringArgv()` without any sanitization or validation. An attacker who convinces a victim to click on a specially crafted link can thereby control important fields in the debug configuration (such as the target executable, arguments, environment variables, etc.) and initiate a debug session that executes arbitrary commands.  
  **Impact:**  
  If exploited, this flaw may cause the extension to launch a debugging session with parameters chosen by the attacker. This might result in the execution of untrusted binaries or commands and could lead to remote code execution or system compromise.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - The URI handler distinguishes between different URI paths but does not otherwise perform any filtering or validation on the supplied payload.  
  **Missing Mitigations:**  
  - There is no sanitization or whitelist applied to the YAML or query-string payload.  
  - No user interaction/confirmation step is implemented to verify the debug session parameters before the session is started.  
  - No authentication checks are performed on the payload.  
  **Preconditions:**  
  - An attacker must deliver a crafted debug URI (for example, via phishing or by posting on a webpage) and the victim must click on it while running the extension.  
  **Source Code Analysis:**  
  - In *externalLaunch.ts*, the class `UriLaunchServer` implements the method `handleUri()`.  
  - For `/launch/config`, it decodes the query string and calls `YAML.parse(query)`, then immediately merges the resulting object into a default debug configuration.  
  - For `/launch/command`, the handler uses `stringArgv()` to parse a command line and then uses the parsed arguments without further sanitization.  
  **Security Test Case:**  
  1. Start an instance of VSCode with the CodeLLDB extension active.  
  2. Craft a URI such as:  
     ```
     vscode://vadimcn.vscode-lldb/launch/config?program:%20"/bin/sh"%0Aargs:%0A-%20"-c"%0A-%20"touch%20/tmp/malicious_triggered"
     ```  
  3. Trigger the URI (for example, via the command line using `code --open-url "<crafted URI>"` or by clicking a link).  
  4. Verify that the extension launches a debug session with the given parameters (e.g. check that `/tmp/malicious_triggered` is created).  
  5. Optionally, confirm that adding input validation prevents the attack when desired.

---

- **Vulnerability Name:** Unvalidated Webview HTML Injection via Debug Session Custom Event  
  **Description:**  
  The extension creates and manages debug-related webviews via the `WebviewManager` class (in *webview.ts*). In its event handler `onDebugSessionCustomEvent()`, the code listens for custom events with the name `_pythonMessage`. If the event body’s `message` property equals `"webviewSetHtml"`, the handler directly assigns the provided `html` string to the webview’s content:
  ```ts
  this.sessionPanels[e.session.id][e.body.id].webview.html = e.body.html;
  ```
  No sanitization or validation is performed on the HTML content in `e.body.html`. This means that if an attacker can inject a malicious custom event payload, they can cause arbitrary HTML (and potentially JavaScript) to be rendered in the webview.  
  **Impact:**  
  By injecting malicious HTML/JavaScript into the webview, an attacker could execute arbitrary code in the context of VSCode. This may lead to session hijacking, theft of sensitive data (such as credentials or debug information), or further lateral attacks within the user’s environment.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - There is no sanitization or filtering of the HTML payload before it is injected into the webview.  
  **Missing Mitigations:**  
  - Sanitization of the HTML content (e.g. stripping scripts or dangerous tags) before assignment.  
  - Validation that debug session custom events used to set webview content originate from trusted sources.  
  - An explicit confirmation step from the user before updating webview content using externally supplied HTML.  
  **Preconditions:**  
  - An attacker must be able to inject or manipulate a custom debug session event (for instance, by compromising a debug adapter or leveraging other debug configuration injection vulnerabilities) so that a `_pythonMessage` event with `message: "webviewSetHtml"` is delivered with a malicious HTML payload.  
  **Source Code Analysis:**  
  - In *webview.ts*, the method `onDebugSessionCustomEvent(e: DebugSessionCustomEvent)` processes events from the debug session.  
  - When `e.body.message` equals `"webviewSetHtml"`, the corresponding webview’s HTML is set directly:
    ```ts
    this.sessionPanels[e.session.id][e.body.id].webview.html = e.body.html;
    ```
  - No input sanitization is performed on `e.body.html` before this assignment.  
  **Security Test Case:**  
  1. Launch VSCode with the CodeLLDB extension installed and start a debug session.  
  2. Using a tool or a simulated debug adapter, send a custom debug session event with the following structure:
     ```json
     {
       "event": "_pythonMessage",
       "body": {
         "message": "webviewSetHtml",
         "id": "test_webview",
         "html": "<script>alert('XSS');</script>"
       }
     }
     ```
  3. Verify that the webview panel identified by “test_webview” updates its content to include the injected HTML.  
  4. Confirm that the script executes (e.g. an alert pops up), thereby demonstrating the successful injection of unsanitized HTML content.