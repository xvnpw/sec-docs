- **Vulnerability Name**: Server‑Side Request Forgery (SSRF) via Remote Stylesheet Fetch

  - **Description**:  
    The extension allows users to configure external (remote) CSS style sheets via the `"css.styleSheets"` setting (typically in a workspace’s `.vscode/settings.json`). When a remote URL is specified (i.e. one matching the regular expression `/^https?:\/\//i`), the extension calls its `getRemote()` function, which in turn uses the native `fetch` API to retrieve the stylesheet. An attacker who can supply or influence the workspace configuration can set this setting to point to a malicious or internal URL. When the user opens the workspace, the extension blindly fetches the stylesheet from that URL. This gives an attacker control over the target endpoint of the request and enables the abuse of the extension as a proxy for making arbitrary HTTP/HTTPS requests—including to internal network addresses.

  - **Impact**:  
    - An attacker may leverage the extension to perform internal network scanning or access sensitive internal resources that are not normally exposed to the Internet.  
    - The victim’s machine may be forced to initiate requests to endpoints chosen by the attacker.  
    - Sensitive data could be unintentionally exposed if the remote resource returns confidential information based on the victim’s network context.

  - **Vulnerability Rank**: High

  - **Currently Implemented Mitigations**:  
    - In `Provider.getStyles` (in *src/provider.ts*), the code checks if a style sheet is remote using a simple regular expression (`/^https?:\/\//i`).  
    - No further checks (such as input sanitization or domain restrictions) are applied before invoking `fetch` on the supplied URL.

  - **Missing Mitigations**:  
    - There is no validation or sanitization on remote URLs provided via the configuration.  
    - The extension lacks measures such as whitelisting trusted domains or blacklisting internal/private IP addresses.  
    - No user confirmation or prompt is implemented before fetching external content.

  - **Preconditions**:  
    - The attacker must be able to inject or influence the workspace configuration (for example, by including a malicious `.vscode/settings.json` in a project the victim downloads or opens).  
    - The victim’s environment must allow outbound network requests from VSCode extensions.  
    - The remote URL provided must resolve to a target of the attacker’s choice (for instance, an internal endpoint).

  - **Source Code Analysis**:  
    - **Step 1 – Configuration Reading**:  
      In `src/settings.ts`, the `getStyleSheets` function reads the `"css.styleSheets"` configuration without any sanitization. It also performs variable substitutions based solely on the file path.  
      
    - **Step 2 – Determining Remote URLs**:  
      In `src/provider.ts`, within the `getStyles` method, each stylesheet glob is evaluated. For any glob that matches the regular expression `/^https?:\/\//i` (accessed via the `isRemote` getter), the stylesheet is considered remote.
      
    - **Step 3 – Fetching Remote Content**:  
      For remote URLs, the `getRemote()` function is called. This function simply invokes the built‑in `fetch(url)` to retrieve the content. No additional checks or restrictions are performed on the URL.
      
    - **Step 4 – Processing Fetched Content**:  
      The fetched remote content is then passed to the `parse()` function (in *src/parser.ts*) where the extension extracts CSS selectors to support completions and "go to definition" features.
      
    - **Visualization**:  
      1. **User Configuration** → `.vscode/settings.json` includes a remote URL (e.g., `"http://malicious-server.local/malicious.css"`).  
      2. **Settings Module** → `getStyleSheets` returns this URL (after variable substitution, if any).  
      3. **Provider Module** → `getStyles` detects the URL is remote (using `/^https?:\/\//i`).  
      4. **Remote Fetch** → `getRemote()` is called and `fetch(url)` is used to request the content.  
      5. **Parsing** → The response is parsed and used for providing intellisense.
      
    - **Conclusion**:  
      Because no further validation or sanitization is applied between reading the configuration and fetching the remote resource, an attacker can force the extension to initiate arbitrary HTTP/HTTPS requests.

  - **Security Test Case**:  
    - **Step 1**:  
      Prepare a workspace directory and create a `.vscode/settings.json` file with the following content:
      ```json
      {
          "css.styleSheets": [ "http://malicious-server.local/malicious.css" ]
      }
      ```
    - **Step 2**:  
      Set up a controlled HTTP server at `malicious-server.local` that logs all incoming requests.
    - **Step 3**:  
      Open the workspace in Visual Studio Code with the vulnerable extension enabled.
    - **Step 4**:  
      Open or edit an HTML document (or otherwise trigger the extension’s auto‑validation/completion functionality).
    - **Step 5**:  
      Observe the controlled server logs.  
      **Expected Result**: A request from the extension to `http://malicious-server.local/malicious.css` is logged, thereby confirming that the extension fetched the remote URL without proper validation.