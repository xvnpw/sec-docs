# Critical Vulnerabilities in VS Code PDF Preview Extension

## Supply Chain Code Injection via Manipulated PDF.js Libraries

  - **Description:**
    - A threat actor can craft a malicious repository that contains altered versions of the PDF.js libraries (e.g. modified files in the "lib" folder such as `pdf.js`, `viewer.js`, or `main.js`).
    - The published instructions (in README) explicitly instruct users to "overwrite ./lib/* by extracted directories" when upgrading PDF.js.
    - When a victim installs or updates the extension using the manipulated repository, the extension's webview will load and execute these malicious (attacker‐controlled) scripts.
    - Once executed in the trusted context of VS Code's webview (which has JavaScript enabled), the malicious code could perform arbitrary operations or communicate with other parts of VS Code and the local system.
  
  - **Impact:**
    - **Remote Code Execution (RCE):** The malicious scripts run inside VS Code's webview can execute arbitrary JavaScript code with access to the extension's privileges.
    - **Privilege Escalation:** Abusing the extension's trusted context may allow command execution via VS Code APIs, read sensitive workspace data, or modify local files.
    - **Supply Chain Compromise:** The integrity of the PDF preview feature is undermined because the extension blindly loads local libraries from its repository without checking their authenticity.
  
  - **Vulnerability Rank:** Critical
  
  - **Currently Implemented Mitigations:**
    - The webview HTML (constructed in `pdfPreview.ts`) is built using a Content Security Policy (CSP) that restricts network connections and limits resource origins.
    - The webview is configured to load local resources only from paths that are under the extension root (using `localResourceRoots`).
    - However, these mitigations do not help when the entire repository source (including the "lib" folder) is maliciously altered.
  
  - **Missing Mitigations:**
    - **Integrity Verification:** No cryptographic integrity checks (code signing or hash verification) are performed on the library files loaded from the "lib" folder.
    - **Sandboxing for Webview Scripts:** The webview does not isolate externally loaded scripts (which are marked as "unsafe-inline" in the CSP) from the extension's privileged context.
    - **Update Process Hardening:** No measures exist to verify that the upgraded libraries match trusted versions provided by the official PDF.js release.
  
  - **Preconditions:**
    - The victim installs or upgrades the extension from a repository whose contents have been manipulated by an attacker.
    - The extension's README instructions are followed (overwriting the "lib" folder with contents from the repository), thereby introducing malicious script files.
    - The webview is enabled with full script execution (as set by `enableScripts: true`) and configured to trust all files within the extension folder.
  
  - **Source Code Analysis:**
    - In `extension.ts`, the extension sets the extension root with  
      `const extensionRoot = vscode.Uri.file(context.extensionPath);`
      and later passes this to the custom PDF provider.
    - In `pdfPreview.ts`, the function `getWebviewContents()` constructs the webview's HTML page. It calls a helper function `resolveAsUri(...)` that simply uses `path.join` with the extension root to build URIs. For example:
      - `<script src="${resolveAsUri('lib', 'build', 'pdf.js')}"></script>`
      - `<script src="${resolveAsUri('lib', 'web', 'viewer.js')}"></script>`
      - `<script src="${resolveAsUri('lib', 'main.js')}"></script>`
    - If the repository has been manipulated, the "lib" folder may contain attacker-supplied JavaScript code. Because the webview is created with `enableScripts: true` and its local resource roots are set to include the extension folder, these malicious scripts are loaded and executed without further integrity checks.
    - Although a CSP is enforced, it only restricts network origins; the CSP still allows inline execution (via the use of `'unsafe-inline'` in the script-src directive) and does nothing to validate the origin of the loaded local files.
  
  - **Security Test Case:**
    - **Step 1:** Create a manipulated version of the repository. In this version, modify one or more of the PDF.js library files in the "lib" folder (for example, insert a payload into `lib/main.js` that logs a message to the console or triggers an alert—this stands in for malicious code that would attempt RCE).
    - **Step 2:** Follow the upgrade instructions in the README to overwrite the existing "lib" folder with the manipulated content.
    - **Step 3:** Launch VS Code with the extension installed.
    - **Step 4:** Open a PDF file so that the PDF preview is activated.
    - **Step 5:** Observe that the manipulated `lib/main.js` (or other altered file) is loaded by the webview and that the payload executes (for example, by confirming that the injected alert or console message appears).
    - **Step 6:** (Optional) Attempt to use additional commands or API calls from the malicious script to prove that arbitrary code execution is possible within the extension's privileged context.