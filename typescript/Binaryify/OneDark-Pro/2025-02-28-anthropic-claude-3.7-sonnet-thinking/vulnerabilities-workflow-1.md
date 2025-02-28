# Vulnerabilities in One Dark Pro Extension

After a thorough analysis of the One Dark Pro VSCode extension, one high-severity vulnerability has been identified.

## Webview Markdown Code Injection via Manipulated CHANGELOG.md

### Description
The extension defines a webview (in `ChangelogWebview` in `/code/src/webviews/Changelog.ts`) that loads its HTML content by reading a local `CHANGELOG.md` file. The file is read using the VSCode file system API and decoded with `TextDecoder`. Its content is then converted to HTML by calling `marked.parse` without any sanitization. The resulting HTML is assigned (via `this.panel.webview.html = fullHtml` in `/code/src/webviews/Webview.ts`) to a webview that is created with the option `enableScripts: true`. An attacker who supplies a manipulated extension repository with a maliciously crafted `CHANGELOG.md` (for example containing embedded `<script>` tags or event handler attributes) will cause the unsanitized HTML to be rendered in the webview—thereby executing arbitrary JavaScript in that context.

### Impact
The injected JavaScript runs with the privileges of the webview, potentially allowing an attacker to:
- Access or interact with VSCode APIs exposed to the webview.
- Exfiltrate data or hijack user interactions.
- Tamper with the extension's user interface.

Although the attack scope is limited to the webview context, further exploitation may be possible depending on the APIs or data available.

### Vulnerability Rank
High

### Currently Implemented Mitigations
Currently, the output of `marked.parse` is passed directly to the webview's HTML. No additional sanitization, HTML filtering, or Content Security Policy (CSP) is applied between parsing and rendering.

### Missing Mitigations
- Sanitize or escape the HTML output from the markdown parser to remove or neutralize embedded `<script>` tags and on-event attributes.
- Configure the markdown parser to disallow raw HTML (for example, by using an option or a separate sanitization library).
- Include a strict CSP meta tag in the generated HTML for the webview to block inline scripts or scripts from untrusted sources.

### Preconditions
- The attacker must supply a manipulated version of the extension repository where the `CHANGELOG.md` file is replaced with one containing a malicious payload.
- The victim inadvertently installs and runs this manipulated extension.
- The victim (or an automated process) triggers a command (for example, "Show Changelog") that opens the webview.

### Source Code Analysis
In **`/code/src/webviews/Changelog.ts`**:
- The code constructs the file path for `CHANGELOG.md` using `__dirname` and reads its contents with `workspace.fs.readFile(...)`.
- The binary data is decoded using `new TextDecoder().decode(data)` and then converted to HTML via `marked.parse(content)` without sanitization.

In **`/code/src/webviews/Webview.ts`**:
- The `show()` method awaits the HTML produced by `ChangelogWebview` and assigns it directly to the webview's content with `this.panel.webview.html = fullHtml`.
- The webview is created with `enableScripts: true`, which permits any JavaScript present in the HTML to execute.

Because there is no sanitization between reading, parsing, and rendering of the markdown content, any embedded malicious payload in `CHANGELOG.md` will be executed when the webview is displayed.

### Security Test Case
1. Create a modified version of `CHANGELOG.md` that includes a malicious payload, for example:
   ```markdown
   # Changelog

   <script>alert("XSS triggered via malicious CHANGELOG.md");</script>
   ```
2. Package the extension (or simulate the repository) with this modified `CHANGELOG.md` in place.
3. Install the extension in a VSCode instance.
4. Use the command palette to invoke the command (for example, `oneDarkPro.showChangelog`) that opens the webview.
5. Verify that the malicious script executes (e.g., an alert dialog appears), confirming that unsanitized markdown content leads to code injection in the webview.
6. Document the evidence of the vulnerability.

The remaining functionality of the extension, primarily focused on providing visual themes through static configuration files and theme generation scripts, does not appear to contain additional high-severity vulnerabilities related to RCE, Command Injection, or Code Injection.