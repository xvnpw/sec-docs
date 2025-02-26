- **Vulnerability Name:** Webview Content Injection via Unsanitized Markdown in Changelog

  - **Description:**
    - The extension’s changelog feature reads the local file `CHANGELOG.md` and decodes its content.
    - This content is converted into HTML using the third‑party library `marked` via a call to `marked.parse(content)` without any sanitization.
    - The resulting HTML is then directly injected into a VSCode webview (via assignment to `this.panel.webview.html` in `src/webviews/Webview.ts`), without applying a strict Content Security Policy.
    - An external attacker who is able to modify or replace the `CHANGELOG.md` file (for example, by compromising the update channel or obtaining write‑access to the extension’s installation directory) can inject a malicious payload (for example, `<script>alert('XSS');</script>`).
    - When an unsuspecting user executes the command (such as via the command palette using `oneDarkPro.showChangelog`), the manipulated HTML is rendered in the webview and the payload executes.

  - **Impact:**
    - Successful exploitation results in cross‑site scripting (XSS) within the webview.
    - An attacker can execute arbitrary JavaScript within the extension’s context, potentially leading to interface manipulation, exfiltration of configuration data, or further compromise of the user’s VSCode environment.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The conversion of markdown to HTML is performed directly through `marked.parse(content)` without further processing.
    - No strict Content Security Policy (CSP) is enforced on the webview to restrict the execution of inline scripts.

  - **Missing Mitigations:**
    - **HTML Sanitization:** Before injecting the HTML into the webview, it should be processed with a sanitization library (e.g., DOMPurify) to strip or escape dangerous elements and attributes.
    - **Content Security Policy (CSP):** The webview should enforce a strict CSP (for example, disallowing inline scripts) so that even if malicious HTML is injected, its script execution potential is limited.
    - **File Integrity Validation:** Implement integrity or signature verification measures to ensure that critical local files like `CHANGELOG.md` have not been tampered with.

  - **Preconditions:**
    - The attacker must have a means to modify or replace the `CHANGELOG.md` file in the extension’s installation directory.
    - The extension’s changelog display command (such as `oneDarkPro.showChangelog`) must be executed by the user, triggering the rendering of the unsanitized HTML in the webview.

  - **Source Code Analysis:**
    - In `src/webviews/Changelog.ts`, the path to the changelog file is constructed as follows:
      ```ts
      const changelogPath = Uri.file(path.join(__dirname, '../../', 'CHANGELOG.md'))
      ```
    - The file is then read and its contents decoded:
      ```ts
      workspace.fs.readFile(changelogPath)
        .then((data) => new TextDecoder().decode(data))
      ```
    - The decoded content is converted to HTML without sanitization:
      ```ts
      .then((content) => marked.parse(content))
      ```
    - In `src/webviews/Webview.ts`, the HTML is directly injected into the webview:
      ```ts
      this.panel.webview.html = fullHtml
      ```
    - The absence of sanitization and CSP enforcement means that any malicious payload embedded in `CHANGELOG.md` will be executed when rendered.

  - **Security Test Case:**
    - **Preparation:**
      - Locate the extension’s `CHANGELOG.md` file within its installation directory.
      - Modify the file to include a test payload, for example:
        ```markdown
        # Changelog

        <script>alert('XSS');</script>
        ```
    - **Execution:**
      - Launch Visual Studio Code with the extension installed.
      - Open the command palette and invoke the command `oneDarkPro.showChangelog`.
    - **Verification:**
      - A webview should appear displaying the changelog.
      - The appearance of an alert box with the message `XSS` confirms that the unsanitized HTML rendered the test payload, thereby triggering script execution.
    - **Conclusion:**
      - The successful display of the alert verifies that the extension is vulnerable to webview content injection via unsanitized markdown.