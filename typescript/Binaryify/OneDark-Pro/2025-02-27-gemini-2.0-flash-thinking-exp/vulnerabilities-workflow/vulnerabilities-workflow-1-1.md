- Vulnerability name: Cross-Site Scripting (XSS) in Changelog Webview
- Description:
    - An attacker gains write access to the GitHub repository of the One Dark Pro theme (e.g., through compromised maintainer account or by exploiting repository vulnerabilities).
    - The attacker modifies the `CHANGELOG.md` file and injects malicious JavaScript code within the markdown content. For example, they could inject an iframe or script tag with malicious JavaScript.
    - A user installs or updates the One Dark Pro VSCode extension.
    - The user executes the command `oneDarkPro.showChangelog` to view the changelog in a webview.
    - VSCode loads and renders the `CHANGELOG.md` content in a webview.
    - Due to the injected malicious JavaScript in `CHANGELOG.md`, the script executes within the context of the webview, potentially allowing the attacker to perform actions like stealing user tokens, accessing local resources (depending on webview context and CSP), or redirecting the user to a malicious website.
- Impact:
    - If successfully exploited, this vulnerability could allow an attacker to execute arbitrary JavaScript code within the VSCode extension's webview context. This could potentially lead to:
        - Stealing sensitive information (if accessible from webview context).
        - Performing actions on behalf of the user within VSCode.
        - Redirecting the user to external malicious websites.
        - Potentially gaining further access to the user's VSCode environment or system, depending on the capabilities of the webview and any exploited VSCode vulnerabilities.
- Vulnerability rank: high
- Currently implemented mitigations:
    - The project uses `marked.parse` to render markdown content in the webview. `marked` is known to sanitize HTML by default, which is a potential mitigation against basic XSS attacks.
- Missing mitigations:
    - Content Security Policy (CSP) for the webview to restrict the capabilities of the webview and prevent execution of inline scripts or loading of external resources.
    - Subresource Integrity (SRI) for any external resources loaded by the webview (though none are apparent in the provided code).
    - Regular security audits of the `CHANGELOG.md` and other markdown files to prevent accidental or malicious injection of harmful content.
- Preconditions:
    - Attacker needs to gain write access to the GitHub repository to modify `CHANGELOG.md`.
    - User must install the compromised extension version and execute the `oneDarkPro.showChangelog` command.
- Source code analysis:
    - In `src/webviews/Changelog.ts`:
        ```typescript
        import { ChangelogWebview } from './Webview'
        import { Uri, workspace } from 'vscode'
        import { TextDecoder } from 'util'
        import * as path from 'path'
        import { marked } from 'marked'

        export class ChangelogWebview extends WebviewController {
          // ...
          get content(): Promise<string> {
            const changelogPath = Uri.file(
              path.join(__dirname, '../../', 'CHANGELOG.md')
            )
            return Promise.resolve(workspace.fs.readFile(changelogPath))
              .then((data) => new TextDecoder().decode(data))
              .then((content) => marked.parse(content))
          }
        }
        ```
        - The `ChangelogWebview` class reads `CHANGELOG.md` and uses `marked.parse` to convert markdown to HTML.
        - The HTML content is then directly loaded into the webview using `this.panel.webview.html = fullHtml;` in `src/webviews/Webview.ts`.
        - If `CHANGELOG.md` is compromised and contains malicious JavaScript, and if `marked.parse` sanitization is bypassed or insufficient, XSS can occur.
- Security test case:
    1. **Prerequisite:** Set up a local development environment for VSCode extension development.
    2. **Modify `CHANGELOG.md`:** In the local repository of the One Dark Pro extension, modify the `CHANGELOG.md` file. Add the following malicious markdown content at the end of the file:
        ```markdown
        ## Malicious Section
        <script>
            // Malicious JavaScript code to demonstrate XSS
            alert('XSS Vulnerability in Changelog!');
        </script>
        ```
    3. **Package and install the extension:** Package the modified extension into a `.vsix` file and install it in VSCode using "Extensions: Install from VSIX...".
    4. **Execute the command:** Open VSCode and execute the command `One Dark Pro: Show Changelog` from the command palette (Ctrl+Shift+P or Cmd+Shift+P).
    5. **Verify XSS:** Check if an alert box with the message "XSS Vulnerability in Changelog!" appears. If the alert box appears, it confirms the XSS vulnerability.