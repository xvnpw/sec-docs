### Vulnerability List

- Vulnerability Name: Arbitrary File Open via Crafted Link in Preview
  - Description: A crafted markdown link in the preview, when clicked, can be used to open arbitrary files on the user's system due to insufficient sanitization of the `href` attribute in the `_crossnote.clickTagA` command handler.
    - Step by step description how someone can trigger vulnerability:
      1. An attacker crafts a malicious markdown file containing a link with a `file:///` URI pointing to a sensitive file on the user's system (e.g., `[Click here](file:///etc/passwd)`).
      2. The victim opens this malicious markdown file in VSCode with the Markdown Preview Enhanced extension.
      3. The preview of the markdown file is rendered, displaying the crafted link.
      4. The victim, either tricked or unknowingly, clicks on the crafted link in the preview.
      5. The `_crossnote.clickTagA` command handler in the extension processes the link. Due to insufficient validation, the extension attempts to open the file specified in the `href` (e.g., `/etc/passwd`) within VSCode.
  - Impact: An attacker could craft a malicious markdown file that, when previewed by a user, could trick the user into clicking a link that opens sensitive local files in VSCode. This could lead to information disclosure if the attacker can socially engineer the user to open and potentially copy content of sensitive files. In more advanced scenarios, if combined with other vulnerabilities or misconfigurations (outside of this project scope), it could potentially be a stepping stone for further exploitation.
  - Vulnerability Rank: High
  - Currently implemented mitigations: None. The code directly attempts to open the file path specified in the `href` after minimal processing, without proper validation or sanitization.
  - Missing mitigations:
    - Input validation and sanitization of the `href` attribute in the `_crossnote.clickTagA` command handler.
    - Restricting the allowed schemes and paths that can be opened via links in the preview. Only allow `http://`, `https://`, and relative file paths within the workspace. Block `file://` and other potentially dangerous schemes.
    - Implement a user confirmation dialog before opening any local files from links clicked in the preview, especially for `file://` URIs or absolute paths.
  - Preconditions:
    - User has the Markdown Preview Enhanced extension installed in VSCode.
    - User opens a malicious markdown file in VSCode and opens the preview.
    - User clicks on a crafted link in the preview.
  - Source code analysis:
    - File: `/code/src/extension-common.ts`
    - Function: `clickTagA`
    - Step-by-step analysis:
      1. The `clickTagA` function is triggered when a user clicks on a link in the preview, and it receives the link's `href` and `scheme`.
      2. The `href` is decoded using `decodeURIComponent(href)`.
      3. Several `replace` operations are performed on `href` to remove potential VS Code resource prefixes. However, these replacements do not prevent arbitrary `file:///` URIs from being processed.
      4. The code checks for specific file extensions (`.pdf`, `.xls`, etc.) and attempts to open them using `utility.openFile(href)`.
      5. If `href` starts with `${scheme}://` (which would be `file://` in our exploit case), it's parsed as a URI and VS Code's `workspace.openTextDocument` or `commands.executeCommand('vscode.open', ...)` is used.
      6. Critically, there is no check to validate if the `href` points to a safe or expected location. If the `href` is crafted as `file:///etc/passwd`, the code will attempt to open this sensitive file.
      ```typescript
      async function clickTagA({
        uri,
        href,
        scheme,
      }: {
        uri: string;
        href: string;
        scheme: string;
      }) {
        href = decodeURIComponent(href); // Step 3: Decode href
        href = href
          .replace(/^vscode\-resource:\/\//, '') // Prefix replacements
          .replace(/^vscode\-webview\-resource:\/\/(.+?)\//, '')
          .replace(/^file\/\/\//, '${scheme}:///')
          .replace(
            /^https:\/\/file\+\.vscode-resource.vscode-cdn.net\//,
            `${scheme}:///`,
          )
          .replace(/^https:\/\/.+\.vscode-cdn.net\//, `${scheme}:///`)
          .replace(
            /^https?:\/\/(.+?)\.vscode-webview-test.com\/vscode-resource\/file\/+/,
            `${scheme}:///`,
          )
          .replace(
            /^https?:\/\/file(.+?)\.vscode-webview\.net\/+/,
            `${scheme}:///`,
          );
        if ( // Step 5: Check file extensions
          ['.pdf', '.xls', '.xlsx', '.doc', '.ppt', '.docx', '.pptx'].indexOf(
            path.extname(href),
          ) >= 0
        ) {
          try {
            utility.openFile(href); // Step 5: Call utility.openFile
          } catch (error) {
            vscode.window.showErrorMessage(error);
          }
        } else if (href.startsWith(`${scheme}://`)) { // Step 6: Check scheme
          // ... VSCode API calls to open file ...
        } else if (href.match(/^https?:\/\//)) { // Step 7: Check http(s)
          vscode.commands.executeCommand('vscode.open', vscode.Uri.parse(href));
        } else {
          utility.openFile(href); // Step 8: Call utility.openFile for other cases
        }
      }
      ```
  - Security test case:
    1. Create a new markdown file named `poc.md`.
    2. Add the following markdown content to `poc.md`:
       ```markdown
       [Click here to open /etc/passwd](file:///etc/passwd)
       ```
       (For Windows, use a file like `[Click here to open C:\Windows\System32\drivers\etc\hosts](file:///C:/Windows/System32/drivers/etc/hosts)`)
    3. Open `poc.md` in VSCode.
    4. Open the preview for `poc.md` (using `Ctrl+Shift+V` or `Cmd+Shift+V`).
    5. In the preview, click on the link "Click here to open /etc/passwd" (or the Windows equivalent).
    6. Observe if VSCode attempts to open the `/etc/passwd` (or `hosts`) file in a new editor window. If VSCode successfully opens the file or attempts to (e.g., shows an error because of permissions but tries to access the file), the vulnerability is confirmed.