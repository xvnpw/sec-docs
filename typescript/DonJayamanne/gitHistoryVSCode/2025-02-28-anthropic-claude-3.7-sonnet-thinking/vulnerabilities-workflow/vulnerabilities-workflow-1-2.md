# Vulnerability List

## Unsanitized File Name Injection in Webview HTML

### Description
The extension builds its HTML content for the history webview by interpolating dynamic data into an inline script. Although most variables (such as configuration settings and extension paths) are safely serialized with `JSON.stringify`, the file name (retrieved with `path.basename(fileUri.fsPath)`) is inserted directly into a JavaScript assignment. An attacker providing a repository with a maliciously crafted file name (for example, one including a single quote to break out of the string context) may inject arbitrary JavaScript code.

**Step-by-step trigger:**
1. The attacker supplies a repository that includes at least one file with a specially crafted name (for example: `evil';alert('XSS');//.txt`).
2. The victim then opens this repository in Visual Studio Code.
3. When the victim invokes the repository's git history view for that file, the extension builds the webview's HTML.
4. The inline script sets the file name using a pattern such as: `window['fileName'] = '${fileName}';`
5. Because the file name is not escaped or safely serialized, the injected payload breaks out of its intended string context and executes as JavaScript.

### Impact
An attacker who persuades a user to open a repository containing a malicious file name can cause arbitrary JavaScript code to run in the context of the extension's webview. This could lead to actions including data exfiltration, user impersonation, or further lateral escalation within the VS Code session.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
• All dynamic variables used elsewhere to generate the webview HTML (such as configuration settings and extension paths) are wrapped with `JSON.stringify` for proper serialization.
• The overall construction of the webview content is performed in a controlled manner.
However, the file name itself is not sanitized before interpolation into the inline script.

### Missing Mitigations
• The file name should be escaped—preferably by wrapping it with `JSON.stringify` or by using a dedicated sanitization routine—before it is placed into the inline script.
• A broader sanitization process should be applied to any strings derived from repository metadata that are later used in dynamically generated HTML.

### Preconditions
• The victim opens a repository in VS Code that is under attacker influence.
• At least one file in the repository has a name containing malicious characters (for example, embedded single quotes or script fragments).
• The victim triggers the file history view (or an equivalent feature) which constructs the webview using the unsanitized file name.

### Source Code Analysis
• In the (previously analyzed) file (for example, `src/server/htmlViewer.ts`), the function that builds the webview HTML includes a line that sets the file name via an inline script:
  ```js
  window['fileName'] = '${fileName}';
  ```
• Unlike other variables that are wrapped with safe serialization (such as using `JSON.stringify`), the file name is directly interpolated.
• Therefore, a payload (for example: `evil';alert('XSS');//.txt`) results in the output:
  ```js
  window['fileName'] = 'evil';alert('XSS');//txt';
  ```
  which prematurely terminates the string and executes the injected JavaScript.

### Security Test Case
1. **Setup:**
   - Create a new Git repository containing a file with the name: `evil';alert('XSS');//.txt`
   - Commit and push the repository.
2. **Execution:**
   - Open Visual Studio Code and load the repository containing the malicious file name.
   - Trigger the git history view (or corresponding command that opens the affected webview) for that file.
3. **Expected Outcome:**
   - The constructed webview HTML will include an inline script where the malicious payload is not escaped.
   - An injected JavaScript action (such as an alert dialog or other visible behavior) is executed.
4. **Verification:**
   - Confirm that the injected JavaScript payload executes as expected.
   - Inspect the rendered HTML in the webview to verify that the file name appears unsanitized.