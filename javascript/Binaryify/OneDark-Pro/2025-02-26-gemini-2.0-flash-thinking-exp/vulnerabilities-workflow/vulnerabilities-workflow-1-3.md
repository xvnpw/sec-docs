### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) in Changelog Webview
- Description:
  1. An attacker contributes to the project by submitting a pull request that modifies the `CHANGELOG.md` file.
  2. The attacker injects malicious markdown code into `CHANGELOG.md`, for example, including Javascript code within HTML tags or using Javascript-based markdown features if supported by `marked.parse()`.
  3. The project maintainers merge the malicious pull request.
  4. A new version of the extension containing the malicious `CHANGELOG.md` is released and installed/updated for users.
  5. A user opens the changelog webview by executing the `oneDarkPro.showChangelog` command.
  6. The extension reads the `CHANGELOG.md` file and uses `marked.parse()` to render its content as HTML within the webview.
  7. The malicious Javascript code injected by the attacker in `CHANGELOG.md` gets executed within the context of the webview, potentially allowing the attacker to perform actions within the VS Code environment on behalf of the user, within the limitations of the webview context.
- Impact:
  Cross-Site Scripting (XSS) vulnerability allows an attacker to execute arbitrary Javascript code within the context of the Changelog webview in VS Code. The impact is limited to what can be achieved within a VS Code webview context, but it could potentially lead to information disclosure, UI manipulation within the webview, or further exploitation depending on the capabilities exposed by the webview and VS Code API accessible from the webview context.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  None. The `marked.parse()` function is used directly without sanitization of the input `CHANGELOG.md` content.
- Missing Mitigations:
  Input sanitization should be performed on the `CHANGELOG.md` content before passing it to `marked.parse()`. Alternatively, a safer markdown parsing library that is less prone to XSS vulnerabilities could be used, or options in `marked.parse()` should be checked to disable or sanitize potentially unsafe HTML/Javascript execution. Content Security Policy (CSP) for the webview could also be considered to restrict the capabilities of executed scripts.
- Preconditions:
  - Attacker needs to be able to contribute to the project and get malicious markdown code merged into `CHANGELOG.md`.
  - A user needs to install or update to a version of the extension containing the malicious `CHANGELOG.md`.
  - The user needs to explicitly open the changelog webview by executing the `oneDarkPro.showChangelog` command.
- Source Code Analysis:
  1. File: `/code/src/webviews/Changelog.ts`
  2. Function: `ChangelogWebview.content` getter.
  3. Code:
     ```typescript
     get content(): Promise<string> {
         const changelogPath = Uri.file(
           path.join(__dirname, '../../', 'CHANGELOG.md')
         )
         return Promise.resolve(workspace.fs.readFile(changelogPath))
           .then((data) => new TextDecoder().decode(data))
           .then((content) => marked.parse(content)) // Vulnerable line: marked.parse() without sanitization
     }
     ```
  4. The code reads the content of `CHANGELOG.md` and directly passes it to `marked.parse()`.
  5. `marked.parse()` processes markdown and converts it to HTML. If `CHANGELOG.md` contains malicious markdown that can be interpreted as executable Javascript or unsafe HTML, it will be rendered in the webview, leading to XSS.
- Security Test Case:
  1. Modify the `CHANGELOG.md` file in a local clone of the project.
  2. Add the following malicious markdown code to `CHANGELOG.md`:
     ```markdown
     ## Vulnerability Test

     <img src="x" onerror="alert('XSS Vulnerability in Changelog Webview!')">

     [Malicious Link](javascript:alert('XSS from link'))

     <script>alert('XSS from script tag')</script>

     \`\`\`html
     <script>alert('XSS from code block')</script>
     \`\`\`
     ```
  3. Package and install the modified extension in VS Code using `vsce package` and `Extensions: Install from VSIX...`.
  4. Open VS Code and execute the command `One Dark Pro: Show Changelog` (or `oneDarkPro.showChangelog` command ID).
  5. Observe if the alert boxes are displayed in the Changelog webview. If any of the `alert()` calls are executed, it confirms the XSS vulnerability.