## Vulnerability List for VSCode LeetCode Extension

Below is the updated list of high‐severity (and above) vulnerabilities discovered in the VS Code LeetCode extension, considering an external attacker perspective and filtering based on the provided criteria.

---

**Vulnerability Name:** Command Injection via Unsanitized File Path in Submission/Testing Commands  
**Description:**  
When the “Submit” or “Test” command is triggered, the extension obtains the active file’s path (via functions such as `getActiveFilePath`). That file path is then embedded into a quoted string (for example, `"${filePath}"`) and passed as an argument to a child process. Because the command is executed with shell interpretation (using `shell: true`), an attacker who is able to influence the workspace’s file names or paths (for example, by creating a file named:  
```
evil.js" && echo HACKED && "
```) can effectively “break out” of the quoted context and inject additional commands.  
**Impact:**  
Successful exploitation permits arbitrary command execution under the user’s VS Code process. This could result in remote code execution, leakage of sensitive data, or complete system compromise under the privileges of the user running VS Code.  
**Vulnerability Rank:** Critical  
**Currently Implemented Mitigations:**  
• The current code wraps the file path in quotes before passing it to the child process.  
**Missing Mitigations:**  
• Sanitize and escape file path values to remove or neutralize shell–special characters.  
• Replace use of `shell: true` with safer process–execution APIs (for example, using `execFile`) that pass arguments as an array without shell interpretation.  
**Preconditions:**  
• The attacker must be able to supply or force the presence of a file with a name containing malicious shell metacharacters in the workspace.  
• The user must open that file (making it the active document) and trigger the “Submit” or “Test” command.  
• The process execution is performed using the `shell: true` flag.  
**Source Code Analysis:**  
• In `src/leetCodeExecutor.ts` (invoked by `submit.ts` and `test.ts`), the method constructs command arguments by embedding the active file path directly into a quoted string without escaping.  
• For example:  
```ts
await this.executeCommandWithProgressEx(
  "Submitting to LeetCode...",
  this.nodeExecutable,
  [await this.getLeetCodeBinaryPath(), "submit", `"${filePath}"`]
);
```  
• If `filePath` contains shell metacharacters (for instance, an embedded quote or command separator), the shell will interpret these characters and allow command injection.  
**Security Test Case:**  
1. In a controlled workspace, create a file whose name includes shell–special characters (e.g.,  
   ```
   evil.js" && echo HACKED && "
   ```  
   ).  
2. Open this file in VS Code so that it becomes the active document.  
3. Trigger the “Submit” (or “Test”) command (via a CodeLens button or the command palette).  
4. Monitor the output channel or system logs to verify that an injected command (like printing “HACKED”) is executed.  
5. Confirm that the injected payload leads to arbitrary command execution.

---

**Vulnerability Name:** Command Injection via Malicious Test Case Input in the Test Command  
**Description:**  
When a user selects the “Write directly…” option under the test command, the extension displays an input box for custom test cases. The helper function `parseTestString` wraps the supplied input in quotes before adding it to the CLI call. On Unix-like systems, for example, it does:  
```ts
return `'${test}'`;
```  
Because this implementation does not escape quotes inside the user’s input, an attacker (or a manipulated input) containing embedded quotes (for example,  
```
'; echo HACKED; '
```) can break out of the quoting context. This manipulation results in the shell executing the injected command (`echo HACKED`, in this case).  
**Impact:**  
Exploitation allows an attacker (or a socially engineered input) to execute arbitrary shell commands in the context of the user’s system. This may lead to remote code execution and subsequent system compromise.  
**Vulnerability Rank:** High  
**Currently Implemented Mitigations:**  
• The test input is merely wrapped in quotes (single on Unix–like systems and double quotes on Windows when using CMD) without proper escaping of internal quotes.  
**Missing Mitigations:**  
• Escape all shell metacharacters (especially quotes) in test inputs.  
• Use a process–execution API (such as `execFile`) that passes arguments as a list rather than via a shell.  
• Enforce rigorous input validation on the test input field.  
**Preconditions:**  
• The user triggers the “Test” command and is prompted to enter custom test cases.  
• The attacker must be able to supply or influence the test input (e.g., via social engineering) that contains malicious characters.  
• The extension calls the CLI with `shell: true` enabled.  
**Source Code Analysis:**  
• In `src/commands/test.ts`, when the “Write directly…” option is chosen, the extension shows an input box to capture test data:  
```ts
const testString: string | undefined = await vscode.window.showInputBox({
  prompt: "Enter the test cases.",
  ...
});
```  
• The input is then passed to the helper function `parseTestString`, which for Unix–like systems returns a string using single quotes around the input without escaping embedded characters.  
• This processed string is appended to the CLI command and executed with shell interpretation.  
**Security Test Case:**  
1. Trigger the “Test” command via CodeLens or the command palette.  
2. When prompted, enter a malicious test input such as:  
   ```
   '; echo HACKED; '
   ```  
3. Confirm and execute the command.  
4. Check the extension’s output channel or logs for evidence (e.g., “HACKED”) that the injected command was executed.  
5. Validate that the malicious payload caused arbitrary command execution.

---

**Vulnerability Name:** Cross–Site Scripting (XSS) in LeetCode Solution Webview  
**Description:**  
When the extension displays a solution in its custom webview, it first parses the entire solution string (which contains fields such as title, URL, language, author, votes, and body) via the `parseSolution` function in `leetCodeSolutionProvider.ts`. The raw solution body is then passed directly to the markdown renderer through a call like:  
```ts
const body: string = markdownEngine.render(this.solution.body, {
  lang: this.solution.lang,
  host: "https://discuss.leetcode.com/",
});
```  
If an attacker can manipulate or supply a malicious solution string (for example, by controlling the network response from the LeetCode server or by intercepting the data in transit), they might inject HTML or JavaScript payloads (for instance, an `<img>` tag with an `onerror` attribute) into the solution’s markdown. The rendered HTML is then inserted into the webview without additional sanitization—a vector that can result in XSS.  
**Impact:**  
Successful exploitation enables the execution of arbitrary JavaScript code within the context of the extension’s webview. Although the webview is rendered in a sandboxed environment with a Content Security Policy (CSP), bypassing these restrictions may lead to phishing attacks, exfiltration of sensitive data, or manipulation of the displayed content to trick the user.  
**Vulnerability Rank:** High  
**Currently Implemented Mitigations:**  
• A restrictive CSP is embedded in the generated HTML (via a meta tag with directives such as `default-src 'none'`, `img-src https:`, `script-src vscode-resource:`, and `style-src vscode-resource:`).  
**Missing Mitigations:**  
• Sanitize and escape the solution content (especially the solution body) to strip any potentially dangerous HTML tags or attributes before processing it with the markdown renderer.  
• Ensure that the markdown engine itself is configured to either escape raw HTML or is followed by a robust HTML–sanitization routine.  
**Preconditions:**  
• The attacker must be able to control or modify the solution data (e.g., by compromising the remote server or via a man–in–the–middle attack) so that the rendered markdown includes malicious content.  
• The user must trigger the “Show Solution” command (or equivalently view the solution in a webview) so that the malicious payload is rendered.  
**Source Code Analysis:**  
• In `src/webview/leetCodeSolutionProvider.ts`, the method `parseSolution(raw: string)` partitions the raw solution input and assigns `solution.body` from unsanitized content.  
• Later, in `getWebviewContent()`, the solution fields (head, info, body) are inserted verbatim into an HTML template that is set as the content of the webview.  
• There is no intermediate sanitization filtering out unexpected HTML or JavaScript—in effect trusting the remote solution string completely.  
**Security Test Case:**  
1. Create a mock solution string with a malicious payload embedded in the solution body. For example, inject the following snippet as the solution body:  
   ```html
   <img src="x" onerror="alert('XSS')">
   ```  
2. Use the extension’s “Show Solution” command to render this crafted solution (this may involve simulating a network response or manually invoking the webview with the mock data).  
3. Observe the webview; if the payload executes (for example, an alert box pops up), this confirms that XSS is possible.  
4. Verify that the payload is not being sanitized and that the injected script executes in the context of the webview.