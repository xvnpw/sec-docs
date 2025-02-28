# Command Injection via Problem Identifier Parsing

- **Vulnerability Name:**  
  Command Injection via Problem Identifier Parsing

- **Description:**  
  The extension extracts a problem's identifier by reading a problem file's contents (or by falling back to the file name) using a loose regular expression. An attacker who supplies a manipulated repository can craft a problem file whose comment line (or even its file name) embeds shell metacharacters and extra commands. When the victim later triggers the "Show Problem" command, the extension passes the unsanitized problem identifier as an argument to an external command (via the "leetcode" CLI) that is executed with a shell. As a result, any injected shell commands will be interpreted and executed on the victim's machine.  

  *Step by step how an attacker can trigger this vulnerability:*  
  1. The attacker creates (or modifies) a problem file inside a repository distributed to the victim. In the file, the attacker inserts a specially crafted comment that adheres to the expected pattern while including unwanted shell metacharacters. For example, the file might include:  
     ```
     // @lc code=start id=123; touch /tmp/owned # 
     ```  
     Alternatively, if no comment exists, the extension falls back to using the file name—so a file can be named:  
     ```
     123; touch /tmp/owned.js
     ```  
  2. The victim opens the malicious repository in VS Code. The extension then attempts to later identify the problem by reading the file. It uses the regular expression `/@lc.+id=(.+?) /` (or, if no match is found, the file's base name) to capture the problem ID.
  3. Because the attacker's crafted comment (or file name) includes a payload (for instance, "123; touch /tmp/owned"), the extension extracts this entire string as the problem identifier.
  4. The extension's function that shows the problem — in particular, `showProblem()` in the `leetCodeExecutor` module — constructs a command array that includes the unsanitized problem identifier. It then calls a helper (which in turn calls Node's `child_process.spawn` with the `shell: true` option) to run a CLI command such as:  
     ```
     [ "node", "/path/to/vsc-leetcode-cli/bin/leetcode", "show", "123; touch /tmp/owned", "-c", "-l", "javascript" ]
     ```  
  5. With the shell enabled and no proper escaping applied, the injected "; touch /tmp/owned" is interpreted by the shell as an additional command, resulting in the attacker's payload being executed on the victim's machine.

- **Impact:**  
  An attacker can achieve arbitrary command execution (remote code execution) within the context of the victim's VS Code environment. This may allow the attacker to take complete control of the host system or perform further malicious actions.

- **Vulnerability Rank:**  
  High

- **Currently Implemented Mitigations:**  
  • The extension does wrap some file paths in quotes (e.g. `"${filePath}"`), but the key identifier value (derived from file content or file name) is not explicitly sanitized or escaped before being passed to a shell.  
  • There is no check or transformation on the captured problem identifier to remove shell metacharacters.

- **Missing Mitigations:**  
  • Proper input validation and sanitization on the problem identifier extracted from file contents.  
  • Use of safe child process APIs (for example, setting `shell: false` or using libraries that avoid command–line concatenation) or explicit escaping/whitelisting of allowed characters.  
  • Validation of file names and contents to ensure they match an expected strict format for problem IDs (e.g. numbers only).

- **Preconditions:**  
  • The victim must open a repository (or workspace) that contains a problem file whose content or file name has been manipulated.  
  • The malicious file must include a specially crafted comment (or have a malicious name) that the extension uses to extract the problem ID.  
  • The victim then triggers a command (e.g. "Show Problem") that causes the extension to run the affected function.

- **Source Code Analysis:**  
  1. **Extraction of Identifier:**  
     In `/code/src/utils/problemUtils.ts`, the function `getNodeIdFromFile` reads the file's content and applies the regex  
     ```
     /@lc.+id=(.+?) /
     ```  
     to capture the problem ID. If no match is found it uses the file's base name (splitting on "."). Neither path performs any sanitization to remove or escape shell metacharacters.
  
  2. **Usage in Command Execution:**  
     In `/code/src/leetCodeExecutor.ts`, the `showProblem` method builds a command array that includes the unsanitized `problemNode.id` along with other parameters (such as template type and language):  
     ```
     const cmd: string[] = [await this.getLeetCodeBinaryPath(), "show", problemNode.id, templateType, "-l", language];
     ```  
     This array is passed to `executeCommandWithProgressEx()`, which in turn ends up calling `executeCommand()` where Node's `child_process.spawn` is invoked with the option `{ shell: true }`.
  
  3. **Risk from Unsanitized Input:**  
     Using `shell: true` means that if the captured problem ID contains shell metacharacters (for example, a semicolon `;`), the full command string can be modified so that additional unintended commands (such as `touch /tmp/owned`) are executed by the shell.

- **Security Test Case:**  
  1. **Setup a Malicious File:**  
     • Create a file (e.g., `malicious.js`) with the following content:  
       ```js
       // @lc code=start id=123; touch /tmp/owned #
       // Some sample code
       ```  
     • Alternatively, rename a file to something like:  
       ```
       123; touch /tmp/owned.js
       ```  
  2. **Open in VS Code:**  
     • Open the malicious repository (or workspace) in VS Code so that the file is visible to the extension.
  3. **Trigger the Vulnerable Function:**  
     • In VS Code, trigger the "Show Problem" command (either via the context menu or Code Lens) for the problem corresponding to the malicious file.
  4. **Observe the Outcome:**  
     • Check whether the shell command injection was successful (for example, verify that the file `/tmp/owned` has been created as a result of the injected command).
  5. **Confirmation:**  
     • If the file is present, this confirms that the unsanitized problem identifier allowed arbitrary shell command execution.