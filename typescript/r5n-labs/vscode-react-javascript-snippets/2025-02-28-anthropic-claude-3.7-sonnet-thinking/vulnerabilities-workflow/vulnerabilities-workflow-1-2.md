# Vulnerabilities in VSCode Extension

## Malicious Snippet Injection Leading to Remote Code Execution

- **Vulnerability Name:**  
  Malicious Snippet Injection Leading to Remote Code Execution

- **Description:**  
  An attacker who controls the repository's snippet definitions can modify (or inject) a malicious snippet body. For example, the attacker may replace a safe snippet body with one that contains a snippet variable referencing a VS Code command (e.g. `${command:malicious.trigger}` or other command‐invoking placeholder). When the victim (who has installed this manipulated repository) triggers the snippet search command from the extension, the following happens step by step:
  1. The extension's generator (in `generateSnippets.ts`) collates all snippet definitions from the repository's source snippets into a JSON file (`generated.json`).
  2. The malicious snippet definition—crafted by the attacker—is written into this generated file.
  3. When a user runs the command registered as `'reactSnippets.search'`, the extension reads and parses the JSON file from disk using Node's `readFileSync` and `JSON.parse`.
  4. The extension then calls its `parseSnippet` routine (which includes formatting via Prettier and placeholder replacement) on the snippet's body. This routine does not neutralize or validate snippet placeholders.
  5. Finally, the extension passes the resulting string to VS Code's snippet API via `new SnippetString(body)` and inserts it into the active editor.
  6. If the snippet body contains a malicious placeholder (for example, one that causes VS Code to evaluate a command variable), then during snippet expansion the VS Code snippet engine may invoke the unwanted command.
  
- **Impact:**  
  If the injected command placeholder is processed by VS Code, the attacker may achieve remote code execution in the context of the editor. This could lead to arbitrary command execution on the victim's system, data exfiltration, or further compromise of the host environment.

- **Vulnerability Rank:**  
  Critical

- **Currently Implemented Mitigations:**  
  • The extension simply reads snippet definitions from a generated JSON file and passes them through simple string formatting (via Prettier and placeholder replacement).  
  • No runtime filtering or sanitization is performed on the snippet bodies before insertion into the text editor.

- **Missing Mitigations:**  
  • There is no validation or sanitization of snippet content to detect or neutralize dangerous placeholder patterns (such as `${command:…}` or similar constructs).  
  • There is no white-listing or escaping of snippet variables that might trigger execution of VS Code commands.  
  • The extension trusts the content of the repository's snippet definitions without checking for injected payloads.

- **Preconditions:**  
  • The attacker must be able to supply a manipulated repository (for example, through a compromised supply chain or by persuading a victim to install the extension from an attacker‑controlled branch).  
  • The victim must activate the extension and trigger the snippet search command so that the malicious snippet is read, parsed, and ultimately inserted into an open editor.  
  • VS Code must process the malicious snippet body in a way that resolves and executes dangerous snippet variables.

- **Source Code Analysis:**  
  1. In **`generateSnippets.ts`** the extension aggregates snippet definitions from various source files. These source arrays (found in files like `components.ts`, `imports.ts`, etc.) are reduced into an object where each snippet's body is processed by the function `parseSnippetToBody` (which in turn calls formatting via `formatSnippet` and placeholder replacement via `replaceSnippetPlaceholders`).
  2. In **`snippetSearch.ts`** the extension reads the generated JSON snippet file using  
     ```js
     const snippets = readFileSync(__dirname + '/../snippets/generated.json', 'utf8');
     ```  
     and then parses it with `JSON.parse`. The QuickPick list items are built using the snippet's prefix, description, and body.
  3. When a user selects a snippet in the QuickPick, the raw snippet's body is run through `parseSnippet(rawSnippet.body)`. This function calls `formatSnippet(revertSnippetPlaceholders(snippetBody))` without any sanitization to remove potentially dangerous snippet variables.
  4. Finally, the snippet is inserted using  
     ```js
     activeTextEditor.insertSnippet(new SnippetString(body));
     ```  
     which means that any injected placeholder (such as one that invokes a command) will be processed by VS Code's snippet engine.
  5. Since there is no check to remove or escape `${command:…}` variables, an attacker-controlled snippet may trigger unintended command execution.

- **Security Test Case:**  
  1. **Preparation:**  
     - Create a malicious repository branch (or fork) that alters one of the snippet definitions (for example, in one of the source snippets like `components.ts`) so that its body contains a malicious placeholder such as:  
       ```
       "body": [
         "${command:malicious.trigger}",
         "Some safe filler text"
       ]
       ```  
     - Ensure that this malicious snippet is included in the repository and will be processed by the extension's generate routine.
  2. **Deployment:**  
     - Install the VS Code extension from the manipulated repository.
     - Open VS Code in a workspace where the extension is active.
  3. **Execution:**  
     - Trigger the extension command (e.g. via the command palette using "ES7 snippet search").
     - In the QuickPick list, select the malicious snippet (identify it by its prefix or injected description).
     - Confirm that the snippet is inserted into the active editor.
  4. **Observation:**  
     - Check if the malicious placeholder is expanded and if the associated command is executed (for example, by monitoring for unexpected actions such as opening unauthorized files, launching external commands, or logging output that indicates the command was triggered).
     - Verify through logging or debugger that a VS Code command (e.g. `malicious.trigger`) is attempted/executed.
  5. **Conclusion:**  
     - If the inserted snippet causes an unexpected command execution (or triggers any payload), this validates that the extension is vulnerable to malicious snippet injection leading to remote code execution.