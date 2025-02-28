# Vulnerabilities in ES7+ React/Redux/React-Native/JS Snippets VS Code Extension

After analyzing the codebase of the ES7+ React/Redux/React-Native/JS snippets VS Code extension, I've identified the following critical vulnerabilities that could lead to remote code execution (RCE), command injection, or code injection:

## Remote Code Execution via Malicious Prettier Configuration

### Vulnerability name
Remote Code Execution via Malicious Prettier Configuration

### Description
The extension allows the use of Prettier configuration from the workspace to format snippets. When a user has this extension installed and opens a malicious repository, the extension will load Prettier configuration from that repository via the `prettier.resolveConfig()` method with `editorconfig: true` enabled. This configuration is then used without proper validation when formatting snippets.

In `getPrettierConfig.ts`:
```typescript
let prettierConfig: prettier.Options | null;
prettier
  .resolveConfig('', { editorconfig: true })
  .then((config) => (prettierConfig = config));

const getPrettierConfig = (): Options => {
  const { prettierEnabled } = extensionConfig();
  return {
    parser: 'typescript',
    ...(prettierEnabled && prettierConfig),
  };
};
```

The extension blindly merges and uses whatever configuration is loaded from the repository, which can include malicious plugins or options.

### Impact
An attacker can create a malicious repository with specially crafted Prettier configuration that loads arbitrary code through custom plugins. When a victim opens this repository in VS Code with this extension installed, the malicious Prettier configuration will be loaded and executed when snippets are generated or formatted, leading to arbitrary code execution in the context of the VS Code process.

### Vulnerability rank
Critical

### Currently implemented mitigations
None. The extension does not validate or sanitize the Prettier configuration loaded from the workspace.

### Missing mitigations
1. Disable the use of custom Prettier plugins from workspace configurations
2. Whitelist allowed Prettier configuration options
3. Sandbox the formatting process
4. At minimum, display a security warning when loading Prettier configuration from untrusted workspaces

### Preconditions
1. Victim must have the VS Code extension installed
2. Victim must open a repository containing malicious Prettier configuration
3. Extension's prettierEnabled setting must be true (which is the default)

### Source code analysis
The vulnerability exists in the following execution flow:

1. In `getPrettierConfig.ts`, the extension initializes by resolving Prettier configuration:
   ```typescript
   prettier.resolveConfig('', { editorconfig: true })
     .then((config) => (prettierConfig = config));
   ```
   This loads configuration from any `.prettierrc`, `.prettierrc.js`, or `prettier` field in `package.json` in the current workspace.

2. When the extension needs to format snippets in `formatters.ts`, it uses this configuration:
   ```typescript
   export const formatSnippet = (snippetString: string) => {
     return extensionConfig().prettierEnabled
       ? prettier.format(snippetString, getPrettierConfig())
       : snippetString;
   };
   ```

3. The configuration can specify custom plugins that get loaded and executed:
   ```typescript
   // In getPrettierConfig.ts
   return {
     parser: 'typescript',
     ...(prettierEnabled && prettierConfig),
   };
   ```
   
4. This happens when:
   - The extension activates and generates snippets (`await generateSnippets()` in `index.ts`)
   - Configuration changes trigger regeneration of snippets
   - User searches for a snippet via the command palette

### Security test case
1. Create a malicious repository with the following `.prettierrc.js` file:
   ```javascript
   module.exports = {
     plugins: [
       {
         parsers: {
           typescript: {
             parse: (text, parsers, options) => {
               // Malicious code execution
               const process = require('child_process');
               process.execSync('calc.exe'); // Launch calculator on Windows as proof
               
               // Return valid AST to avoid errors
               return require('prettier/parser-typescript').parsers.typescript.parse(text, options);
             }
           }
         }
       }
     ]
   };
   ```

2. Commit and push this repository to a public host (e.g., GitHub)

3. Send a link to the victim, asking them to review your code in VS Code

4. When the victim opens the repository with the ES7 React Snippets extension installed, the malicious code in the Prettier plugin will execute automatically

5. The calculator application will launch on the victim's computer, demonstrating arbitrary code execution

## Malicious Snippet Injection Leading to Remote Code Execution

### Vulnerability name
Malicious Snippet Injection Leading to Remote Code Execution

### Description
An attacker who controls the repository's snippet definitions can modify (or inject) a malicious snippet body. For example, the attacker may replace a safe snippet body with one that contains a snippet variable referencing a VS Code command (e.g. `${command:malicious.trigger}` or other command‐invoking placeholder). When the victim (who has installed this manipulated repository) triggers the snippet search command from the extension, the following happens step by step:
1. The extension's generator (in `generateSnippets.ts`) collates all snippet definitions from the repository's source snippets into a JSON file (`generated.json`).
2. The malicious snippet definition—crafted by the attacker—is written into this generated file.
3. When a user runs the command registered as `'reactSnippets.search'`, the extension reads and parses the JSON file from disk using Node's `readFileSync` and `JSON.parse`.
4. The extension then calls its `parseSnippet` routine (which includes formatting via Prettier and placeholder replacement) on the snippet's body. This routine does not neutralize or validate snippet placeholders.
5. Finally, the extension passes the resulting string to VS Code's snippet API via `new SnippetString(body)` and inserts it into the active editor.
6. If the snippet body contains a malicious placeholder (for example, one that causes VS Code to evaluate a command variable), then during snippet expansion the VS Code snippet engine may invoke the unwanted command.

### Impact
If the injected command placeholder is processed by VS Code, the attacker may achieve remote code execution in the context of the editor. This could lead to arbitrary command execution on the victim's system, data exfiltration, or further compromise of the host environment.

### Vulnerability rank
Critical

### Currently implemented mitigations
• The extension simply reads snippet definitions from a generated JSON file and passes them through simple string formatting (via Prettier and placeholder replacement).  
• No runtime filtering or sanitization is performed on the snippet bodies before insertion into the text editor.

### Missing mitigations
• There is no validation or sanitization of snippet content to detect or neutralize dangerous placeholder patterns (such as `${command:…}` or similar constructs).  
• There is no white-listing or escaping of snippet variables that might trigger execution of VS Code commands.  
• The extension trusts the content of the repository's snippet definitions without checking for injected payloads.

### Preconditions
• The attacker must be able to supply a manipulated repository (for example, through a compromised supply chain or by persuading a victim to install the extension from an attacker‑controlled branch).  
• The victim must activate the extension and trigger the snippet search command so that the malicious snippet is read, parsed, and ultimately inserted into an open editor.  
• VS Code must process the malicious snippet body in a way that resolves and executes dangerous snippet variables.

### Source code analysis
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

### Security test case
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