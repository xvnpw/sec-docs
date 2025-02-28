# Vulnerabilities in npm-intellisense

## 1. Remote Code Execution via Import Command with Malicious Package Names

### Vulnerability Name
Remote Code Execution via Import Command with Malicious Package Names

### Description
The npm-intellisense extension allows users to import npm packages using a command. When a user executes the import command, the extension generates JavaScript/TypeScript import statements based on package names from package.json. However, the extension does not properly sanitize the package names before inserting them into import statements. An attacker could create a malicious repository with a package.json containing crafted package names that include JavaScript code. When a victim runs the import command on a package with a malicious name, the code will be inserted directly into the victim's file.

Step by step:
1. Attacker creates a repository with a package.json containing a maliciously crafted package name, for example: `"malicious-package\\'; alert(document.domain); //"`.
2. Victim clones the repository and opens it in VSCode with npm-intellisense extension installed.
3. Victim uses the import command provided by npm-intellisense.
4. The extension presents the malicious package name in the quick pick menu.
5. When victim selects this package, the extension generates an import statement containing the malicious code.
6. This code is inserted into the victim's active file, which could lead to code execution.

### Impact
This vulnerability can lead to remote code execution in the victim's VSCode environment. The malicious code would execute within the context of VSCode, potentially allowing the attacker to access sensitive information, modify files, or execute additional arbitrary code.

### Vulnerability Rank
High

### Currently Implemented Mitigations
There are no sanitization measures in place for package names when generating import statements.

### Missing Mitigations
- The extension should sanitize package names before including them in generated import statements
- Input validation should be implemented to ensure package names do not contain malicious code
- The extension should use a safer method to generate import statements, such as using VSCode's API for inserting text that prevents code injection

### Preconditions
- Victim must have npm-intellisense extension installed
- Victim must open a repository containing the malicious package.json
- Victim must use the import command and select the malicious package name

### Source Code Analysis
In the file `command-import.ts`, the `addImportStatementToCurrentFile` function directly inserts the package name into code without any sanitization:

```typescript
function addImportStatementToCurrentFile(item: QuickPickItem, config: Config) {
    const statementES6 = `import {} from ${config.importQuotes}${item.label}${config.importQuotes}${config.importLinebreak}`;
    const statementRequire = `${config.importDeclarationType} ${guessVariableName(item.label)} = require(${config.importQuotes}${item.label}${config.importQuotes})${config.importLinebreak}`;
    const statement = config.importES6 ? statementES6 : statementRequire;
    const insertLocation = window.activeTextEditor.selection.start;
    window.activeTextEditor.edit(edit => edit.insert(insertLocation, statement));
}
```

The package name (`item.label`) is directly inserted into a template string without any validation or sanitization. If the package name contains code like `malicious-package\\'; alert(document.domain); //`, the resulting import statement would be:

```javascript
import {} from 'malicious-package\'; alert(document.domain); //'
```

When this code is evaluated by JavaScript, it will execute the injected `alert(document.domain)` code.

### Security Test Case
1. Create a package.json with the following content:
```json
{
  "dependencies": {
    "legitimate-package": "1.0.0",
    "malicious-package\\'; alert(document.domain); //": "1.0.0"
  }
}
```
2. Open this project in VSCode with npm-intellisense extension installed
3. Press Ctrl+Shift+P to open the command palette
4. Type "npm intellisense: import" and select the command
5. In the quick pick menu, select "malicious-package\\'; alert(document.domain); //"
6. Observe that an alert box appears showing the domain, proving code execution

## 2. Remote Code Execution via Malicious Package Name in Package JSON

### Vulnerability Name
Remote Code Execution via Malicious Package Name in Package JSON

### Description
The npm-intellisense extension processes package.json files to extract package names for autocompletion. When processing these package names, it does not properly validate or sanitize them before using them to generate code suggestions. An attacker who controls the package.json file can include maliciously crafted package names that, when used in autocompletion, will inject malicious code into the victim's JavaScript/TypeScript files.

Step by step:
1. Attacker creates a repository with a package.json file containing malicious package names.
2. Victim clones the repository and opens it in VSCode with npm-intellisense installed.
3. When the victim begins typing an import statement, the extension provides autocompletion suggestions based on the package.json.
4. If the victim selects a malicious package name, the extension inserts it into the import statement without sanitization.
5. When the victim's code is executed, the malicious code runs.

### Impact
This vulnerability can lead to remote code execution within the victim's environment. The injected code would execute with the same privileges as the application running the JavaScript code, potentially allowing the attacker to access sensitive information, modify files, or execute arbitrary commands.

### Vulnerability Rank
High

### Currently Implemented Mitigations
No mitigations are currently implemented for sanitizing package names used in autocomplete suggestions.

### Missing Mitigations
- Sanitization of package names before using them in code suggestions
- Validation to ensure package names adhere to npm naming conventions
- Escaping of special characters in package names when inserting them into code

### Preconditions
- Victim must have npm-intellisense extension installed
- Victim must open a repository with a malicious package.json file
- Victim must use the autocomplete feature when writing an import statement

### Source Code Analysis
In the `PackageCompletionItem.ts` file, the class extends CompletionItem to provide autocomplete functionality:

```typescript
export class PackageCompletionItem extends CompletionItem {  
  constructor(label: string, state: State) {
    super(label);
    this.kind = CompletionItemKind.Module;
    this.textEdit = TextEdit.replace(this.importStringRange(state), label);
  }

  importStringRange({ textCurrentLine, cursorLine, cursorPosition }) : Range {
    const textToPosition = textCurrentLine.substring(0, cursorPosition);
    const quotationPosition = Math.max(textToPosition.lastIndexOf('\"'), textToPosition.lastIndexOf('\''));
    return new Range(cursorLine, quotationPosition + 1, cursorLine, cursorPosition)
  }
}
```

The problem is that the `label` (which is the package name) is directly used without any sanitization. Package names are obtained from package.json via the `getNpmPackages` function in `provide.ts`:

```typescript
export function getNpmPackages(state: State, config: Config, fsf: FsFunctions) {
    return fsf.readJson(getPackageJson(state, config, fsf))
        .then(packageJson => [
            ...Object.keys(packageJson.dependencies || {}),
            ...Object.keys(config.scanDevDependencies ? packageJson.devDependencies || {} : {}),
            ...(config.showBuildInLibs ? getBuildInModules() : [])
        ])
        .catch(() => []);
}
```

If the package.json contains a malicious package name like `"malicious-package\\"; eval(\"alert('XSS')\"); //"`, this string will be directly inserted into the user's code when selected from autocomplete.

### Security Test Case
1. Create a package.json file with the following content:
```json
{
  "dependencies": {
    "legitimate-package": "1.0.0",
    "malicious-package\\\"; eval(\\\"alert('XSS')\\\"); //": "1.0.0"
  }
}
```
2. Open this project in VSCode with npm-intellisense extension installed
3. Create a new JavaScript file and start typing an import statement: `import { } from '`
4. Wait for autocomplete suggestions to appear
5. Select the malicious package name from the suggestions
6. Observe that the following code is inserted:
```javascript
import { } from 'malicious-package\"; eval(\"alert('XSS')\"); //'
```
7. When this code is executed, it will run the injected alert command, demonstrating successful code execution

## 3. Unsanitized External Data Leading to Code Injection in Auto-Import Statements

### Vulnerability Name
Unsanitized External Data Leading to Code Injection in Auto-Import Statements

### Description
A malicious actor can craft a repository (or package) whose contents include manipulated dependency names and/or file names. These names (for example, in a modified package.json or in a file inside node_modules with a crafted name) are read without proper sanitization by the extension. The extension's logic then uses these unsanitized values to build import statements (both via the auto-completion provider and the import command). If a developer accepts one of these auto-import suggestions, the resulting statement may include injected payload (for example, extra code appended to the module name, dangerous closing quotes, or additional JS code) that later—when the file is run—could trigger unintended execution.

**Step by step how it can be triggered:**
1. The attacker publishes a repository that contains a modified package.json with a dependency key such as:
   ```
   "evil-module'; process.exit(1);//": "1.0.0"
   ```
   Alternatively (or in addition), a file inside node_modules is deliberately renamed with extra characters (e.g. including quotes or JavaScript punctuation).
2. When the victim opens this repository in VSCode, the extension scans the workspace by reading package.json and recursively listing files (via functions like `readFilesFromDir` in util.ts and `fsf.readJson` in fs-functions.ts).
3. The unsanitized dependency names and file names flow through routines such as `getNpmPackages` (in provide.ts) and `getImportStatementFromFilepath` (in util.ts). These functions simply use string replace and splitting methods to generate variable names and import paths without escaping or rejecting suspicious characters.
4. When the developer later triggers the "import" command (via the command palette or auto-completion provider registered in extension.ts) the extension displays a QuickPick list whose items are derived directly from these dependency names.
5. Upon accepting a malicious auto-import suggestion, an import statement like
   ```
   import {} from 'evil-module'; process.exit(1);//'
   ```
   or its CommonJS equivalent is inserted into the code.
6. If the developer does not notice the injected payload and later runs or builds the project, the injected code (in this case, a call to process.exit or any other arbitrary code) will be executed in the context of the developer's project.

### Impact
- The injected payload embedded in the auto-import statement can alter runtime behavior or even execute arbitrary code once the file is run.
- This code injection may lead to a full compromise of the developer's runtime environment, loss of control over the executed project, or execution of commands that could further compromise the system.
- Since the extension automatically builds static import text based on unsanitized external data, the attack can be both covert and hard to trace back to the repository content.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- There is no sanitization or validation of dependency names or file names in the functions that read package.json (via fsf.readJson in fs-functions.ts) or traverse directories (via readFilesFromDir in util.ts).
- The import statement construction in both `getImportStatementFromFilepath` and in the command handler (`onImportCommand` in command-import.ts) directly interpolates configuration values and the unsanitized dependency name.

### Missing Mitigations
- Input validation and sanitization of any externally provided strings (including dependency names and file names) before they are used to build import statements.
- Use of a strict whitelist (e.g., allowing only alphanumeric characters, underscores, and hyphens) for module names.
- Escaping or filtering out dangerous characters (such as quotes, semicolons, or other JavaScript punctuation) from any data sourced from package.json or file names.
- Defensive coding in auto-import routines to ensure that suggestions cannot include executable payloads.

### Preconditions
- A malicious actor must supply a manipulated repository (or package) containing a crafted package.json or file names that include payload strings.
- The victim must open this manipulated repository in VSCode so that the extension reads the attacker-controlled content from the workspace's node_modules and package.json.
- The developer must later use the auto-import command or select one of the auto-completion suggestions generated by the extension.

### Source Code Analysis
1. **Dependency and File Reading:**
   - In **fs-functions.ts** the `readJson` function simply parses the contents of a package.json file without any validation.
   - In **provide.ts**, the function `getNpmPackages` calls `fsf.readJson` on the package.json (located via `getPackageJson` and `nearestPackageJson`) and then uses `Object.keys` on the "dependencies" or "devDependencies" fields.
2. **Auto-Completion Items Construction:**
   - In **PackageCompletionItem.ts**, the dependency name (as `item.label`) is used to build a text edit that replaces the current import statement fragment with the dependency name.
3. **Import Statement Generation:**
   - In **util.ts**, the function `getImportStatementFromFilepath` takes a file path (which may come from a malicious file name) and performs minimal regex replacements (e.g. removing ".js" or "index") to generate a variable name and import string.
4. **Command Execution Flow:**
   - In **command-import.ts**, the function `onImportCommand` fetches packages via `getNpmPackages` (and later mapping these to QuickPickItems) and finally builds an import statement by directly concatenating configuration settings and the unsanitized module name.
5. **Data Flow Summary:**
   - Unsanitized external data → package.json dependency keys and file paths → processed by string manipulation functions without rigorous validation → constructed into auto-import statements → inserted into the developer's active file without any cleanup.

### Security Test Case
1. **Setup:**
   - Create a test workspace containing a manipulated package.json file with a dependency declared as follows:
     ```json
     {
       "dependencies": {
         "evil-module'; console.log('Injected!');//": "1.0.0"
       }
     }
     ```
   - Optionally, create a file in a simulated node_modules directory whose name includes suspicious characters.
2. **Action:**
   - Open the test workspace in VSCode and ensure the extension is activated.
   - Invoke the auto-import command (or trigger auto-completion in a JavaScript/TypeScript file).
3. **Verification:**
   - Verify that the QuickPick list shows an entry corresponding to the "evil-module…".
   - Select the attacked QuickPickItem so that the extension inserts an import statement into the active editor window.
4. **Observation:**
   - Examine the inserted import statement. It should appear similar to:
     ```
     import {} from 'evil-module'; console.log('Injected!');//'
     ```
   - Confirm that the malicious payload (e.g. `console.log('Injected!');`) is included verbatim in the inserted statement.
5. **Conclusion:**
   - The test proves that unsanitized external data from a repository can flow into code that would be inserted into a developer's source file, thereby enabling code injection if that file is later executed.