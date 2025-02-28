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