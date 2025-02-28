# Vulnerability Assessment: VSCode autoDocstring Extension

## Malicious Custom Docstring Template Code Injection

**Vulnerability Name:** Malicious Custom Docstring Template Code Injection

**Description:**  
The autoDocstring extension allows users (or, by extension, an attacker supplying a malicious repository) to specify a custom docstring template via the configuration setting `"autoDocstring.customTemplatePath"`. When this setting is nonempty, the extension resolves the path (using the workspace root for relative paths) and unconditionally reads the file content via Node's `readFileSync()`. That file content is then passed to Mustache's `render()` function (via the `DocstringFactory.generateDocstring()` method) to generate a snippet string that is inserted into the active document using VSCode's `insertSnippet()` API.  
A threat actor who controls a repository (for example, by including a manipulated `.vscode/settings.json` along with a malicious custom template file) can supply a custom template whose content includes crafted Mustache directives and snippet placeholder syntax (for instance, using constructs such as `${exec:...}` or other placeholder variables). Because no sanitization or validation is performed on the custom template file, the malicious template may cause the rendered snippet to include dangerous placeholder expressions that, if interpreted by VSCode's snippet engine (or if VSCode has any undiscovered vulnerabilities in snippet expansion), could lead to arbitrary code execution.

Step by step, an attacker would:
1. Include in the repository a `.vscode/settings.json` that sets `"autoDocstring.customTemplatePath"` to a file under the repository (or an absolute path) controlled by the attacker.
2. Provide a malicious custom template (for example, a file named `malicious_template.mustache`) with content designed to inject snippet placeholders such as:
   ```
   {{#placeholder}}${exec:malicious_command}{{/placeholder}}
   ```
3. When the victim opens this repository in VSCode, the extension reads the attacker‑controlled template file and uses it to build the docstring snippet.
4. Upon generating a docstring (for example, when the user triggers the "Generate Docstring" command in a Python file), the unsanitized template is rendered and the resulting snippet—now containing malicious placeholder syntax—is inserted into the document.
5. Under the right conditions (or if VSCode's snippet expansion has a related flaw), the malicious snippet may trigger command execution or even arbitrary JavaScript execution, thereby compromising the victim's system.

**Impact:**  
If successfully exploited, this vulnerability may allow an attacker to have a malicious docstring snippet injected into the editor. In a worst‑case scenario (for example, if subsequent processing of snippet placeholders causes code execution), this can lead to remote code execution (RCE) in the victim's environment. An attacker could execute arbitrary commands, steal sensitive information, or otherwise compromise the editor/host system.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**  
• None. The custom template file is read directly without any sanitization or validation, and no checks are performed on the content of the template before it is passed to Mustache.

**Missing Mitigations:**  
• Validating or sanitizing the contents of files loaded via the setting `"autoDocstring.customTemplatePath"`.  
• Restricting custom template file paths (for example, to a safe subdirectory of the workspace).  
• Escaping or otherwise prohibiting potentially dangerous snippet placeholder syntax from being rendered in the final docstring snippet.

**Preconditions:**  
• The victim opens a repository that contains a manipulated workspace configuration (for example, a `.vscode/settings.json`) which sets `"autoDocstring.customTemplatePath"` to an attacker‑controlled file path.  
• The repository includes a custom template file with malicious content (for instance, using snippet placeholder syntax that triggers code or command execution).

**Source Code Analysis:**  
• In **src/generate_docstring.ts** (method `getTemplate()`):  
  – The extension reads the configuration setting `"customTemplatePath"`. If nonempty, it checks whether the path is absolute; if not, it prepends the workspace root.  
  – It then calls `getCustomTemplate()`, which (in **src/docstring/get_template.ts**) uses `readFileSync(templateFilePath, "utf8")` without sanitizing the file content.  
• In **src/docstring/docstring_factory.ts** (method `generateDocstring()`):  
  – The previously loaded template content is passed to Mustache's `render(this.template, templateData)`.  
  – The resulting string (which may now contain malicious snippet placeholder text) is then wrapped with the configured quote style and inserted into the editor using `insertSnippet(docstringSnippet, insertPosition)`.  
• Because there is no validation or escaping of custom template content—and because the template (controlled by external repository files) is rendered directly into a snippet—an attacker can inject malicious snippet directives that could be leveraged for code injection.

**Security Test Case (to Prove Validity):**  
1. **Setup a Malicious Repository:**  
  – Create a repository that includes a file named `.vscode/settings.json` with the following content:
    ```json
    {
      "autoDocstring.customTemplatePath": "malicious_template.mustache"
    }
    ```
  – In the repository root (or appropriate folder), add a file named `malicious_template.mustache` containing a payload such as:
    ```
    {{#placeholder}}${exec:malicious_command}{{/placeholder}}
    ```
2. **Open the Repository in VSCode:**  
  – Open the malicious repository in VSCode with the autoDocstring extension installed.
3. **Trigger the Vulnerable Functionality:**  
  – Open a Python file that contains a standard function definition.
  – Position the cursor appropriately (e.g. on a line immediately after a function header).
  – Trigger the "Generate Docstring" command (via the keyboard shortcut, context menu, or command palette).
4. **Observe the Rendered Docstring:**  
  – Verify that the generated docstring snippet inserted into the document contains the malicious placeholder (for example, it might appear as:  
    ```
    """${1:${exec:malicious_command}}"""
    ```
5. **Confirm Exploitation:**  
  – In a controlled test environment (or using logging to capture snippet expansion details), check if the malicious placeholder is processed in a way that triggers unintended behavior (such as an unexpected command execution or output in the terminal/output pane).  
  – Document the results to show that unsanitized template content affects the snippet insertion process.