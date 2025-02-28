# Vulnerabilities

## • Vulnerability: Malicious TOML Snippet Injection Leading to Remote Code Execution

  - **Description**  
    A threat actor supplying a manipulated repository can alter the contents of the TOML snippet files (e.g. those under `completions/snippets/` subdirectories). These files are read and parsed by the extension's `readSnippets()` method (in `src/utils.ts`) using `toml.parse` without any sanitization. An attacker can craft a malicious payload within the snippet definitions (for example, within the `body` attribute) that, when processed or later expanded as a VSCode snippet by creating a `SnippetString`, exploits a vulnerability in the TOML parser or the snippet expansion logic. In a step‐by‐step scenario:  
    1. The attacker creates or modifies a snippet file (for example, `completions/snippets/python/imports.toml`) in the distributed repository so that one snippet's body contains a payload designed to trigger prototype pollution or code injection.  
    2. The extension loads this file using the hardcoded file name in its completion provider (e.g. in `DjangoPythonCompletionItemProvider`), calling `readSnippets()`.  
    3. The file is read by VSCode's file system API and decoded without any integrity check or sanitization.  
    4. The unvalidated content is parsed with `toml.parse` and the resulting snippet objects (including the malicious payload in the `body` field) are passed directly to `new SnippetString(...)` in the completion item.  
    5. When a user accepts that snippet (or perhaps even when the snippet engine processes its placeholders), the malicious payload can cause the extension to execute unintended JavaScript code in its host context, leading to remote code execution (RCE).

  - **Impact**  
    • Upon successful exploitation, the attacker can execute arbitrary commands or code on the victim's machine via the VSCode extension host.  
    • This may lead to full compromise of the user's environment, data leakage, or further lateral movement within the system.

  - **Vulnerability Rank**  
    • Critical

  - **Currently Implemented Mitigations**  
    • The selection of snippet files is hardcoded (via the `files` arrays in each completion provider), which limits file name manipulation.  
    • However, the file content is read and parsed without further validation or sanitization; no integrity checks or secure parsing options are employed.

  - **Missing Mitigations**  
    • Input validation and sanitization of snippet file contents after reading from disk.  
    • Use of a hardened or security‑reviewed TOML parser that guards against prototype pollution or unexpected payload evaluation.  
    • Integrity verification (e.g. digital signatures or checksums) of snippet files before loading them into the extension.

  - **Preconditions**  
    • The attacker must be able to supply or convince the victim to install a manipulated repository version of the extension (for example, via a compromised update channel or distribution of a forked repository presented as "trusted").  
    • The victim then loads the extension with malicious TOML snippet files, which are parsed and later used to build VSCode snippet completions.

  - **Source Code Analysis**  
    • **Step 1:** In `src/utils.ts`, the method `readSnippets(name: string)` constructs a file URI using:
      - `const location = vscode.Uri.joinPath(this.extensionUri, 'completions/snippets', name)`
    • **Step 2:** The file is read and decoded:
      - ```js
        const buffer = await vscode.workspace.fs.readFile(location);
        const str = new TextDecoder("utf-8").decode(buffer);
        ```
    • **Step 3:** The decoded content is directly parsed:
      - ```js
        return toml.parse(str).snippets;
        ```
      There is no further validation of the parsed content.
    • **Step 4:** In `src/completions/base.ts`, each snippet's `body` is passed directly into a new `SnippetString`:
      - ```js
        item.insertText = new SnippetString(snippet.body);
        ```
      Without sanitization, any malicious payload inserted in the snippet file now becomes part of the code generation logic and might lead to unintended behavior if the underlying libraries or snippet processor mishandles the payload.

  - **Security Test Case**  
    1. **Preparation:**  
       - Create a manipulated snippet TOML file (for example, override `completions/snippets/python/imports.toml` or another file used by a completion provider).  
       - In the file, insert a snippet with a payload designed to trigger code execution. For instance:
         ```toml
         [[snippets]]
         prefix = "malicious"
         detail = "malicious snippet"
         body = """${{function(){require('child_process').exec('calc.exe')}}}"""
         description = "Malicious payload"
         ```
    2. **Execution:**  
       - Package or clone the extension repository with the manipulated snippet file.  
       - Start VSCode and launch the extension (for example, via the debugger or by loading the extension normally).  
       - Open a Python file (or file of an appropriate language that triggers the relevant completion provider) and type the snippet prefix (e.g. `malicious`).
    3. **Observation:**  
       - Observe whether VSCode's snippet expansion mechanism processes the payload and whether any side effects occur (for example, an external program opens, environment variables are modified, or unusual behavior is logged in the extension host).  
       - Verification can also include injecting benign but instrumented payloads that log evidence of code execution.
    4. **Conclusion:**  
       - If the injected snippet payload causes execution of the injected code in the extension's context, then remote code execution has been successfully achieved, confirming the vulnerability.