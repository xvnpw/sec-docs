## Vulnerability List for Indent-Rainbow Extension

### Vulnerability: Regular Expression Injection in `ignoreLinePatterns` leading to unexpected behavior

* Description:
    1. An attacker can modify the VSCode workspace settings to include a malicious regular expression in the `indentRainbow.ignoreLinePatterns` configuration array.
    2. The Indent-Rainbow extension reads this configuration and uses `new RegExp()` to create regular expression objects from each string in the `ignoreLinePatterns` array.
    3. When the extension processes a text document, it iterates through these regular expressions and uses them to identify lines that should be excluded from indentation error highlighting.
    4. A carefully crafted regular expression, injected by the attacker, can be designed to match unintended lines or even all lines in a document.
    5. This will cause the extension to incorrectly skip indentation error highlighting for those lines, potentially masking real indentation issues from the user.

* Impact:
    Users may be misled about indentation errors in their code because the extension can be manipulated to suppress error highlighting on arbitrary lines based on attacker-controlled regular expressions. This can lead to developers overlooking real indentation problems, potentially introducing bugs or inconsistencies in their code. The intended security benefit of the extension, which is to help users identify and correct indentation errors, is undermined.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    None. The extension directly uses the strings provided in the `indentRainbow.ignoreLinePatterns` configuration to create regular expressions without any sanitization, validation, or restrictions.

* Missing Mitigations:
    * Input validation: Implement validation for the `indentRainbow.ignoreLinePatterns` configuration setting. This could involve:
        * Restricting the complexity of allowed regular expressions to prevent ReDoS (though DoS is excluded, complex regex could still lead to unexpected freezes).
        * Using a safer alternative to regular expressions if the intended functionality allows it (e.g., simple string matching).
        * Sanitizing or escaping special characters in the input strings before creating RegExp objects.
    * Documentation update: Add a warning to the extension's documentation advising users about the potential risks of using complex or untrusted regular expressions in `ignoreLinePatterns`. Recommend caution when using shared workspace configurations that might contain such settings.

* Preconditions:
    * The attacker must be able to modify the VSCode workspace settings. This can be achieved if:
        * The user opens a workspace that is controlled by the attacker (e.g., a malicious repository).
        * The user has shared workspace settings that the attacker can modify.

* Source Code Analysis:
    1. **Configuration Loading:** In `/code/src/extension.ts`, lines 69-85, the extension retrieves the `ignoreLinePatterns` array from the workspace configuration:
    ```typescript
    const ignoreLinePatterns = vscode.workspace.getConfiguration('indentRainbow')['ignoreLinePatterns'] || [];
    ```
    2. **RegExp Object Creation:** The code then iterates through this array and attempts to convert each string into a `RegExp` object.
    ```typescript
    ignoreLinePatterns.forEach((ignorePattern,index) => {
        if (typeof ignorePattern === 'string') {
          //parse the string for a regex
          var regParts = ignorePattern.match(/^\/(.*?)\/([gim]*)$/);
          if (regParts) {
            // the parsed pattern had delimiters and modifiers. handle them.
            ignoreLinePatterns[index] = new RegExp(regParts[1], regParts[2]);
          } else {
            // we got pattern string without delimiters
            ignoreLinePatterns[index] = new RegExp(ignorePattern);
          }
        }
      });
    ```
    - `new RegExp()` is used directly with the string from the configuration. This is where the injection vulnerability occurs, as an attacker-controlled string is directly interpreted as a regular expression.
    3. **RegExp Execution:** Later in the `updateDecorations` function (lines 158-165), the extension iterates through the `ignoreLinePatterns` and executes each regex against the document text using `ignorePattern.exec(text)`:
    ```typescript
    ignoreLinePatterns.forEach(ignorePattern => {
        while (ignore = ignorePattern.exec(text)) {
          const pos = activeEditor.document.positionAt(ignore.index);
          const line = activeEditor.document.lineAt(pos);
          ignoreLines.push(line.lineNumber);
        }
      });
    ```
    - The results of these regex executions determine which lines will have indentation error highlighting skipped.

* Security Test Case:
    1. Install the Indent-Rainbow extension in VSCode.
    2. Create a new workspace or open an existing one.
    3. Create a new text file (e.g., `test.py`) and set the language mode to Python.
    4. Add the following Python code with intentional indentation errors:
    ```python
    def test_function():
     if True:
      print("Indented correctly")
       print("Incorrect indentation") # Intentional indentation error
    ```
    5. Observe that the Indent-Rainbow extension correctly highlights the line with incorrect indentation (`print("Incorrect indentation")`).
    6. Open VSCode settings (File > Preferences > Settings > Settings). Navigate to "Workspace" settings.
    7. Search for "indentRainbow.ignoreLinePatterns".
    8. Click "Add Item" to add a new item to the `indentRainbow.ignoreLinePatterns` array.
    9. Enter the malicious regular expression `/.*/g` as the value for the new item. This regex matches any line.
    10. Save the settings.
    11. Re-open the `test.py` file or switch back to it if it's already open.
    12. Observe that the indentation error on the line `print("Incorrect indentation")` is **no longer highlighted**. The malicious regular expression `/.*/g` has caused the extension to ignore all lines for error highlighting, thus successfully demonstrating the vulnerability.