# Vulnerabilities in VSCode Bookmarks Extension

## Vulnerability 1: Unsafe Deserialization of Bookmark Data Leading to Prototype Pollution and Code Injection  

**Description:**  
When the setting "bookmarks.saveBookmarksInProject" is enabled, the extension loads bookmark data from files stored in the repository (for example, a JSON file in the workspace's ".vscode" folder). The function (invoked inside the activation routine via calls such as `await loadBookmarks(workspaceFolder)`) deserializes this data without any apparent validation or strict schema enforcement. An attacker who prepares a malicious repository can supply a bookmarks file that injects unexpected properties (for example, a `__proto__` key or other prototype override keys) that pollute the core objects used by the extension. Later when the extension iterates over or otherwise uses these bookmark objects (for example, when building the QuickPick list or when applying decorations), the polluted prototypes may trigger unintended behaviors or even execute attacker–supplied code in the context of the extension host.  

**Impact:**  
Through prototype pollution and unsanitized deserialization, an attacker may force the extension to execute arbitrary JavaScript code. This effectively leads to remote code execution (RCE) within the VSCode extension host process and ultimately could compromise the victim's system.  

**Vulnerability Rank:** Critical  

**Currently Implemented Mitigations:**  
- The current implementation makes use of standard JSON parsing routines (e.g. via JSON.parse when loading bookmark data) rather than evaluating files as code.  
- However, there is no explicit check that the structure of the bookmark data conforms to a strict schema.  

**Missing Mitigations:**  
- No input validation or sanitization is performed on the deserialized bookmark data.  
- A whitelist–based schema check or safe deserialization (for example, using libraries that guard against prototype pollution) is missing.  

**Preconditions:**  
- The user must open a repository that contains bookmark data (such as a ".vscode/bookmarks.json" file) and have the "bookmarks.saveBookmarksInProject" setting enabled.  
- The attacker must have prepared this repository with a malicious payload designed to inject extra properties (e.g. a crafted `__proto__` object).  

**Source Code Analysis:**  
- In `/code/src/extension.ts`, the function `loadWorkspaceState()` (invoked during activation) calls `await loadBookmarks(...)`. The returned data is stored in controller objects (e.g. inside the "files" array) without any subsequent sanitization.  
- Later code—in commands such as the QuickPick listing and decoration update routines—assumes that the bookmark objects hold only the expected members (like "line", "column", and "label"). Because any injected prototype pollution is not checked, an attacker–supplied extra property could later modify method behavior during operations such as sorting or iteration.  

**Security Test Case:**  
1. Create a malicious repository that includes a bookmark file (for example, ".vscode/bookmarks.json") containing a payload such as:  
   ```json
   {
     "__proto__": { "malicious": "trigger_rce" },
     "bookmarks": [
       { "line": 10, "column": 5, "label": "Test" }
     ]
   }
   ```  
2. Ensure that the workspace settings enable saving bookmarks in the project (i.e. `"bookmarks.saveBookmarksInProject": true`).  
3. Open the repository in VSCode so that the extension loads this bookmarks file.  
4. Trigger any operation that iterates over or uses the bookmark objects (such as displaying the bookmarks list or updating decorations).  
5. Monitor whether the malicious payload is detected or—through the polluted prototype—a custom getter or overridden method gets invoked (for example, by adding logging or attempting to trigger an external command). Successful execution of attacker–controlled logic demonstrates exploitation.

## Vulnerability 2: Code Injection via Malicious Bookmark Labels in QuickPick Navigation  

**Description:**  
The extension builds lists of bookmarks to allow navigation (using commands such as "Bookmarks: List" and "Bookmarks: List from All Files"). In these routines (for example, in the function `list()` in `/code/src/extension.ts`), each bookmark's label (potentially provided by the user or stored in the repository) is directly inserted into QuickPick item properties and later passed to a helper (such as `parsePosition()`) to extract line and column numbers. If an attacker supplies a malicious bookmark label through manipulated repository data, and if the helper function (or other downstream code) processes the label using unsafe operations (for example, via dynamic evaluation or by insufficiently sanitizing string content), it may result in code–injection.  

**Impact:**  
An attacker–controlled bookmark label could result in arbitrary JavaScript code execution within the extension host if the label is later interpreted in an unsafe context. This would lead to RCE and pose a serious security risk for the affected VSCode instance.  

**Vulnerability Rank:** High  

**Currently Implemented Mitigations:**  
- The code currently uses basic string operations (such as `trim()` and string concatenation) when building QuickPick items. There is no explicit sanitization logic applied to bookmark labels.  

**Missing Mitigations:**  
- There is no whitelist or escaping mechanism to ensure that bookmark labels contain only safe characters.  
- The helper function (e.g. `parsePosition()`), whose implementation is not shown, may be unsafe if it treats parts of the label as code (for instance, if it (mis)uses `eval()` to extract line/column data).  

**Preconditions:**  
- The malicious repository must include a bookmarks file with at least one bookmark object whose "label" field contains an injected payload (for example, including characters or expressions that could be interpreted as code).  
- The victim must load this repository and invoke one of the bookmark navigation commands so that the malicious label is used in building the QuickPick interface.  

**Source Code Analysis:**  
- In `/code/src/extension.ts`, the function `list()` loops over `activeController.activeFile.bookmarks` and constructs QuickPick items. The label is built as follows:  
  ```ts
  items.push({ 
    description: "(Ln " + bookmarkLine.toString() + ", Col " + bookmarkColumn.toString() + ")", 
    label: codicons.tag + " " + activeController.activeFile.bookmarks[index].label 
  });
  ```  
- Later, in the "onDidSelectItem" callback the description is passed to `parsePosition(itemT.description)` to determine the destination. If `parsePosition()` does not safely validate this input (or—worse—uses dynamic evaluation), the malicious label could lead to code injection.  

**Security Test Case:**  
1. Create a repository that includes a bookmarks file with a bookmark whose "label" is set to a malicious payload. For example:  
   ```json
   {
     "bookmarks": [
       { "line": 15, "column": 3, "label": "NormalLabel $(require('child_process').exec('calc'))" }
     ]
   }
   ```  
2. Load the repository (with `"bookmarks.saveBookmarksInProject": true` enabled) in VSCode.  
3. Run the "Bookmarks: List" command so that the QuickPick is shown with the malicious label.  
4. Select the bookmark from the list.  
5. Verify whether the malicious payload is executed (for example, by checking if an external application is launched or any unexpected behavior occurs).  
6. If the injected code is executed, this confirms that unsanitized bookmark labels can lead to code injection.