# Vulnerabilities in Bookmarks Extension

## Unsafe Deserialization of Bookmark Files Leading to Remote Code Execution

### Description
The Bookmarks extension supports saving bookmarks in project files (via the `saveBookmarksInProject` setting). When a user opens a malicious repository with a crafted bookmark file, the extension will load and process this file without proper validation. This vulnerability allows an attacker to execute arbitrary code within the VSCode context by exploiting the bookmark loading mechanism.

The vulnerability is triggered when the extension loads bookmarks from a project file in the `loadWorkspaceState` function of `extension.ts`. The extension reads bookmark files from the project directory without proper validation or sanitization of the content, creating an attack vector for code execution.

Specifically, the function deserializes this data without any apparent validation or strict schema enforcement. This allows an attacker to supply a bookmarks file that injects unexpected properties (such as a `__proto__` key or other prototype override keys) that pollute the core objects used by the extension. Later, when the extension uses these bookmark objects (for example, when building the QuickPick list or applying decorations), the polluted prototypes may trigger unintended behaviors or execute attacker-supplied code.

### Impact
Through prototype pollution and unsanitized deserialization, an attacker may force the extension to execute arbitrary JavaScript code. This effectively leads to remote code execution (RCE) within the VSCode extension host and allows them to:
- Access any files the VSCode process has access to
- Steal sensitive information from open projects
- Install additional malicious extensions or modify VSCode settings
- Potentially gain access to the user's local system

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- The current implementation makes use of standard JSON parsing routines (e.g., via JSON.parse when loading bookmark data) rather than evaluating files as code.
- However, there is no explicit check that the structure of the bookmark data conforms to a strict schema, and the extension loads bookmark files without proper validation or sanitization.

### Missing Mitigations
- Validate and sanitize bookmark data loaded from project files
- Implement a content security policy for loaded bookmark files
- Add integrity checks for bookmark files to detect tampering
- A whitelist-based schema check or safe deserialization (for example, using libraries that guard against prototype pollution)

### Preconditions
- The user must open a malicious repository in VSCode
- The `saveBookmarksInProject` setting must be enabled (it's not enabled by default, but attackers can try to social engineer users to enable it)
- The attacker must have prepared this repository with a malicious payload designed to inject extra properties (e.g., a crafted `__proto__` object)

### Source Code Analysis
In `extension.ts`, the `loadWorkspaceState` function contains:

```typescript
// `saveBookmarksInProject` TRUE
// single or multi-root, will load from each `workspaceFolder`
controllers = await Promise.all(
    vscode.workspace.workspaceFolders!.map(async workspaceFolder => {
        const ctrl = await loadBookmarks(workspaceFolder);
        return ctrl;
    })
);
```

When `saveBookmarksInProject` is true, the extension loads bookmark data from each workspace folder. This loading process in the `loadBookmarks` function doesn't properly validate the bookmark data, allowing an attacker to craft a malicious bookmark file that can execute arbitrary code when loaded.

The returned data is stored in controller objects (e.g., inside the "files" array) without any subsequent sanitization. Later code—in commands such as the QuickPick listing and decoration update routines—assumes that the bookmark objects hold only the expected members (like "line", "column", and "label"). Because any injected prototype pollution is not checked, an attacker-supplied extra property could later modify method behavior during operations such as sorting or iteration.

The issue continues in the `saveWorkspaceState` function where bookmarks are saved without any validation:

```typescript
// `saveBookmarksInProject` TRUE
// single or multi-root, will save to each `workspaceFolder` 
controllers.forEach(controller => {
    saveBookmarks(controller);
});
```

### Security Test Case
1. Create a malicious repository that includes a bookmark file (for example, ".vscode/bookmarks.json") containing a payload such as:
   ```json
   {
     "__proto__": { "malicious": "trigger_rce" },
     "bookmarks": [
       { "line": 10, "column": 5, "label": "Test" }
     ]
   }
   ```
2. Ensure that the workspace settings enable saving bookmarks in the project (i.e., `"bookmarks.saveBookmarksInProject": true`).
3. Open the repository in VSCode so that the extension loads this bookmarks file.
4. Trigger any operation that iterates over or uses the bookmark objects (such as displaying the bookmarks list or updating decorations).
5. Monitor whether the malicious payload is detected or—through the polluted prototype—a custom getter or overridden method gets invoked. Successful execution of attacker-controlled logic demonstrates exploitation.

## Code Injection via Malicious Bookmark Labels

### Description
The Bookmarks extension allows users to define labels for bookmarks. These labels are not properly sanitized before being processed, which creates a vector for code injection. A malicious repository can contain bookmarks with specially crafted labels that inject and execute code.

The extension builds lists of bookmarks to allow navigation (using commands such as "Bookmarks: List" and "Bookmarks: List from All Files"). In these routines (for example, in the function `list()` in `/code/src/extension.ts`), each bookmark's label is directly inserted into QuickPick item properties and later passed to a helper (such as `parsePosition()`) to extract line and column numbers. If an attacker supplies a malicious bookmark label through manipulated repository data, and if the helper function processes the label using unsafe operations, it may result in code injection.

### Impact
An attacker can execute arbitrary JavaScript code within the VSCode extension context by tricking the user into interacting with maliciously labeled bookmarks. An attacker-controlled bookmark label could result in arbitrary JavaScript code execution if the label is later interpreted in an unsafe context, posing a serious security risk for the affected VSCode instance.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- The code currently uses basic string operations (such as `trim()` and string concatenation) when building QuickPick items.
- There is no explicit sanitization logic applied to bookmark labels, and the extension doesn't sanitize bookmark labels before processing them.

### Missing Mitigations
- Sanitize bookmark labels to remove potentially dangerous content
- Implement proper escaping when displaying labels in the UI
- Add validation to ensure labels don't contain executable code
- There is no whitelist or escaping mechanism to ensure that bookmark labels contain only safe characters

### Preconditions
- The user must open a malicious repository with bookmarks containing specially crafted labels
- The user must interact with the labeled bookmarks (view them in the sidebar or list)
- The victim must load this repository and invoke one of the bookmark navigation commands so that the malicious label is used in building the QuickPick interface

### Source Code Analysis
In `extension.ts`, the `toggleLabeled` function accepts label input without proper sanitization:

```typescript
let suggestion = suggestLabel(vscode.window.activeTextEditor.selection);
if (!params && suggestion !== "" && useSelectionWhenAvailable()) {
    if (await activeController.toggle(selections, suggestion)) {
        vscode.window.showTextDocument(vscode.window.activeTextEditor.document, {preview: false, viewColumn: vscode.window.activeTextEditor.viewColumn} );
    }
    // ...
}
```

The function takes labels from user selection and uses them directly without validation. When loading from a malicious repository, this could be exploited to inject code.

Also, in the `askForBookmarkLabel` function:

```typescript
activeController.addBookmark(position, bookmarkLabel, book);
```

The bookmark label is added directly without validation or sanitization.

In `list()` function, the code loops over `activeController.activeFile.bookmarks` and constructs QuickPick items:

```typescript
items.push({ 
  description: "(Ln " + bookmarkLine.toString() + ", Col " + bookmarkColumn.toString() + ")", 
  label: codicons.tag + " " + activeController.activeFile.bookmarks[index].label 
});
```

Later, in the "onDidSelectItem" callback the description is passed to `parsePosition(itemT.description)` to determine the destination. If `parsePosition()` does not safely validate this input (or uses dynamic evaluation), the malicious label could lead to code injection.

### Security Test Case
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