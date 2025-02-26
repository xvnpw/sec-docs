- **Vulnerability Name:** Arbitrary File Disclosure via Malicious Bookmarks File

- **Description:**  
  When the extension is configured to save bookmarks in the project (using the setting `bookmarks.saveBookmarksInProject`), bookmark data is persisted–for example, in a JSON file (typically under a hidden folder such as `.vscode/`). An attacker who can inject or modify this bookmarks file (for example, by committing malicious content to a public repository or by other means of compromising the saved state) can add one or more entries with file URIs that point to sensitive files outside the intended workspace (for example, on Linux: `file:///etc/passwd` or on Windows: a system file).  
  **Step by step how it might be triggered:**  
  1. The attacker gains write access (through a malicious commit or other supply-chain means) to the project repository or the bookmarks file stored locally (when saving bookmarks in project is enabled).  
  2. The attacker injects one or more malicious bookmark entries with file URIs targeting sensitive files (for example, a URI that points to a file outside the workspace).  
  3. A user later opens the workspace in VS Code. The extension loads its bookmarks via the function (e.g., inside `loadWorkspaceState()`) without validating that the file URIs are restricted to the workspace.  
  4. The user then uses a navigation command (such as “Bookmarks: List from All Files” or “Bookmarks: Jump To”) which displays the stored bookmark entries.  
  5. Unaware of the malicious entry, the user selects it. The command registered as `bookmarks.jumpTo` then calls `vscode.workspace.openTextDocument(uri)` with the unsanitized URI from the bookmarks file, causing VS Code to open—and thus display—the contents of a sensitive file.

- **Impact:**  
  An attacker can force the application to open and reveal the contents of arbitrary files on the user’s system. Depending on the target file, this may lead to the disclosure of sensitive configuration details, passwords, or other system information normally not exposed within the editor. Such disclosure could further aid in pivoting to other attacks on the system.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**  
  - The extension assumes that the bookmark state (loaded via functions like `loadBookmarks()`) comes from a trusted source; there is no additional validation performed on the file URIs before they are used.
  - Commands such as `bookmarks.jumpTo` directly use the stored URI (passed in as a parameter) when calling VS Code’s API (e.g. `vscode.workspace.openTextDocument(uri)`).

- **Missing Mitigations:**  
  - No validation or sanitization is performed on the persisted bookmark data. In particular, there is no check to ensure that a bookmark’s URI points only to files within the active workspace.
  - A whitelist or restriction on allowed file paths (or scheme and host checks) is missing.
  - No warning is shown to the user when a bookmark entry appears to reference a file outside of the workspace.

- **Preconditions:**  
  - The user has enabled saving bookmarks in the project (i.e. `bookmarks.saveBookmarksInProject` is set to true), so that bookmark state is persisted in files that are part of the workspace.
  - An attacker has a means to inject or modify the bookmarks file (for example, via a malicious pull request, commit, or other supply‐chain compromise).
  - The user subsequently opens the workspace containing the malicious bookmark entries and uses a navigation command that relies on the data from that file.

- **Source Code Analysis:**  
  - In the extension’s activation routine (in file `extension.ts`), the function `loadWorkspaceState()` is used to load bookmark state. When saving bookmarks in the project is enabled, the function loads bookmarks from the workspace folder without inspecting the contents (e.g. no filtering is applied to the file URIs stored within the file).
  - Later, when the user invokes the command registered as `"_bookmarks.jumpTo"`, the callback immediately calls  
    ```ts
    vscode.workspace.openTextDocument(uri).then(doc => { … });
    ```  
    where the `uri` parameter originates directly from the stored bookmark data.
  - Similar patterns appear in the “list from all files” command where bookmark items are built and later used to trigger file opens.
  - The absence of any explicit check to verify that the file URIs remain within the expected workspace boundaries means that a maliciously injected URI is processed as if it were valid.

- **Security Test Case:**  
  1. Ensure that the user’s settings have enabled saving bookmarks to the project by setting `"bookmarks.saveBookmarksInProject": true` (or using the default if it is enabled).
  2. Manually edit the bookmarks file (for example, `.vscode/bookmarks.json`) in the workspace and add a bookmark entry with a malicious file URI (e.g., `{"line": 1, "column": 1, "label": "Malicious", "uri": "file:///etc/passwd"}` on Linux or an equivalent sensitive file on Windows).
  3. Reload the workspace in VS Code so that the extension loads the persisted bookmark state.
  4. Invoke the “Bookmarks: List from All Files” command (from the Command Palette).
  5. Verify that the QuickPick list displays the malicious bookmark entry.
  6. Select the malicious bookmark.
  7. Observe that VS Code opens the file specified by the malicious URI, thereby revealing the contents of a sensitive file.
  8. Confirm that the attack succeeds in disclosing file contents not normally visible in the editor.