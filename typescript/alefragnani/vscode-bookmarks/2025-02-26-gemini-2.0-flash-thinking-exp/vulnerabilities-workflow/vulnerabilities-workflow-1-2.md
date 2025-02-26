- **Vulnerability Name:** Path Traversal in Bookmark File Handling

  - **Description:**  
    An attacker with write access to the project’s bookmark file (for example, when bookmarks are saved in the workspace via the setting “bookmarks.saveBookmarksInProject”) can inject bookmark entries that use crafted relative paths to “escape” the intended workspace directory. For example, rather than a path beginning with “..” (which the code rejects), an attacker can use a value such as:  
    `subfolder/../../sensitive.txt`  
    Because the filtering in the code only checks if a file’s path string starts with “..”, this “traversal” path bypasses the check. Later when a user issues a navigation command (for instance via “jumpTo” or “list from all files”), the extension constructs a file URI from the unsanitized relative path (using helper functions like `appendPath`) and opens the file. This can lead to the display (and possible disclosure) of files outside the workspace.

  - **Impact:**  
    An attacker can cause the extension to open and display arbitrary files that lie outside the intended workspace. Sensitive files (such as configuration files, secrets, or internal documentation located in parent directories) may be disclosed to a user who unwittingly navigates to the malicious bookmark entry.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**  
    In the function `splitOrMergeFilesInMultiRootControllers()` (located in `extension.ts`), there is a simple filter that removes files whose path begins with "`..`":  
    ```js
    const validFiles = activeController.files.filter(file => !file.path.startsWith(".."));
    activeController.files = [...validFiles];
    ```  
    However, this check is string based only and does not perform proper path normalization.

  - **Missing Mitigations:**  
    - **Normalization and Validation:** The extension should normalize any persisted relative file paths (for example, using Node’s `path.normalize`) and then verify that the resulting absolute path is strictly within the workspace directory.  
    - **Robust Sanitization:** Instead of only checking if a string starts with "`..`", the code should resolve the relative path and then enforce an “allowed directory” check.

  - **Preconditions:**  
    - The user’s project is configured to save bookmarks inside the project (i.e. “bookmarks.saveBookmarksInProject” is set to `true`).  
    - An attacker is able to modify (or introduce via a malicious pull request or repository compromise) the bookmark data file (typically stored in `.vscode/bookmarks.json` or similar).

  - **Source Code Analysis:**  
    - In `extension.ts`, the function `splitOrMergeFilesInMultiRootControllers()` performs a filtering step:  
      ```js
      const validFiles = activeController.files.filter(file => !file.path.startsWith(".."));
      activeController.files = [...validFiles];
      ```  
      This check only examines the very beginning of the file path string. An attacker can bypass it by supplying a relative path that does not start with "`..`" but still uses directory traversal (such as `subfolder/../../sensitive.txt`).  
    - Later on, when a command like `_bookmarks.jumpTo` is triggered, the extension uses functions such as `appendPath` to build a full URI from the workspace folder and the stored file path without revalidating that the resulting path lies within the allowed directory.  
    - Consequently, crafted bookmark data can lead the extension to open an arbitrary file.

  - **Security Test Case:**  
    1. **Prepare a Malicious Bookmark File:**  
       - In a test project with “bookmarks.saveBookmarksInProject” set to `true`, modify (or create) the bookmark file (for example, `.vscode/bookmarks.json`) to include an entry with a path such as:  
         ```
         "path": "subfolder/../../sensitive.txt"
         ```  
    2. **Open the Project:**  
       - Launch VSCode in the context of this project so that the Bookmarks extension loads the injected bookmark data.
    3. **Trigger Navigation:**  
       - Execute a navigation command (for example, “Bookmarks: Jump to Next” or “Bookmarks: List from All Files”) so that the extension processes the bookmark entry.
    4. **Observe the Outcome:**  
       - If the extension does not normalize and validate the resolved path properly, it will open the file located at the resolved absolute path—which may be outside of the project—thereby disclosing its contents.
    5. **Expected Result:**  
       - The test confirms that the extension is vulnerable if it allows a bookmark to open a file (e.g. “sensitive.txt”) that lies outside the workspace.