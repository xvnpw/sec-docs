- **Vulnerability Name:** Path Traversal in Template Resolution

  - **Description:**
    An attacker can craft a Django template file (or modify an existing one) to include a file path containing directory traversal sequences (for example, using "../" segments). When a user who has opened that file and then invokes the “Go to Definition” feature (via F12 or Ctrl+Click on the path), the extension’s definition provider uses a regular expression to capture the relative file path without sanitization. The provider then resolves that path against the current file’s directory and builds a glob pattern used to search for matching files. Because there is no check to ensure that the resolved file path stays within approved template directories or within the workspace boundaries, a malicious user can force the extension to reveal the location—and thereby open—the contents of files outside the intended directories.
    **Step by step triggering:**
    1. An attacker places a Django template file in the workspace (or submits one via a repository update) containing an include or extends tag that references a relative file path with traversal segments (e.g., `{% include "../../secret_config.txt" %}`).
    2. The user opens this template in VS Code.
    3. When the user positions the cursor over the file path (the extension checks that the cursor is within the matched text) and triggers “Go to Definition,” the extension’s TemplatePathProvider is activated.
    4. The provider’s `getTemplate` function first matches the file path against a relative path regular expression. It then resolves the path using Node’s `resolve(dirname(document.uri.path), path)` without validating that the outcome lies within a trusted directory.
    5. The provider uses `workspace.findFiles` with a glob pattern based on the resolved path to return a matching file URI.
    6. If a file outside of the intended templates (for example, a sensitive configuration file) is found, its URI is returned to VS Code, which then opens the file.

  - **Impact:**
    An attacker can leverage this weakness to force the extension to reveal local files that were not meant to be exposed (such as configuration files, secrets, or other sensitive data). This represents an information disclosure risk and a breach of the intended file access boundaries.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The provider does check that the user cursor is positioned over the detected file path before proceeding.
    - However, no validation is performed on the resolved path to ensure that it lies within a designated safe directory (e.g. within known template directories).

  - **Missing Mitigations:**
    - There is no sanitization or bounds checking on relative file paths.
    - The extension does not enforce that the resolved file remains within a trusted workspace subtree (for example, within a dedicated “templates” folder).
    - A whitelist of allowed path prefixes or an explicit check of the resolved absolute path against the workspace root is missing.

  - **Preconditions:**
    - The attacker must be able to influence the content of a file within the workspace (for example, by contributing a malicious template file to a repository that the user then opens).
    - The user must execute the “Go to Definition” command on the maliciously crafted file path and have a workspace that contains files outside the intended templates directory.

  - **Source Code Analysis:**
    1. In `/code/src/providers/definitionProvider.ts`, the `TemplatePathProvider.getTemplate` function is designed to identify file paths in a line of a document using two regular expression patterns. One of these (`RELATIVE_PATH_RE`) captures relative file paths such as those starting with `./` or `../`.
    2. If a relative match is found, the code assigns `path = relative_match[1]` and then calculates a search pattern with the following call:
       ```
       search = workspace.asRelativePath(resolve(dirname(document.uri.path), path))
       ```
       This concatenates the current document’s directory with the captured path.
    3. Critically, no check is performed to confirm that `resolve(dirname(document.uri.path), path)` does not escape from allowed directories.
    4. The resulting `search` string is then passed directly to `workspace.findFiles(search, '', 1, token)`. If the user has a file (or creates one) that matches a directory‐traversed pattern (for example, “../../secret_config.txt”), the function may resolve and return a URI pointing to an unintended file.
    5. Finally, if the user’s cursor is indeed over the path, the provider returns a `Location` for the file (with position set to the beginning), allowing the file’s content to be viewed.

  - **Security Test Case:**
    1. **Setup:**
       - Create (or modify) a Django template file in the workspace (for example, `test_template.html`).
       - In this file, insert an include directive with a crafted relative file path. For example:
         ```
         {% include "../../secret_config.txt" %}
         ```
         (Ensure that a file such as `secret_config.txt` exists outside the intended templates directory for testing purposes.)
    2. **Execution:**
       - Open `test_template.html` in Visual Studio Code.
       - Place the cursor over the relative file path string `"../../secret_config.txt"`.
       - Invoke the “Go to Definition” command (via F12 or Ctrl+Click on the path).
    3. **Expected Outcome:**
       - The extension’s definition provider should resolve the malicious path and return a file URI that leads to the file located at `../../secret_config.txt`.
       - VS Code then attempts to open that file, potentially exposing its content.
       - If the file outside the intended directory is opened without additional warnings or blocking, the vulnerability is confirmed.
    4. **Cleanup:**
       - Remove or remediate the test template file and any dummy sensitive files after testing.

Implementing proper path validation (for example, verifying that resolved paths remain within allowed directories) is recommended to mitigate this vulnerability.