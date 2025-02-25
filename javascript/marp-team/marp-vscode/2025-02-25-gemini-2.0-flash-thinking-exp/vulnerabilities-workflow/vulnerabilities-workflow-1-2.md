- **Vulnerability Name:** Unrestricted HTML Rendering in Trusted Workspaces  
  **Description:**  
  An attacker can craft a malicious Markdown file that includes dangerous HTML elements (for example, a `<script>` tag that executes arbitrary JavaScript) and include a Marp front matter (i.e. `marp: true`). If the user opens this file in a workspace that is marked as trusted—and if the user’s configuration for HTML rendering (controlled by the `markdown.marp.html` setting) is set to “all” (or otherwise bypasses the default allowlist)—then the extension will render every HTML element without filtering. This results in the injected script being executed in the preview pane.  
  **Impact:**  
  Exploitation would allow an attacker to execute arbitrary JavaScript code in the context of the VS Code instance (or its preview window). This could lead to session hijacking, theft of sensitive information, or any number of client-side attacks that compromise the user’s environment.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - In untrusted workspaces the extension always ignores HTML elements regardless of the `markdown.marp.html` setting.
  - When using the default behavior in trusted workspaces, Marp Core relies on a predefined allowlist (see its internal `allowlist.ts`) to filter out dangerous elements.  
  **Missing Mitigations:**  
  - No enforcement (or runtime warning) is provided when the user explicitly sets the configuration to “all” in a trusted workspace.
  - There is no additional sanitization or content security policy applied at render time to guard against injected scripts when the allowlist is intentionally bypassed.
  **Preconditions:**  
  - The target Markdown file must be opened in a workspace that is marked as trusted.
  - The user’s configuration for HTML rendering (i.e. `markdown.marp.html`) must be set to “all” or otherwise disable the safe allowlist.
  - The attacker must be able to supply or trick the user into opening a maliciously crafted Markdown file.
  **Source Code Analysis:**  
  - The extension delegates Markdown rendering to Marp Core. Marp Core normally sanitizes HTML using an allowlist (defined in its internal file such as `src/html/allowlist.ts`).
  - When a user opts for “all” via the `markdown.marp.html` setting, this allowlist is bypassed so that all HTML elements in the user’s Markdown are embedded verbatim in the output.
  - For example, a file with the following content:  
    ```markdown
    ---
    marp: true
    ---
    
    <script>alert('XSS');</script>
    ```  
    when rendered in a trusted workspace with HTML rendering set to “all” will trigger the execution of the script.
  **Security Test Case:**  
  1. In VS Code (with the Marp for VS Code extension installed), mark a workspace as trusted.  
  2. In the user settings, set `markdown.marp.html` to “all”.  
  3. Create a Markdown file with the following content:
     ```markdown
     ---
     marp: true
     ---
     
     <script>alert('XSS');</script>
     ```
  4. Open the file in VS Code and switch to the Marp preview.
  5. Verify that the alert (or equivalent malicious behavior) occurs, confirming that the script was executed.

- **Vulnerability Name:** Insecure Path Resolution During Markdown Export  
  **Description:**  
  When exporting a slide deck (to HTML, PDF, PPTX, or images), the extension uses a path resolution method that depends on whether the Markdown file belongs to a VS Code workspace. If the file does not belong to any workspace—or if the experimental setting `markdown.marp.strictPathResolutionDuringExport` is disabled—the export functionality resolves relative paths based on the local file system rather than strictly within the workspace. An attacker can craft a Markdown file whose image or link references use relative paths that point to sensitive local files. When a user triggers an export, the export process could inadvertently include the contents of these files into the output.  
  **Impact:**  
  This vulnerability could lead to local file disclosure. Sensitive data (for example, configuration files or other restricted documents) might be embedded into an exported slide deck, revealing information that should remain private.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - An experimental setting (`markdown.marp.strictPathResolutionDuringExport`) is available that, when enabled, forces the export command to resolve paths relative to the VS Code workspace of the Markdown file.  
  **Missing Mitigations:**  
  - The strict path resolution feature is experimental and is not enabled by default, leaving the fallback behavior vulnerable in cases where the Markdown file is not in a workspace.
  - There is no runtime sanitization or checking to prevent a maliciously crafted relative path from referencing sensitive locations on the user’s file system.
  **Preconditions:**  
  - The user must run the export command on a Markdown file that is not part of a recognized workspace or in an environment where `markdown.marp.strictPathResolutionDuringExport` is disabled.
  - The Markdown file must include relative paths (for example, in image links) that reference sensitive files on the local file system.
  **Source Code Analysis:**  
  - According to the changelog and documentation, if a Markdown file is not tied to a workspace, the export command falls back to resolving relative paths using the local file system’s structure.
  - For instance, a Markdown file containing a line like:
    ```markdown
    ![](/etc/passwd)
    ```
    when exported without strict path resolution, the export engine may try to include the content of `/etc/passwd` into the exported slide deck.
  - This behavior relies on the underlying file resolution logic in the export module, and there is no additional filtering to block access to sensitive system files.
  **Security Test Case:**  
  1. Create a Markdown file with Marp front matter and include a reference to a sensitive local file (e.g., an image reference such as `![](/etc/passwd)` on a Unix-like system or a similarly sensitive file on other platforms).  
  2. Ensure that the Markdown file is opened outside of any VS Code workspace or that the experimental strict path resolution setting is left disabled.  
  3. Trigger the export command (to PDF, HTML, etc.) using the Marp for VS Code extension.  
  4. Review the export output to determine if the contents of the sensitive file have been included.  
  5. The successful inclusion of such content confirms the vulnerability.