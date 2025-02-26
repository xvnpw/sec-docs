- **Vulnerability Name:** SSRF via External Stylesheet Fetching  
  **Description:**  
  The extension supports external stylesheets referenced through `<link>` elements in HTML files. An attacker can craft a malicious HTML file that contains a `<link>` tag with a reference to an attacker‑controlled URL. When a user (or an automated system) opens this malicious workspace, the extension will automatically scan the HTML file and attempt to fetch the remote stylesheet. The steps involved are:  
  1. The attacker creates an HTML file containing a tag such as:  
     `<link rel="stylesheet" href="http://attacker-controlled.example/evil.css">`  
  2. The attacker distributes this file (for example, by contributing it to a public repository or mailing it directly).  
  3. A victim, using VS Code with the extension enabled, opens the project.  
  4. The extension reads the HTML file, discovers the external stylesheet reference, and automatically attempts to fetch the file from the provided URL.  
  5. The attacker’s server then receives the request from the victim’s machine—potentially hitting internal endpoints if the URL is carefully crafted.  

  **Impact:**  
  Exploitation of this vulnerability may allow the attacker to:
  - Initiate unwanted outbound requests from the victim’s machine.
  - Leverage the victim’s network permissions to access internal or otherwise unreachable services.
  - Potentially gather information about the victim’s network environment, leading to further targeting.  

  **Vulnerability Rank:** High  

  **Currently Implemented Mitigations:**  
  - There is no evidence in the documentation or configuration of any URL validation or whitelist enforcement for external stylesheet links.  

  **Missing Mitigations:**  
  - Validate and sanitize the URL extracted from `<link>` elements.
  - Enforce a whitelist of allowed domains or require HTTPS.
  - Restrict fetching only to local workspace files unless explicitly approved.
  
  **Preconditions:**  
  - The attacker must be able to supply or modify HTML content in a project (for example, via a malicious pull request or by tricking a user into downloading a compromised project).
  - The victim must have the extension enabled and automatically process external `<link>` references.

  **Source Code Analysis:**  
  - The README and changelog state that the extension “supports external stylesheets referenced through `link` elements in HTML files.”  
  - This implies that during the workspace scan the extension parses HTML files, extracts the href attribute from `<link>` tags, and fetches the corresponding CSS file.  
  - Without proper input validation (e.g., checking the scheme, domain, or network destination), this behavior results in an SSRF risk.  
  - The absence of documented URL restrictions or sanitization steps indicates that any URL supplied via a `<link>` element will be fetched.  

  **Security Test Case:**  
  1. **Preparation:** Set up a controlled HTTP server (acting as the attacker’s server) to log incoming requests.  
  2. **Attack File Creation:** Create an HTML file with the following content:  
     ```html
     <!DOCTYPE html>
     <html>
     <head>
       <link rel="stylesheet" href="http://<YOUR-TEST-SERVER>/evil.css">
     </head>
     <body>
       <h1>Test Page</h1>
     </body>
     </html>
     ```  
  3. **Workspace Setup:** Place the HTML file in a new workspace and open the workspace in Visual Studio Code with the extension enabled.  
  4. **Trigger Action:** Either open the HTML file or manually trigger the caching process (e.g., via “Cache CSS class definitions” command).  
  5. **Observation:** Monitor the test server logs for an HTTP request corresponding to `evil.css`.  
  6. **Result:** Verification of the outbound request confirms that the extension fetched the external resource, validating the SSRF vulnerability.

---

- **Vulnerability Name:** Arbitrary File Read via Symlink Traversal in Workspace  
  **Description:**  
  The extension scans workspace files according to configured glob patterns (by default, `"**/*.{css,html}"`) to cache CSS class definitions. If a malicious actor includes a symlink (or similarly manipulated file path) within the project that points to a sensitive file outside the intended project directory, the extension might follow the link and read unauthorized file content. The exploitation steps can be outlined as follows:  
  1. The attacker creates a project (or submits a contribution) containing a symlink named for example `malicious.css` that points to a sensitive file (e.g., `/etc/passwd` on Linux or a critical configuration file on Windows).  
  2. The extension, during its file scan and caching process, uses its include glob pattern to locate files.  
  3. The glob pattern matches the symlink without checking if it points outside the workspace.  
  4. The extension then opens and reads the content of the file the symlink points to, unknowingly caching sensitive information.  

  **Impact:**  
  The exploitation can lead to:  
  - Disclosure of confidential or system-sensitive data.
  - Leakage of internal configuration details, which can pave the way for further attacks.  
  - Compromise of the victim’s system confidentiality through unintended file reads.

  **Vulnerability Rank:** High

  **Currently Implemented Mitigations:**  
  - Although user settings (e.g., `"html-css-class-completion.includeGlobPattern"` and `"excludeGlobPattern"`) allow configuring which files or folders to scan, there is no documented behavior regarding the handling of symbolic links or path validation that would prevent reading files outside the workspace.

  **Missing Mitigations:**  
  - Implement explicit checks to ensure that files opened or scanned reside within the intended project directory.
  - Do not follow symlinks that point outside the workspace root (or require explicit user confirmation).
  - Sanitize and validate resolved file paths before processing.

  **Preconditions:**  
  - The attacker must be able to place a malicious project or contribution in a workspace (for example, by contributing to a public repository).
  - The user must open or check out the project with the extension enabled, triggering the caching process.
  
  **Source Code Analysis:**  
  - Documentation for the extension specifies the use of glob patterns to locate CSS and HTML files.  
  - In the absence of specific code to resolve and restrict symbolic links, a pattern like `"**/*.{css,html}"` will match symlinked files indiscriminately.  
  - Thus, if a symlink points to a file outside the repository (e.g., a system file), the standard file I/O used by the extension will follow the link and include the file content in its cache.

  **Security Test Case:**  
  1. **Preparation:** On a test system, create a file (for instance, if on Linux, use `/etc/hosts` or another noncritical file that represents sensitive data).  
  2. **Attack Setup:** In a new workspace, create a symlink named `malicious.css` that points to the chosen sensitive file.  
     - Example (Linux/macOS):  
       ```
       ln -s /etc/hosts malicious.css
       ```  
  3. **Workspace Setup:** Open the workspace in Visual Studio Code with the extension installed and enabled.  
  4. **Trigger Action:** Trigger the caching process either by opening the workspace (or by executing the “Cache CSS class definitions” command).  
  5. **Observation:** Check the extension’s output or cache. Alternatively, log the file read operations if possible.  
  6. **Result:** If the sensitive file’s content appears in the cache data (or an error log indicates an unexpected file read), then the vulnerability is confirmed.