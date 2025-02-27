- **Vulnerability Name:** Insecure Workspace Proxy Server Enabling Directory Traversal and Unauthorized File Access

  - **Description:**
    The extension’s HTTP proxy server (located in `workspace-proxy-server.ts`) is used during export operations to handle resource requests from within a workspace. When a GET request is handled, the code joins the workspace folder’s URI with a user‑provided URL pathname without explicitly validating or sanitizing it. This omission permits path traversal (for example, using “../” sequences) that can force the resolved URI outside the intended workspace folder. An attacker who is able to send HTTP requests to this proxy endpoint (for example, because of network misconfiguration or container exposure) could supply a crafted path, causing the proxy to read and return arbitrary local filesystem contents.

  - **Impact:**
    An attacker with access to the proxy server (even though it is by default bound to 127.0.0.1, misconfigurations or certain deployment setups might expose it externally) could retrieve sensitive files from the local filesystem. This could lead to the unintended exposure of credentials, configuration files, or proprietary source code.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - The proxy server is bound to the loopback interface (127.0.0.1) to limit access to local processes only.
    - The code uses `Uri.joinPath(workspaceFolder.uri, url.pathname)` to combine the incoming request’s pathname with the workspace folder’s URI.

    *(Note: These measures do not explicitly validate or sanitize dangerous path sequences, and as such, are insufficient when an attacker can control the request data.)*

  - **Missing Mitigations:**
    - There is no explicit check to ensure that the resolved URI remains within the intended workspace folder.
    - No sanitization or normalization is performed on the user‑supplied URL path (for example, to detect and reject “../” sequences).
    - There is no additional access control (such as authentication or IP filtering) on the proxy endpoint.

  - **Preconditions:**
    - An export operation is triggered (for instance, by opening a Markdown document with Marp frontmatter), which causes the proxy server to start.
    - The document is associated with a workspace folder.
    - An attacker must be able to send crafted HTTP requests to the proxy endpoint (e.g. due to misconfigurations that expose the proxy).

  - **Source Code Analysis:**
    - In `/code/src/workspace-proxy-server.ts`, the GET request handler begins by constructing a URL object:
      ```js
      const url = new URL(req.url, `http://${req.headers.host}`)
      ```
    - The target VS Code URI is then constructed by “joining” the workspace folder’s URI with the raw `url.pathname`:
      ```js
      const vscodeUri = workspaceFolder.uri.with({
        fragment: url.hash,
        path: Uri.joinPath(workspaceFolder.uri, url.pathname).path,
        query: url.search,
      })
      ```
    - Because there is no validation to ensure that `url.pathname` does not contain sequences like `../` that would traverse upward, an attacker could provide a malicious pathname to resolve a file outside the workspace folder.
    - The code later checks for file existence using `workspace.fs.stat(vscodeUri)` and reads the file’s contents if found, potentially returning data from unintended filesystem locations.

  - **Security Test Case:**
    1. In a controlled testing environment, open a workspace (e.g. `/home/user/project`) in VS Code and open a Markdown document that includes Marp frontmatter (e.g. a header containing `---\nmarp: true\n---`), so that an export operation is initiated and the workspace proxy server starts.
    2. Determine (or capture from logs) the proxy server’s port number.
    3. Using a tool such as curl or Postman, send an HTTP GET request to a URL like:
       ```
       http://127.0.0.1:<port>/../.bashrc
       ```
       (Ensure that the “../” sequence is URL‑encoded if necessary.)
    4. If the vulnerability is present, the proxy server will resolve the path to a file outside the workspace (in this example, the user’s `.bashrc`) and return its contents in the HTTP response.
    5. After adding proper path sanitization (for example, verifying that the resolved path is within the workspace folder), the same request should be rejected (e.g. returning a 404 or error message).