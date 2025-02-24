## Combined Vulnerability List

This document consolidates identified vulnerabilities from the provided lists into a single, de-duplicated list. Each vulnerability is detailed with its description, impact, rank, mitigations, preconditions, source code analysis, and a security test case.

### Directory Listing Enabled in Static File Server

* **Vulnerability Name:** Directory Listing Enabled in Static File Server
* **Description:**
  The static file server (implemented in `server/static_file_server.go`) simply wraps Go’s built‑in file server without preventing directory browsing. When a user (or attacker) requests a URL corresponding to a directory that lacks an index file, the built‑in handler auto‑generates and returns a listing of the directory’s contents.
* **Impact:**
  Exposing directory contents lets an attacker enumerate files and subdirectories. This may disclose internal configuration files, static assets, or backup files that could be used for further targeted attacks.
* **Vulnerability Rank:** High
* **Currently Implemented Mitigations:**
  No restrictions or checks are in place to prevent automatic directory enumeration.
* **Missing Mitigations:**
  - Detect if the requested path is a directory without an index file and return a “403 Forbidden” or “404 Not Found” response.
  - Alternatively, wrap the file server with logic that explicitly disables directory listings.
* **Preconditions:**
  - The static file server must be enabled and serving files from a directory that lacks a proper index file.
  - The server is publicly accessible, allowing external requests to trigger directory listings.
* **Source Code Analysis:**
  In the file `server/static_file_server.go`, the code delegates directly to Go’s `http.FileServer`. Because no check or filter is applied on directory requests, an HTTP GET that maps to a directory (that does not contain an index file) triggers an automatic directory listing.
* **Security Test Case:**
  1. Deploy the application with the static file server enabled.
  2. Ensure that the server’s root (or at least one subdirectory) does not contain an index file.
  3. From an external client, issue an HTTP GET request for that directory’s URL.
  4. Verify that an auto‑generated directory listing is returned and that file and subdirectory names are exposed.

### Missing X‑Content‑Type‑Options Header in Static File Server

* **Vulnerability Name:** Missing X‑Content‑Type‑Options Header in Static File Server
* **Description:**
  The static file server does not set the HTTP header `X-Content-Type-Options: nosniff` when serving files. Without this header, browsers may MIME‑sniff file contents rather than relying solely on the declared content type.
* **Impact:**
  Improper MIME type interpretation can enable certain cross‑site scripting (XSS) attacks or drive‑by downloads, particularly if an attacker can influence file content or file naming such that the browser misinterprets the file’s type.
* **Vulnerability Rank:** High
* **Currently Implemented Mitigations:**
  There is no logic in the static file server to add the `X-Content-Type-Options` header to responses.
* **Missing Mitigations:**
  - Update the static file server’s handler logic to call, for example:
    ```go
    w.Header().Set("X-Content-Type-Options", "nosniff")
    ```
    prior to writing out the file response.
* **Preconditions:**
  - The static file server must be active.
  - It must serve files (such as JavaScript or HTML) that could be susceptible to misuse if their MIME type is modified by the browser through sniffing.
* **Source Code Analysis:**
  In `server/static_file_server.go`, although the code sets conventional headers (such as Content‑Type) based on file extension, it does not include any step to append the security header `X-Content-Type-Options: nosniff`.
* **Security Test Case:**
  1. Deploy the application with the static file server active.
  2. Request a file (for example, a JavaScript or HTML file) using an HTTP client or browser.
  3. Inspect the response headers to verify that `X-Content-Type-Options` is missing.
  4. Use a tool or mimic MIME‑sniffing behavior to demonstrate how the absence of this header may lead to unsafe interpretation of file contents.

### Arbitrary File Read via Misconfigured Header Files in HTTP Headers Configuration

* **Vulnerability Name:** Arbitrary File Read via Misconfigured Header Files in HTTP Headers Configuration
* **Description:**
  The HTTP headers configuration code (in files such as `config/headers.go`) permits header values to be specified via external file references. The code uses a helper function that prepends a base directory to each provided file path. However, no robust sanitization is applied to ensure that the resulting file path remains within the intended directory. An attacker (or a misconfigured administrator) could supply file paths containing directory‑traversal sequences (e.g. `"../"`) to escape the trusted base directory.
* **Impact:**
  Exploiting this vulnerability could allow an attacker to have the server include the contents of arbitrary files (for example, internal configuration files or secrets) in HTTP responses or logs. Such exposure could leak sensitive internal information that may be further exploited.
* **Vulnerability Rank:** High
* **Currently Implemented Mitigations:**
  The configuration code simply calls `JoinDir(base, file)` without verifying that the combined path does not escape the intended directory.
* **Missing Mitigations:**
  - Sanitize and validate each file path input (e.g., by using `filepath.Clean`) and verify that the resolved path has the expected base directory as its prefix.
  - Reject any file paths containing directory‑traversal sequences (like `"../"`) or those that resolve to an absolute path outside of the intended directory.
* **Preconditions:**
  - The application must be configured to load header values from external files.
  - An attacker (or an erroneous configuration) must supply file paths that include directory‑traversal patterns.
* **Source Code Analysis:**
  In `config/headers.go`, a method (e.g. `SetDirectory`) iterates over configured header file paths and calls:
  ```go
  h.Files[i] = JoinDir(dir, h.Files[i])
  ```
  Because there is no subsequent validation that the resulting path remains within the trusted directory, malicious values (e.g. those containing `"../"`) can be used to read arbitrary files.
* **Security Test Case:**
  1. Configure the application’s HTTP headers to include a header that references an external file using a directory‑traversal sequence (for example: `"../secret.conf"`).
  2. Start the server with this configuration loaded.
  3. Trigger an HTTP request that causes the header round‑tripper to process and include the configured header value.
  4. Verify that the contents of a file outside of the intended directory (e.g. `secret.conf`) are read and incorporated—demonstrating that an attacker could extract arbitrary file contents.

### Insecure File Permissions for Generated TLS Private Keys by Certificate Generation Utility

* **Vulnerability Name:** Insecure File Permissions for Generated TLS Private Keys by Certificate Generation Utility
* **Description:**
  The certificate generation utility (located in `config/generate.go`) is used to create certificate/key pairs for test or development purposes. When writing out the generated TLS private key file, the code sets its permissions to 0644 instead of using more restrictive permissions. This misconfiguration means that the private key file is world‑readable. Should the key file be exposed (for example, via a misconfigured static file server), an attacker might be able to retrieve the private key.
* **Impact:**
  If an attacker gains access to the TLS private key, they can impersonate the server, decrypt TLS traffic, and perform man‑in‑the‑middle (MITM) attacks. This completely undermines the confidentiality and integrity guarantees provided by TLS.
* **Vulnerability Rank:** High
* **Currently Implemented Mitigations:**
  The key file is written using:
  ```go
  os.WriteFile(fmt.Sprintf("%s.key", path), b.Bytes(), 0o644)
  ```
  which leaves the file world‑readable.
* **Missing Mitigations:**
  - Modify the certificate generation utility to write private key files with restrictive permissions (such as 0600) so that only the file owner has read access.
* **Preconditions:**
  - The certificate generation tool is executed (for example, via `go run config/generate.go`) to produce TLS key files.
  - The directory where key files are stored is either directly accessible via another misconfigured endpoint (e.g. via the static file server) or is on a multi‑user system where unprivileged users might read the file system.
* **Source Code Analysis:**
  In `config/generate.go`, the function (e.g. `writeCertificateAndKey`) writes out certificates and keys. The section writing the private key is:
  ```go
  b.Reset()
  if err := EncodeKey(&b, key); err != nil {
      return err
  }

  if err := os.WriteFile(fmt.Sprintf("%s.key", path), b.Bytes(), 0o644); err != nil {
      return err
  }
  ```
  The use of file mode `0644` results in the key being accessible by any user on the system.
* **Security Test Case:**
  1. Run the certificate generation tool (for instance, `go run config/generate.go`).
  2. Locate one of the generated key files (e.g., `testdata/server.key`).
  3. On a Unix‑like system, run `ls -l testdata/server.key` and verify that its permissions are `-rw-r--r--` (0644).
  4. If the directory is accessible (or served), attempt an HTTP GET to retrieve the file contents.
  5. Confirm that the private key is readable by unauthorized users.
  6. As remediation, update the code to use restrictive permissions (e.g., 0600), regenerate the key, and verify that the file permissions now prevent unauthorized access.

### Incorrect Content-Type Handling in Static File Server

* **Vulnerability Name:** Incorrect Content-Type Handling in Static File Server
* **Description:**
  The `StaticFileServer` in `server/static_file_server.go` determines the `Content-Type` of served files based on the file extension extracted using `filepath.Ext(r.URL.Path)`. This method only considers the final extension of the path. If a file path contains multiple extensions (e.g., `file.js.txt`), `filepath.Ext` will return the last extension (`.txt` in this example), leading to an incorrect `Content-Type` being set. This can be exploited by an attacker if they can control the file path and content being served to bypass intended `Content-Type` restrictions.
* **Impact:**
  If an attacker can upload or control files served by the `StaticFileServer` and manipulate the file path (e.g., using double extensions), they can potentially serve files with incorrect `Content-Type` headers. This can lead to:
    - **MIME confusion attacks**: An attacker might be able to serve a file with a misleading `Content-Type`, potentially tricking browsers into misinterpreting the file. For example, serving a Javascript file as `text/plain` might prevent its execution, while serving a text file as `application/javascript` might lead to unexpected behavior if the browser attempts to execute it.
    - **Cross-Site Scripting (XSS)**: In scenarios where the `StaticFileServer` is used to serve user-uploaded content or assets within a web application, and if the application relies on `Content-Type` to prevent execution of scripts, this vulnerability could be escalated to XSS. An attacker could upload a file with malicious Javascript code and a path like `malicious.js.txt`. If the server serves this file with `Content-Type: text/plain`, but the application's logic or a misconfiguration allows it to be interpreted as Javascript, XSS might be possible.
* **Vulnerability Rank:** High
* **Currently Implemented Mitigations:**
  None in the `StaticFileServer` code itself. The code directly uses `filepath.Ext` and `mimeTypes` map without any sanitization or validation of the path.
* **Missing Mitigations:**
    - **Path Sanitization**: The `r.URL.Path` should be sanitized to prevent path traversal and ensure it points to a valid file within the served directory.
    - **Extension Validation**: Instead of solely relying on the last extension, a more robust approach would be to validate the file extension against an allowlist of expected extensions or to use a library that can correctly determine the MIME type based on file content (like `http.DetectContentType` or a more specialized MIME type detection library) instead of just the extension.
    - **Content-Type Security Headers**: While not a direct mitigation for incorrect `Content-Type`, setting security headers like `X-Content-Type-Options: nosniff` can help prevent browsers from MIME-sniffing and overriding the server-specified `Content-Type`, reducing the risk of MIME confusion attacks.
* **Preconditions:**
    - The application using `prometheus/common` must utilize the `StaticFileServer` to serve static files.
    - An attacker needs to be able to influence the requested file path and potentially control the content of the served files, either through file upload functionality, path traversal vulnerabilities in other parts of the application, or if the static files themselves are somehow modifiable by an attacker.
* **Source Code Analysis:**
  ```go
  // File: /code/server/static_file_server.go
  func StaticFileServer(root http.FileSystem) http.Handler {
      return http.HandlerFunc(
          func(w http.ResponseWriter, r *http.Request) {
              fileExt := filepath.Ext(r.URL.Path) // Vulnerable line

              if t, ok := mimeTypes[fileExt]; ok {
                  w.Header().Set("Content-Type", t)
              }

              http.FileServer(root).ServeHTTP(w, r)
          },
      )
  }
  ```
  1. The `StaticFileServer` function is defined to serve static files from a given `http.FileSystem` root.
  2. Inside the handler function, `filepath.Ext(r.URL.Path)` is used to extract the file extension from the request URL path.
  3. This extension is then used as a key to look up the `Content-Type` in the `mimeTypes` map.
  4. If a matching `Content-Type` is found, it's set in the `Content-Type` header of the response.
  5. Finally, `http.FileServer(root).ServeHTTP(w, r)` serves the file.
  6. **Vulnerability**: The vulnerability is in step 2 and 3. `filepath.Ext` will only return the last extension. For example, if `r.URL.Path` is `/static/file.js.txt`, `fileExt` will be `.txt`. The `mimeTypes` map might not have an entry for `.txt` or might have it mapped to `text/plain`. Thus, even if the file is intended to be Javascript (`.js`), it could be served with an incorrect `Content-Type`.

  ```
  Visualization:

  Request URL Path: /static/file.js.txt
  ------------------------------------
  | filepath.Ext(r.URL.Path)         |
  ------------------------------------
          |
          V
  fileExt = ".txt"
  ------------------------------------
  | mimeTypes[fileExt]               |
  ------------------------------------
          |
          V
  Content-Type (potentially incorrect)
  ```

* **Security Test Case:**
    1. Set up a simple HTTP server that uses `StaticFileServer` to serve files from a directory. Let's assume the directory contains two files:
        - `test.js.txt`: A Javascript file with `.js.txt` extension. Content: `alert("XSS");`
        - `index.html`: A simple HTML file. Content: `<h1>Static File Server Test</h1><script src="test.js.txt"></script>`
    2. Configure the `mimeTypes` map in `StaticFileServer` to map `.js` to `application/javascript` and `.txt` to `text/plain`.
    3. Start the HTTP server and access `index.html` in a browser.
    4. Observe that the `test.js.txt` file is served with `Content-Type: text/plain`.
    5. Check if the Javascript code in `test.js.txt` is executed by the browser. It should **not** be executed because it's served as `text/plain`.
    6. **Expected Result (Vulnerable)**: The Javascript code is not executed because the `Content-Type` is incorrectly set to `text/plain`. This demonstrates the vulnerability where a file intended as Javascript is served as plain text due to incorrect extension handling. In a more critical scenario, if an attacker could control the served content and the application incorrectly handles the content based on path, this could lead to security issues.