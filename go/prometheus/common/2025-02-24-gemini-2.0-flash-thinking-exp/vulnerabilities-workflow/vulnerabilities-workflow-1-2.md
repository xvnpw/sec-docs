- **Vulnerability Name:** Directory Listing Enabled in Static File Server
  **Description:**
  The static file server (implemented in `server/static_file_server.go`) simply wraps Go’s built‑in file server without preventing directory browsing. When a user (or attacker) requests a URL corresponding to a directory that lacks an index file, the built‑in handler auto‑generates and returns a listing of the directory’s contents.
  **Impact:**
  Exposing directory contents lets an attacker enumerate files and subdirectories. This may disclose internal configuration files, static assets, or backup files that could be used for further targeted attacks.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  No restrictions or checks are in place to prevent automatic directory enumeration.
  **Missing Mitigations:**
  - Detect if the requested path is a directory without an index file and return a “403 Forbidden” or “404 Not Found” response.
  - Alternatively, wrap the file server with logic that explicitly disables directory listings.
  **Preconditions:**
  - The static file server must be enabled and serving files from a directory that lacks a proper index file.
  - The server is publicly accessible, allowing external requests to trigger directory listings.
  **Source Code Analysis:**
  In the file `server/static_file_server.go`, the code delegates directly to Go’s `http.FileServer`. Because no check or filter is applied on directory requests, an HTTP GET that maps to a directory (that does not contain an index file) triggers an automatic directory listing.
  **Security Test Case:**
  1. Deploy the application with the static file server enabled.
  2. Ensure that the server’s root (or at least one subdirectory) does not contain an index file.
  3. From an external client, issue an HTTP GET request for that directory’s URL.
  4. Verify that an auto‑generated directory listing is returned and that file and subdirectory names are exposed.

––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
- **Vulnerability Name:** Missing X‑Content‑Type‑Options Header in Static File Server
  **Description:**
  The static file server does not set the HTTP header `X-Content-Type-Options: nosniff` when serving files. Without this header, browsers may MIME‑sniff file contents rather than relying solely on the declared content type.
  **Impact:**
  Improper MIME type interpretation can enable certain cross‑site scripting (XSS) attacks or drive‑by downloads, particularly if an attacker can influence file content or file naming such that the browser misinterprets the file’s type.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  There is no logic in the static file server to add the `X-Content-Type-Options` header to responses.
  **Missing Mitigations:**
  - Update the static file server’s handler logic to call, for example:
    ```go
    w.Header().Set("X-Content-Type-Options", "nosniff")
    ```
    prior to writing out the file response.
  **Preconditions:**
  - The static file server must be active.
  - It must serve files (such as JavaScript or HTML) that could be susceptible to misuse if their MIME type is modified by the browser through sniffing.
  **Source Code Analysis:**
  In `server/static_file_server.go`, although the code sets conventional headers (such as Content‑Type) based on file extension, it does not include any step to append the security header `X-Content-Type-Options: nosniff`.
  **Security Test Case:**
  1. Deploy the application with the static file server active.
  2. Request a file (for example, a JavaScript or HTML file) using an HTTP client or browser.
  3. Inspect the response headers to verify that `X-Content-Type-Options` is missing.
  4. Use a tool or mimic MIME‑sniffing behavior to demonstrate how the absence of this header may lead to unsafe interpretation of file contents.

––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
- **Vulnerability Name:** Arbitrary File Read via Misconfigured Header Files in HTTP Headers Configuration
  **Description:**
  The HTTP headers configuration code (in files such as `config/headers.go`) permits header values to be specified via external file references. The code uses a helper function that prepends a base directory to each provided file path. However, no robust sanitization is applied to ensure that the resulting file path remains within the intended directory. An attacker (or a misconfigured administrator) could supply file paths containing directory‑traversal sequences (e.g. `"../"`) to escape the trusted base directory.
  **Impact:**
  Exploiting this vulnerability could allow an attacker to have the server include the contents of arbitrary files (for example, internal configuration files or secrets) in HTTP responses or logs. Such exposure could leak sensitive internal information that may be further exploited.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  The configuration code simply calls `JoinDir(base, file)` without verifying that the combined path does not escape the intended directory.
  **Missing Mitigations:**
  - Sanitize and validate each file path input (e.g., by using `filepath.Clean`) and verify that the resolved path has the expected base directory as its prefix.
  - Reject any file paths containing directory‑traversal sequences (like `"../"`) or those that resolve to an absolute path outside of the intended directory.
  **Preconditions:**
  - The application must be configured to load header values from external files.
  - An attacker (or an erroneous configuration) must supply file paths that include directory‑traversal patterns.
  **Source Code Analysis:**
  In `config/headers.go`, a method (e.g. `SetDirectory`) iterates over configured header file paths and calls:
  ```go
  h.Files[i] = JoinDir(dir, h.Files[i])
  ```
  Because there is no subsequent validation that the resulting path remains within the trusted directory, malicious values (e.g. those containing `"../"`) can be used to read arbitrary files.
  **Security Test Case:**
  1. Configure the application’s HTTP headers to include a header that references an external file using a directory‑traversal sequence (for example: `"../secret.conf"`).
  2. Start the server with this configuration loaded.
  3. Trigger an HTTP request that causes the header round‑tripper to process and include the configured header value.
  4. Verify that the contents of a file outside of the intended directory (e.g. `secret.conf`) are read and incorporated—demonstrating that an attacker could extract arbitrary file contents.

––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
- **Vulnerability Name:** Insecure File Permissions for Generated TLS Private Keys by Certificate Generation Utility
  **Description:**
  The certificate generation utility (located in `config/generate.go`) is used to create certificate/key pairs for test or development purposes. When writing out the generated TLS private key file, the code sets its permissions to 0644 instead of using more restrictive permissions. This misconfiguration means that the private key file is world‑readable. Should the key file be exposed (for example, via a misconfigured static file server), an attacker might be able to retrieve the private key.
  **Impact:**
  If an attacker gains access to the TLS private key, they can impersonate the server, decrypt TLS traffic, and perform man‑in‑the‑middle (MITM) attacks. This completely undermines the confidentiality and integrity guarantees provided by TLS.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  The key file is written using:
  ```go
  os.WriteFile(fmt.Sprintf("%s.key", path), b.Bytes(), 0o644)
  ```
  which leaves the file world‑readable.
  **Missing Mitigations:**
  - Modify the certificate generation utility to write private key files with restrictive permissions (such as 0600) so that only the file owner has read access.
  **Preconditions:**
  - The certificate generation tool is executed (for example, via `go run config/generate.go`) to produce TLS key files.
  - The directory where key files are stored is either directly accessible via another misconfigured endpoint (e.g. via the static file server) or is on a multi‑user system where unprivileged users might read the file system.
  **Source Code Analysis:**
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
  **Security Test Case:**
  1. Run the certificate generation tool (for instance, `go run config/generate.go`).
  2. Locate one of the generated key files (e.g., `testdata/server.key`).
  3. On a Unix‑like system, run `ls -l testdata/server.key` and verify that its permissions are `-rw-r--r--` (0644).
  4. If the directory is accessible (or served), attempt an HTTP GET to retrieve the file contents.
  5. Confirm that the private key is readable by unauthorized users.
  6. As remediation, update the code to use restrictive permissions (e.g., 0600), regenerate the key, and verify that the file permissions now prevent unauthorized access.