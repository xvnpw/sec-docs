### Incorrect Content-Type Handling in Static File Server

* Vulnerability Name: Incorrect Content-Type Handling in Static File Server
* Description: The `StaticFileServer` in `server/static_file_server.go` determines the `Content-Type` of served files based on the file extension extracted using `filepath.Ext(r.URL.Path)`. This method only considers the final extension of the path. If a file path contains multiple extensions (e.g., `file.js.txt`), `filepath.Ext` will return the last extension (`.txt` in this example), leading to an incorrect `Content-Type` being set. This can be exploited by an attacker if they can control the file path and content being served to bypass intended `Content-Type` restrictions.
* Impact: If an attacker can upload or control files served by the `StaticFileServer` and manipulate the file path (e.g., using double extensions), they can potentially serve files with incorrect `Content-Type` headers. This can lead to:
    - **MIME confusion attacks**: An attacker might be able to serve a file with a misleading `Content-Type`, potentially tricking browsers into misinterpreting the file. For example, serving a Javascript file as `text/plain` might prevent its execution, while serving a text file as `application/javascript` might lead to unexpected behavior if the browser attempts to execute it.
    - **Cross-Site Scripting (XSS)**: In scenarios where the `StaticFileServer` is used to serve user-uploaded content or assets within a web application, and if the application relies on `Content-Type` to prevent execution of scripts, this vulnerability could be escalated to XSS. An attacker could upload a file with malicious Javascript code and a path like `malicious.js.txt`. If the server serves this file with `Content-Type: text/plain`, but the application's logic or a misconfiguration allows it to be interpreted as Javascript, XSS might be possible.

* Vulnerability Rank: High
* Currently Implemented Mitigations: None in the `StaticFileServer` code itself. The code directly uses `filepath.Ext` and `mimeTypes` map without any sanitization or validation of the path.
* Missing Mitigations:
    - **Path Sanitization**: The `r.URL.Path` should be sanitized to prevent path traversal and ensure it points to a valid file within the served directory.
    - **Extension Validation**: Instead of solely relying on the last extension, a more robust approach would be to validate the file extension against an allowlist of expected extensions or to use a library that can correctly determine the MIME type based on file content (like `http.DetectContentType` or a more specialized MIME type detection library) instead of just the extension.
    - **Content-Type Security Headers**: While not a direct mitigation for incorrect `Content-Type`, setting security headers like `X-Content-Type-Options: nosniff` can help prevent browsers from MIME-sniffing and overriding the server-specified `Content-Type`, reducing the risk of MIME confusion attacks.

* Preconditions:
    - The application using `prometheus/common` must utilize the `StaticFileServer` to serve static files.
    - An attacker needs to be able to influence the requested file path and potentially control the content of the served files, either through file upload functionality, path traversal vulnerabilities in other parts of the application, or if the static files themselves are somehow modifiable by an attacker.

* Source Code Analysis:
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

* Security Test Case:
    1. Set up a simple HTTP server that uses `StaticFileServer` to serve files from a directory. Let's assume the directory contains two files:
        - `test.js.txt`: A Javascript file with `.js.txt` extension. Content: `alert("XSS");`
        - `index.html`: A simple HTML file. Content: `<h1>Static File Server Test</h1><script src="test.js.txt"></script>`
    2. Configure the `mimeTypes` map in `StaticFileServer` to map `.js` to `application/javascript` and `.txt` to `text/plain`.
    3. Start the HTTP server and access `index.html` in a browser.
    4. Observe that the `test.js.txt` file is served with `Content-Type: text/plain`.
    5. Check if the Javascript code in `test.js.txt` is executed by the browser. It should **not** be executed because it's served as `text/plain`.
    6. **Expected Result (Vulnerable)**: The Javascript code is not executed because the `Content-Type` is incorrectly set to `text/plain`. This demonstrates the vulnerability where a file intended as Javascript is served as plain text due to incorrect extension handling. In a more critical scenario, if an attacker could control the served content and the application incorrectly handles the content based on path, this could lead to security issues.