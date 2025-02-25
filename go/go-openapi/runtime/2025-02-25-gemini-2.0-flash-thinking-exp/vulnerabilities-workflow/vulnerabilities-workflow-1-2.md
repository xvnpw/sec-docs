## Vulnerability List

- Header Injection in Content-Disposition during Multipart File Upload

### Vulnerability Name
Header Injection in Content-Disposition during Multipart File Upload

### Description
The `escapeQuotes` function in `client/request.go` escapes backslashes and double quotes in filenames used in `Content-Disposition` headers for multipart file uploads. However, it fails to escape newline characters (`\n` or `\r`). This omission allows an attacker to inject arbitrary headers by crafting a malicious filename containing newline characters followed by the headers they wish to inject.

Steps to trigger the vulnerability:
1.  Prepare a file with a malicious filename. This filename should contain a newline character (`\n` or `\r`) followed by header fields that the attacker wants to inject. For example, a filename could be: `test.txt\nInjected-Header: malicious-value`.
2.  Use an API endpoint that accepts multipart form data and includes a file upload parameter.
3.  Craft a multipart form request where the filename for the file upload parameter is set to the malicious filename prepared in step 1.
4.  Send the crafted multipart form request to the server.
5.  Observe the HTTP request sent by the client. The `Content-Disposition` header for the file part will contain the injected headers due to the unescaped newline characters in the filename.

### Impact
Successful header injection can have various impacts depending on the server-side application and its handling of HTTP headers. Potential impacts include:
- HTTP Response Splitting: In some scenarios, if the injected headers are reflected in the server's response headers without proper sanitization, it could lead to HTTP response splitting vulnerabilities. This allows an attacker to control the response sent back to the client, potentially leading to Cross-Site Scripting (XSS) or cache poisoning.
- Server-Side Request Forgery (SSRF): If the backend server uses the injected headers in subsequent requests, it might be possible to perform SSRF attacks.
- Information Disclosure: Injected headers might reveal sensitive information about the server's internal configuration or processing logic.
- Bypassing Security Controls: Injected headers could potentially bypass certain security controls or filters implemented by the server or intermediate proxies.

The severity of the impact depends heavily on the specific application and how it processes headers. However, the potential for header injection is generally considered a high-risk vulnerability.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The `escapeQuotes` function in `client/request.go` attempts to mitigate header injection by escaping backslashes and double quotes.
```go
func escapeQuotes(s string) string {
	return strings.NewReplacer("\\", "\\\\", `"`, "\\\"").Replace(s)
}
```
However, this mitigation is incomplete as it does not escape newline characters, which are crucial for header injection in this context.

### Missing Mitigations
The primary missing mitigation is proper sanitization of filenames to prevent header injection. Specifically, newline characters (`\n` and `\r`) and potentially other control characters should be removed or escaped from filenames before they are used in the `Content-Disposition` header.

A robust mitigation would involve:
-  Escaping or removing newline characters (`\n`, `\r`), carriage return, line feed and potentially other control characters from the filename.
-  Consider using a more comprehensive header sanitization or encoding mechanism if available from standard libraries.

### Preconditions
1.  The application must use the `github.com/go-openapi/runtime` library to handle client-side HTTP requests.
2.  An API endpoint in the application must accept multipart form data, including file upload parameters.
3.  The attacker needs to be able to control the filename of the uploaded file.

### Source Code Analysis
The vulnerability exists in the `BuildHTTP` function within the `/code/client/request.go` file, specifically in the multipart form handling section:

```go
// /code/client/request.go
func (r *request) buildHTTP(mediaType, basePath string, producers map[string]runtime.Producer, registry strfmt.Registry, auth runtime.ClientAuthInfoWriter) (*http.Request, error) {
    // ...
    if len(r.formFields) > 0 || len(r.fileFields) > 0 {
        // ...
        go func() {
            // ...
            for fn, f := range r.fileFields {
                for _, fi := range f {
                    // ...

                    // Create the MIME headers for the new part
                    h := make(textproto.MIMEHeader)
                    h.Set("Content-Disposition",
                        fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
                            escapeQuotes(fn), escapeQuotes(filepath.Base(fi.Name())))) // Vulnerable code: escapeQuotes does not escape newline characters
                    h.Set("Content-Type", fileContentType)

                    wrtr, err := mp.CreatePart(h)
                    // ...
                }
            }
        }()
        // ...
    }
    // ...
}

func escapeQuotes(s string) string {
	return strings.NewReplacer("\\", "\\\\", `"`, "\\\"").Replace(s)
}
```

- The `BuildHTTP` function constructs an HTTP request.
- When handling multipart form data with file uploads, it iterates through `r.fileFields`.
- For each file, it creates MIME headers, including `Content-Disposition`.
- The `Content-Disposition` header is constructed using `fmt.Sprintf` and the `escapeQuotes` function to sanitize the filename (`filepath.Base(fi.Name())`).
- **Vulnerability**: The `escapeQuotes` function only escapes backslashes and double quotes but not newline characters. This allows an attacker to inject newline characters into the filename, which can be interpreted as header separators, leading to header injection.

**Visualization:**

```
Multipart Form Data Construction:

-----------------------------boundary  <-- Boundary
Content-Disposition: form-data; name="file"; filename="malicious\nInjected-Header: value"  <-- Injected header here due to newline
Content-Type: application/octet-stream

<file content>
-----------------------------boundary--
```

### Security Test Case
**Test Scenario:** Verify that a malicious filename with newline characters can inject headers into the `Content-Disposition` header during a multipart file upload.

**Steps:**

1.  **Set up a test server (optional but recommended for full verification):** You can use a simple HTTP server (e.g., using `net/http` in Go or `http.server` in Python) to receive the multipart request and inspect the headers. Alternatively, you can use a network interception tool like Wireshark or tcpdump to capture the raw HTTP request.
2.  **Prepare a malicious filename:** Create a string that includes a filename, a newline character (`\n` or `\r`), and an injected header. For example: `"test.txt\nInjected-Header: malicious-value"`.
3.  **Create a test file:** Create a dummy file (e.g., an empty text file) to be uploaded.
4.  **Construct a multipart form request using the vulnerable client:**
    ```go
    package main

    import (
        "bytes"
        "fmt"
        "mime/multipart"
        "net/http"
        "os"
        "strings"
        "testing"

        "github.com/go-openapi/runtime/client"
        "github.com/go-openapi/runtime"
    )

    func TestHeaderInjection(t *testing.T) {
        // 1. Prepare a malicious filename
        maliciousFilename := "test.txt\nInjected-Header: malicious-value"

        // 2. Create a test file (empty file for this test)
        tmpFile, err := os.CreateTemp("", "testfile")
        if err != nil {
            t.Fatalf("Failed to create temp file: %v", err)
        }
        defer os.Remove(tmpFile.Name())
        defer tmpFile.Close()

        // 3. Construct multipart form request
        r := client.NewRequest("POST", "/upload", runtime.ClientRequestWriterFunc(func(req runtime.ClientRequest, registry strfmt.Registry) error {
            file, err := os.Open(tmpFile.Name())
            if err != nil {
                return err
            }
            defer file.Close()
            return req.SetFileParam("file", runtime.NamedReader(maliciousFilename, file))
        }))

        producers := map[string]runtime.Producer{runtime.MultipartFormMime: runtime.MultipartProducer()}
        req, err := r.BuildHTTP(runtime.MultipartFormMime, "/", producers, nil)
        if err != nil {
            t.Fatalf("Failed to build HTTP request: %v", err)
        }

        // 4. Inspect the Content-Disposition header (for testing, we just check the header string)
        bodyBuf := new(bytes.Buffer)
        _, err = bodyBuf.ReadFrom(req.Body)
        if err != nil {
            t.Fatalf("Error reading request body: %v", err)
        }
        bodyString := bodyBuf.String()

        // Assert that "Injected-Header: malicious-value" is present in Content-Disposition
        if !strings.Contains(bodyString, "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\\nInjected-Header: malicious-value\"") {
            t.Errorf("Vulnerability not detected. Injected header not found in Content-Disposition header.")
        } else {
            fmt.Println("Vulnerability DETECTED. Injected header found in Content-Disposition header (Test Passed).")
        }

        // Optional: Send the request to a test server and verify server-side behavior.
        // ... (Server setup and request sending code would go here) ...
    }

    func main() {
        testing.Main(func(pat, str string) (bool, error) { return pat == str, nil },
            []testing.InternalTest{{"TestHeaderInjection", TestHeaderInjection}})
    }

    ```

5.  **Run the test case:** Execute the Go test code. The test should assert that the "Injected-Header: malicious-value" is present within the `Content-Disposition` header in the constructed multipart request body.  The output in the console will indicate if the vulnerability was detected.

**Expected Result:** The test case should pass, indicating that the injected header is present in the `Content-Disposition` header, thus confirming the header injection vulnerability. The console output should include "Vulnerability DETECTED. Injected header found in Content-Disposition header (Test Passed).".

This test case demonstrates that the lack of newline character escaping in filenames within `Content-Disposition` headers allows for header injection when using the `github.com/go-openapi/runtime` library for multipart file uploads.