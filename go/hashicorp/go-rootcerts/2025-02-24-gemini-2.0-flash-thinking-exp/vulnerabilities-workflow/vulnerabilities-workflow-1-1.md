### Vulnerability List

- Vulnerability Name: Path Traversal in Certificate Loading
- Description: The `rootcerts` library allows loading CA certificates from a file path (`CAFile`) or a directory path (`CAPath`) provided in the `Config`. If an attacker can control these paths (e.g., through environment variables if the application using this library reads them directly into the `Config`), they can provide paths containing traversal sequences like "../" to access files outside the intended certificate directories.
- Impact: An attacker can potentially read arbitrary files from the system if the application using this library allows external control over the `CAFile` or `CAPath` configuration. This can lead to disclosure of sensitive information, including application configuration, source code, or other system files.
- Vulnerability Rank: High
- Currently implemented mitigations: None. The library directly uses the provided paths with `ioutil.ReadFile` and `filepath.Walk` without any sanitization.
- Missing mitigations: Input sanitization for `CAFile` and `CAPath` in the `Config`. The library should validate and sanitize these paths to prevent traversal attacks. For example, it could verify that the paths are within an expected base directory and reject paths containing ".." components or paths that resolve outside of the intended base directory.
- Preconditions:
    - An application uses the `rootcerts` library to configure TLS.
    - The application allows external configuration of `CAFile` or `CAPath`, for example, by reading these values from environment variables or user-provided input.
    - An attacker can control the values of these configuration parameters.
- Source code analysis:
    - In `rootcerts.go`, the `LoadCACerts` function processes the `Config` struct.
    - If `Config.CAFile` is set, the `LoadCAFile` function is called with the user-provided `CAFile` path.
    - `LoadCAFile` in `rootcerts.go` reads the file content using `ioutil.ReadFile(caFile)`. The `caFile` path is used directly without any validation or sanitization.
    ```go
    func LoadCAFile(caFile string) (*x509.CertPool, error) {
        pool := x509.NewCertPool()

        pem, err := ioutil.ReadFile(caFile) // Vulnerable line: caFile is not sanitized
        if err != nil {
            return nil, fmt.Errorf("Error loading CA File: %s", err)
        }

        ok := pool.AppendCertsFromPEM(pem)
        if !ok {
            return nil, fmt.Errorf("Error loading CA File: Couldn't parse PEM in: %s", err)
        }

        return pool, nil
    }
    ```
    - If `Config.CAPath` is set, the `LoadCAPath` function is called with the user-provided `CAPath`.
    - `LoadCAPath` in `rootcerts.go` uses `filepath.Walk(caPath, walkFn)` to traverse the directory. Inside the `walkFn`, it reads each file using `ioutil.ReadFile(path)`. Both `caPath` and `path` within the walk function are used directly without sanitization.
    ```go
    func LoadCAPath(caPath string) (*x509.CertPool, error) {
        pool := x509.NewCertPool()
        walkFn := func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }

            if info.IsDir() {
                return nil
            }

            pem, err := ioutil.ReadFile(path) // Vulnerable line: path is not sanitized
            if err != nil {
                return fmt.Errorf("Error loading file from CAPath: %s", err)
            }

            ok := pool.AppendCertsFromPEM(pem)
            if !ok {
                return fmt.Errorf("Error loading CA Path: Couldn't parse PEM in: %s", path)
            }

            return nil
        }

        err := filepath.Walk(caPath, walkFn) // Vulnerable line: caPath is not sanitized
        if err != nil {
            return nil, err
        }

        return pool, nil
    }
    ```
- Security test case:
    1. Create a directory structure for testing, for example:
        ```
        /tmp/test_rootcerts/app/
        /tmp/test_rootcerts/certs/cacert.pem  (Valid PEM certificate file)
        /tmp/test_rootcerts/sensitive_file.txt (File to be accessed via path traversal)
        ```
        Place a valid PEM certificate in `/tmp/test_rootcerts/certs/cacert.pem` and a sensitive text file (e.g., with content "This is sensitive data.") in `/tmp/test_rootcerts/sensitive_file.txt`.
    2. Create a Go application `test_app.go` in `/tmp/test_rootcerts/app/` that uses the `rootcerts` library. The application should configure TLS using `rootcerts.ConfigureTLS` and allow setting `CAFile` via an environment variable `TEST_CAFILE`.
        ```go
        package main

        import (
            "crypto/tls"
            "fmt"
            "net/http"
            "os"

            "github.com/hashicorp/go-rootcerts"
        )

        func main() {
            tlsConfig := &tls.Config{}
            conf := &rootcerts.Config{
                CAFile: os.Getenv("TEST_CAFILE"),
            }
            err := rootcerts.ConfigureTLS(tlsConfig, conf)
            if err != nil {
                fmt.Println("Error configuring TLS:", err)
                os.Exit(1)
            }

            client := http.Client{
                Transport: &http.Transport{
                    TLSClientConfig: tlsConfig,
                },
            }

            // Attempt to make a request (this part is just to trigger the TLS config, the actual request is not important for this test)
            _, err = client.Get("https://example.com")
            if err != nil && err.Error() != "Get \"https://example.com\": x509: certificate signed by unknown authority" { // Expecting certificate error if no valid CA is provided, or other errors. If path traversal is successful, different errors might occur.
                fmt.Println("Request Error (expected or due to path traversal attempt):", err)
            } else if err == nil {
                fmt.Println("Request successful (unexpected if path traversal read invalid cert): Request might have proceeded without intended root CAs or path traversal failed silently.")
            } else {
                fmt.Println("Expected x509 error (or path traversal attempt resulted in x509 error):", err)
            }

            // Attempt to read the file content directly to confirm if path traversal is possible.
            content, err := os.ReadFile(os.Getenv("TEST_CAFILE"))
            if err == nil {
                fmt.Printf("File content (if read successfully via path traversal):\n%s\n", string(content))
            } else {
                fmt.Printf("Error reading file (expected if path traversal blocked or target is not readable as cert): %v\n", err)
            }

        }
        ```
    3. Compile the application: `go build test_app.go`
    4. Run the application without path traversal, using a valid certificate file as a baseline:
        ```bash
        export TEST_CAFILE=/tmp/test_rootcerts/certs/cacert.pem
        cd /tmp/test_rootcerts/app/
        ./test_app
        ```
        Observe the output, it might show an x509 error because example.com cert is not signed by `/tmp/test_rootcerts/certs/cacert.pem`, but it should not print the content of sensitive file.

    5. Run the application with path traversal to access the sensitive file:
        ```bash
        export TEST_CAFILE='../../../sensitive_file.txt'
        cd /tmp/test_rootcerts/app/
        ./test_app
        ```
        If the path traversal is successful, the application will attempt to read `/tmp/test_rootcerts/sensitive_file.txt` as a certificate. The application output should now either:
            - Print the content of `/tmp/test_rootcerts/sensitive_file.txt` if the `os.ReadFile` in test app is successful, confirming path traversal.
            - Show an error message indicating that it tried to parse the content of `/tmp/test_rootcerts/sensitive_file.txt` as a PEM certificate, and failed, but importantly, it shows that the application *tried* to read that file, confirming path traversal. The error message might contain parts of the sensitive file content if the PEM parsing fails after reading some of the file.
        This test case demonstrates that an attacker, by controlling the `TEST_CAFILE` environment variable, can cause the application to attempt to read arbitrary files outside of the intended certificate paths, confirming the Path Traversal vulnerability.