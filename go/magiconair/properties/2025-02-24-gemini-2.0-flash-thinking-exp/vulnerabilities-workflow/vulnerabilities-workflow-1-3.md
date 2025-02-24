## Vulnerability List

### Vulnerability 1: Property Expansion Injection leading to Information Disclosure

* Description:
    1. An attacker hosts a malicious properties file on a publicly accessible server. This file contains a property whose value is designed to expose environment variables using property expansion. For example, the malicious property file could contain the line `vulnerable_key = User: ${USER}`.
    2. The application, using the `properties` library, is configured to load properties from URLs, potentially for dynamic configuration updates.
    3. The attacker provides the URL of their malicious properties file to the application, or if the application is configured to fetch URLs from an attacker-controlled source, they manipulate it to point to the malicious file.
    4. The application uses `properties.MustLoadURL` or a similar function to load properties from the attacker-provided URL.
    5. When the application later retrieves the value of a property that triggers expansion (either directly requesting `vulnerable_key` or another key that depends on it), the `properties` library expands the `${USER}` expression.
    6. If the application then logs or displays this expanded value (e.g., `User: <username>`), it unintentionally discloses the environment variable's content.
    7. An external attacker can then obtain sensitive information like usernames, system paths, or other environment variables that might be valuable for further attacks.

* Impact:
    Information disclosure. An attacker can potentially leak sensitive environment variables from the server running the application. This information can be used to further understand the system configuration and potentially aid in escalating attacks.

* Vulnerability Rank: High

* Currently implemented mitigations:
    None. The library currently performs property expansion on values loaded from URLs without sanitization or restrictions on which expressions can be used.

* Missing mitigations:
    - Input sanitization: Sanitize property values loaded from external sources to prevent injection of expansion expressions.
    - Restrict expansion expressions: Implement a whitelist of allowed expansion expressions, or disable environment variable expansion for externally loaded properties.
    - Content Security Policy (CSP): If the expanded values are displayed in a web context, a CSP could help mitigate the impact of potential client-side injection, but it doesn't prevent the server-side information disclosure. This is not applicable in this library context.

* Preconditions:
    - The application uses the `properties` library to load properties from external URLs.
    - The application retrieves and processes property values in a way that triggers property expansion and then exposes the expanded values (e.g., logging, display).
    - An attacker can control or influence the URL from which the properties are loaded.

* Source code analysis:
    1. **`load.go:LoadURL`**: This function fetches content from a given URL.

    ```go
    func (l *Loader) LoadURL(url string) (*Properties, error) {
        resp, err := http.Get(url) // Fetches content from URL
        if err != nil {
            return nil, fmt.Errorf("properties: error fetching %q. %s", url, err)
        }
        defer resp.Body.Close()
        // ... (Error handling and encoding detection) ...
        body, err := io.ReadAll(resp.Body) // Reads the response body
        if err != nil {
            return nil, fmt.Errorf("properties: %s error reading response. %s", url, err)
        }
        // ... (Encoding handling and loadBytes call) ...
        return l.loadBytes(body, enc) // Content is passed to loadBytes
    }
    ```

    2. **`load.go:loadBytes`**: This function parses the byte content into `Properties`.

    ```go
    func (l *Loader) loadBytes(buf []byte, enc Encoding) (*Properties, error) {
        p, err := parse(convert(buf, enc)) // Parses the content
        if err != nil {
            return nil, err
        }
        p.DisableExpansion = l.DisableExpansion
        if p.DisableExpansion {
            return p, nil
        }
        return p, p.check() // Checks for circular references, but after parsing
    }
    ```

    3. **`properties.go:Properties.Get`**: This function retrieves and expands property values.

    ```go
    func (p *Properties) Get(key string) (value string, ok bool) {
        v, ok := p.m[key] // Gets the raw value from map
        if p.DisableExpansion {
            return v, ok
        }
        if !ok {
            return "", false
        }

        expanded, err := p.expand(key, v) // Expands the value

        // ... (Error handling) ...

        return expanded, true
    }
    ```

    4. **`properties.go:Properties.expand`**: This function performs the recursive property expansion.

    ```go
    func (p *Properties) expand(key, input string) (string, error) {
        // ... (Prefix/Postfix handling) ...
        return expand(input, []string{key}, p.Prefix, p.Postfix, p.m) // Calls the core expand function
    }
    ```

    5. **`properties.go:expand`**: This is the core recursive expansion logic. Critically, it uses `os.Getenv(key)` to resolve environment variables.

    ```go
    func expand(s string, keys []string, prefix, postfix string, values map[string]string) (string, error) {
        // ... (Circular dependency check) ...
        for {
            // ... (Finds expression ${key}) ...
            val, ok := values[key]
            if !ok {
                val = os.Getenv(key) // Environment variable lookup
            }
            // ... (Recursive expansion) ...
        }
    }
    ```

    **Visualization:**

    ```mermaid
    sequenceDiagram
        participant Attacker
        participant Application
        participant PropertiesLibrary
        participant WebServer
        participant SystemEnvironment

        Attacker->>WebServer: Host malicious properties file (e.g., vulnerable.properties) with `vulnerable_key = User: ${USER}`
        Application->>PropertiesLibrary: Configure to load properties from URL
        Attacker->>Application: Provide URL to malicious properties file (e.g., `http://attacker.com/vulnerable.properties`)
        Application->>PropertiesLibrary: MustLoadURL("http://attacker.com/vulnerable.properties")
        PropertiesLibrary->>WebServer: GET http://attacker.com/vulnerable.properties
        WebServer-->>PropertiesLibrary: Respond with malicious properties file content
        PropertiesLibrary->>PropertiesLibrary: Parse and store properties (including `vulnerable_key = User: ${USER}`)
        Application->>PropertiesLibrary: GetString("some_key", "default") (or any operation that triggers expansion)
        PropertiesLibrary->>PropertiesLibrary: expand("User: ${USER}")
        PropertiesLibrary->>SystemEnvironment: os.Getenv("USER")
        SystemEnvironment-->>PropertiesLibrary: Return username (e.g., "system_user")
        PropertiesLibrary->>PropertiesLibrary: Expand to "User: system_user"
        PropertiesLibrary-->>Application: Return expanded value "User: system_user"
        Application->>Application: Log/Display "User: system_user" (Information Disclosure)
        Attacker->>Attacker: Obtain leaked username
    ```

* Security test case:
    1. **Setup:**
        - Create a simple HTTP server using Python or `net/http` in Go. This server will host the malicious properties file.
        - Create a malicious properties file named `vulnerable.properties` with the content: `vulnerable_key = User: ${USER}`.
        - In the HTTP server, serve this `vulnerable.properties` file when requested.
        - Create a Go test file that imports the `properties` library.

    2. **Test Steps:**
        - In the Go test, start the HTTP server in a separate goroutine.
        - Construct the URL for the malicious properties file (e.g., `http://localhost:<port>/vulnerable.properties`).
        - Use `properties.MustLoadURL(maliciousURL)` to load properties from the malicious URL.
        - Retrieve the value of `vulnerable_key` using `p.GetString("vulnerable_key", "")`.
        - Assert that the retrieved value contains the actual username of the system running the test. You can get the username using `os.Getenv("USER")` in Go for comparison.

    3. **Expected Result:**
        - The test should pass, demonstrating that the `properties` library expands the `${USER}` environment variable from the externally loaded malicious properties file, proving the information disclosure vulnerability.

    ```go
    // vulnerability_test.go
    package properties_test

    import (
        "fmt"
        "net/http"
        "net/http/httptest"
        "os"
        "strings"
        "testing"

        "github.com/magiconair/properties"
    )

    func TestPropertyExpansionInjection(t *testing.T) {
        // 1. Setup HTTP server to serve malicious properties file
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            content := `vulnerable_key = User: ${USER}`
            w.WriteHeader(http.StatusOK)
            w.Header().Set("Content-Type", "text/plain")
            w.Write([]byte(content))
        })
        server := httptest.NewServer(handler)
        defer server.Close()

        maliciousURL := server.URL

        // 2. Load properties from malicious URL
        p := properties.MustLoadURL(maliciousURL)

        // 3. Retrieve the vulnerable key and check for environment variable expansion
        expandedValue := p.GetString("vulnerable_key", "")
        expectedUsername := os.Getenv("USER") // Get current user's username

        // 4. Assert that the username is present in the expanded value
        if !strings.Contains(expandedValue, expectedUsername) {
            t.Errorf("Vulnerability test failed: Expected expanded value to contain username '%s', but got '%s'", expectedUsername, expandedValue)
        } else {
            fmt.Println("Vulnerability test passed: Successfully expanded and retrieved username:", expandedValue)
        }
    }
    ```