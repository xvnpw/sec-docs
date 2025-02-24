Here is the combined list of vulnerabilities, formatted as markdown:

### Combined Vulnerability List

#### 1. Uncontrolled Resource Consumption via Recursive Property Expansion

- **Vulnerability Name:** Uncontrolled Resource Consumption via Recursive Property Expansion
- **Description:**
    - An attacker can craft a properties file or URL content with deeply nested or circular property references.
    - When the application loads and attempts to expand these properties using the `properties` library's `Get` or `Decode` methods, it triggers a recursive expansion process.
    - Due to the unbounded nature of the recursion in case of circular references or very deep nesting, this can lead to excessive CPU and memory consumption.
    - Step 1: Attacker crafts a malicious properties file or prepares a malicious URL endpoint serving such a file. This file contains deeply nested property expansions or a circular dependency, for example: `key1=${key2}\nkey2=${key3}\n...\nkeyN=${key1}` or deeply nested structure like `key1=${key2}\nkey2=${key3}\n...\nkeyN=${key_N+1}`.
    - Step 2: The application, using the `properties` library, is configured to load properties from the attacker-controlled source (file or URL).
    - Step 3: The application calls `p.Get("someKey")` or `p.Decode(&config)` where `p` is the `Properties` object loaded from the malicious source.
    - Step 4: The `properties` library's expansion mechanism starts processing the nested references.
    - Step 5: In case of circular dependency, the `expand` function will recursively call itself, leading to an infinite loop. In case of deep nesting, it will lead to stack overflow or excessive CPU usage.
- **Impact:**
    - High CPU consumption, potentially leading to application slowdowns or unresponsiveness.
    - High memory consumption, potentially leading to out-of-memory errors and application crashes.
    - In a shared hosting environment, this could impact other applications on the same server.
- **Vulnerability Rank:** high
- **Currently implemented mitigations:**
    - The `expand` function in `properties.go` includes a `maxExpansionDepth` constant (currently set to 64) to limit the depth of recursion and prevent infinite loops in case of circular references.
    - Circular reference detection within the `expand` function, which returns an error when a cycle is detected.
- **Missing mitigations:**
    - While `maxExpansionDepth` and circular reference detection are present, the depth limit might be too high, still allowing significant resource consumption before the limit is reached.
    - There is no configuration option to adjust or disable property expansion, which could be useful in scenarios where expansion is not needed or introduces unacceptable risk.
    - No rate limiting or resource quotas are implemented to restrict the amount of resources consumed by property expansion operations, especially when loading from external sources.
- **Preconditions:**
    - The application must be configured to load properties from an external source (file or URL) that can be influenced or controlled by the attacker.
    - The application must use the `properties` library's `Get` or `Decode` methods that trigger property expansion.
    - Property expansion must be enabled (i.e., `DisableExpansion` is false, which is the default).
- **Source code analysis:**
    - **File: /code/properties.go, Function: `expand`**
        ```go
        func expand(s string, keys []string, prefix, postfix string, values map[string]string) (string, error) {
            if len(keys) > maxExpansionDepth { // Mitigation: Depth limit
                return "", fmt.Errorf("expansion too deep")
            }

            for {
                start := strings.Index(s, prefix)
                if start == -1 {
                    return s, nil
                }

                keyStart := start + len(prefix)
                keyLen := strings.Index(s[keyStart:], postfix)
                if keyLen == -1 {
                    return "", fmt.Errorf("malformed expression")
                }

                end := keyStart + keyLen + len(postfix) - 1
                key := s[keyStart : keyStart+keyLen]

                // ... Circular reference check ...
                for _, k := range keys {
                    if key == k { // Mitigation: Circular reference detection
                        var b bytes.Buffer
                        b.WriteString("circular reference in:\n")
                        for _, k1 := range keys {
                            fmt.Fprintf(&b, "%s=%s\n", k1, values[k1])
                        }
                        return "", fmt.Errorf(b.String())
                    }
                }

                val, ok := values[key]
                if !ok {
                    val = os.Getenv(key)
                }
                new_val, err := expand(val, append(keys, key), prefix, postfix, values) // Recursive call
                if err != nil {
                    return "", err
                }
                s = s[:start] + new_val + s[end+1:]
            }
        }
        ```
        - The `expand` function recursively substitutes property values.
        - `maxExpansionDepth` and circular reference check are in place to mitigate infinite recursion, but the depth limit might be too high for practical purposes.
        - The function can be triggered by loading properties from any source and then calling `Get` or `Decode`.
- **Security test case:**
    - Step 1: Prepare a malicious properties file named `evil.properties` with the following content representing a circular dependency:
        ```properties
        key1=${key2}
        key2=${key1}
        ```
    - Step 2: Create a Go program that uses the `properties` library to load this file and then attempts to get the value of `key1`.
        ```go
        package main

        import (
            "fmt"
            "github.com/magiconair/properties"
            "time"
        )

        func main() {
            start := time.Now()
            p := properties.MustLoadFile("evil.properties", properties.UTF8)
            _, err := p.Get("key1")
            duration := time.Since(start)
            if err != nil {
                fmt.Println("Error:", err)
            }
            fmt.Println("Processing time:", duration)
        }
        ```
    - Step 3: Run the Go program.
    - Step 4: Observe the CPU and memory usage of the program. Even with the `maxExpansionDepth` limit, the program will consume resources for a noticeable duration before detecting the circular dependency and returning an error. In case of very deep but non-circular nesting, the resource consumption can be significantly higher and might not even trigger an error immediately, leading to a temporary hang or slowdown.

    - Step 5: (Improved Test Case for Deep Nesting - requires creating a larger file) Create a malicious properties file `deep_nesting.properties` with a deep chain of dependencies, for example, create 100 keys where each key depends on the next one:
        ```properties
        key1=${key2}
        key2=${key3}
        key3=${key4}
        ...
        key99=${key100}
        key100=value
        ```
    - Step 6: Modify the Go program to load `deep_nesting.properties`.
        ```go
        package main

        import (
            "fmt"
            "github.com/magiconair/properties"
            "time"
        )

        func main() {
            start := time.Now()
            p := properties.MustLoadFile("deep_nesting.properties", properties.UTF8)
            val, _ := p.Get("key1")
            duration := time.Since(start)
            fmt.Println("Value:", val)
            fmt.Println("Processing time:", duration)
        }
        ```
    - Step 7: Run the modified Go program and observe the increased processing time and resource usage compared to loading a benign properties file. The processing time should be noticeably higher due to the recursive expansion, even if it completes successfully.
- **Missing Mitigations:**
    - Implement a configurable expansion depth limit that can be set to a lower value or even zero to disable expansion entirely if needed.
    - Consider adding resource usage monitoring and limits within the expansion process itself, potentially halting expansion if it exceeds certain CPU or memory thresholds.
    - Provide guidance in documentation to users about the risks of loading properties from untrusted sources and recommend disabling expansion or setting a very low depth limit when handling external input.

#### 2. Server‐Side Request Forgery (SSRF) via LoadURL Function

- **Vulnerability Name:** Server‐Side Request Forgery (SSRF) via LoadURL Function
- **Description:**
  The library provides functions (e.g. `LoadURL` and `LoadURLs` in *load.go*) that accept a URL string and fetch its contents using the standard library’s `http.Get()` call. No input validation, domain whitelisting, or explicit timeout is applied to the URL parameter. An external attacker who can influence the URL input (for example, via a misconfigured or public instance that loads property files based on user input) can supply a malicious URL. By pointing the URL to internal resources (e.g. cloud metadata endpoints or otherwise restricted IP addresses), the attacker could force the application to fetch internal data.

  **Step‑by‑step how to trigger:**
  1. Identify that the application (using this library) supports loading configuration properties from remote URLs using functions such as `MustLoadURL()` or `LoadURL()`.
  2. Supply a URL value that points to an internal or otherwise restricted network address. For example, an attacker might supply a URL such as `http://169.254.169.254/latest/meta-data/` or another internal service.
  3. When the application invokes the URL‑loading function, it will blindly issue an HTTP request via `http.Get(url)`. The response is then processed and loaded without any checks restricting outbound requests.
  4. By observing error responses, logs, or (depending on the application’s behavior) the properties loaded into memory, the attacker may infer sensitive internal data or use the library as a foothold to perform further network probing.
- **Impact:**
  An attacker who can force the application to load properties from an arbitrary URL can use SSRF to:
  - Access information about internal network services that are not otherwise exposed externally.
  - Potentially retrieve sensitive data (e.g. internal metadata, credentials, or configuration details).
  - Use the internal access as a stepping stone for further attacks against internal systems.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  - The function does perform a minimal check on the HTTP response’s status code and Content‑Type header (only accepting responses with status code 200 and specific textual content types). However, this check only affects the interpretation (encoding) of the response and does not restrict which URLs can be fetched.
- **Missing Mitigations:**
  - **URL Validation / Whitelisting:** No mechanism to validate user‑supplied URLs against a whitelist of approved hosts or IP ranges is present.
  - **Timeout / Request Context:** The use of the default `http.Get()` (via the global HTTP client) does not enforce a specific timeout or restrict outbound network calls.
  - **Network Restriction:** There is no check to prevent requests to internal or loopback IP addresses.
- **Preconditions:**
  - The application must use the properties library function(s) that load remote URLs (e.g. `LoadURL` or `MustLoadURL`).
  - An attacker must be able to supply (or influence) the URL input—either directly via a user‑accessible configuration parameter, an API endpoint, or indirect configuration file upload.
- **Source Code Analysis:**
  - In *load.go*, the `LoadURL` function starts with:
    ```go
    resp, err := http.Get(url)
    if err != nil {
      return nil, fmt.Errorf("properties: error fetching %q. %s", url, err)
    }
    ```
    Here the input `url` is passed verbatim to `http.Get()` without any validation or filtering.
  - The response is then checked only for a 404 (with an option to ignore) and then that the response code is 200. The Content‑Type header is used solely to select the encoding but is not used to verify that the URL belongs to an allowed domain.
  - No additional security controls (such as timeouts or request context with deadline) are applied.
- **Security Test Case:**
  1. **Setup a Controlled Test Server:**
     - Spin up a local HTTP server (or use an internal test service) that simulates an internal resource and returns a plain‑text response (e.g. “secret=value”).
  2. **Invoke the Vulnerable Function:**
     - Call `MustLoadURL("http://<test-server-address>/...")` (or use the equivalent `LoadURL` function) from the application instance.
  3. **Verify Request Behavior:**
     - Confirm that the library makes an HTTP GET request to the supplied URL and that the response is processed into properties.
  4. **Simulate Malicious Request:**
     - Then, supply a URL pointing to a sensitive internal IP address (for example, `http://169.254.169.254/latest/meta-data/`) and observe that the library attempts to retrieve data from that URL.
  5. **Check Impact:**
     - If the application logs the error or (in misconfigured deployments) loads the remote data, then this demonstrates that the function does not restrict the outgoing request to approved domains.

  This test case proves that an external attacker with influence on the URL input could trigger the application to perform an SSRF request, thereby accessing internal services.

#### 3. Property Expansion Injection leading to Information Disclosure

- **Vulnerability Name:** Property Expansion Injection leading to Information Disclosure
- **Description:**
    1. An attacker hosts a malicious properties file on a publicly accessible server. This file contains a property whose value is designed to expose environment variables using property expansion. For example, the malicious property file could contain the line `vulnerable_key = User: ${USER}`.
    2. The application, using the `properties` library, is configured to load properties from URLs, potentially for dynamic configuration updates.
    3. The attacker provides the URL of their malicious properties file to the application, or if the application is configured to fetch URLs from an attacker-controlled source, they manipulate it to point to the malicious file.
    4. The application uses `properties.MustLoadURL` or a similar function to load properties from the attacker-provided URL.
    5. When the application later retrieves the value of a property that triggers expansion (either directly requesting `vulnerable_key` or another key that depends on it), the `properties` library expands the `${USER}` expression.
    6. If the application then logs or displays this expanded value (e.g., `User: <username>`), it unintentionally discloses the environment variable's content.
    7. An external attacker can then obtain sensitive information like usernames, system paths, or other environment variables that might be valuable for further attacks.

- **Impact:**
    Information disclosure. An attacker can potentially leak sensitive environment variables from the server running the application. This information can be used to further understand the system configuration and potentially aid in escalating attacks.
- **Vulnerability Rank:** High
- **Currently implemented mitigations:**
    None. The library currently performs property expansion on values loaded from URLs without sanitization or restrictions on which expressions can be used.
- **Missing mitigations:**
    - Input sanitization: Sanitize property values loaded from external sources to prevent injection of expansion expressions.
    - Restrict expansion expressions: Implement a whitelist of allowed expansion expressions, or disable environment variable expansion for externally loaded properties.
    - Content Security Policy (CSP): If the expanded values are displayed in a web context, a CSP could help mitigate the impact of potential client-side injection, but it doesn't prevent the server-side information disclosure. This is not applicable in this library context.
- **Preconditions:**
    - The application uses the `properties` library to load properties from external URLs.
    - The application retrieves and processes property values in a way that triggers property expansion and then exposes the expanded values (e.g., logging, display).
    - An attacker can control or influence the URL from which the properties are loaded.
- **Source code analysis:**
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

- **Security test case:**
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