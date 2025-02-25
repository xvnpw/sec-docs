## Vulnerability List for OpenTelemetry-Go Project

**Vulnerability List:**

* **Vulnerability Name:** HTTP Header Injection via Environment Variables
* **Description:**
    The `stringToHeader` function in `/code/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig/envconfig.go` and `/code/exporters/otlp/otlptrace/otlptracehttp/internal/envconfig/envconfig.go` parses header key-value pairs from environment variables like `OTEL_EXPORTER_OTLP_HEADERS`. While the function validates header keys to contain only "token" characters as per RFC7230, it does not prevent header injection attacks. An attacker could potentially inject arbitrary HTTP headers by crafting a malicious header string in the environment variable.

    **Step-by-step trigger:**
    1. An application using OpenTelemetry OTLP exporter for gRPC or HTTP reads exporter configurations from environment variables.
    2. An attacker sets a malicious environment variable, for example `OTEL_EXPORTER_OTLP_HEADERS="X-Malicious-Header: injected-value,Valid-Header: valid-value"`.
    3. The `stringToHeader` function parses this environment variable.
    4. The function incorrectly splits the header string by comma and processes each part. It validates keys to be token chars, but it doesn't prevent injection of new headers via crafted keys or values.
    5. The OTLP exporter uses these parsed headers in subsequent HTTP or gRPC requests to the OTLP collector.
    6. The injected header `X-Malicious-Header: injected-value` is now included in the outgoing requests.

* **Impact:**
    The impact of this vulnerability is high. HTTP header injection can have various security implications. Depending on the collector and intermediary systems, an attacker might be able to:
    - Bypass security controls.
    - Modify or manipulate requests.
    - Potentially gain unauthorized access or control over the collector or downstream systems if they rely on HTTP headers for authentication or authorization.
    - Cause unexpected behavior in the collector or downstream applications.
    - In some scenarios, it might be possible to leverage header injection for cross-site scripting (XSS) or other web-based attacks if the collector or monitoring dashboards expose these headers.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - Header Key Validation: The `isValidHeaderKey` function in `envconfig.go` checks if the header key contains only token characters, preventing some invalid characters in header keys.
    - Error Logging: The `stringToHeader` function logs errors if header parsing fails, which can help in detecting potentially malicious header formats.

    Mitigation Location: `/code/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig/envconfig.go:141-151` and `/code/exporters/otlp/otlptrace/otlptracehttp/internal/envconfig/envconfig.go:141-151`

* **Missing Mitigations:**
    - Header Value Sanitization: The code does not sanitize or validate header values, allowing arbitrary values to be injected.
    - Prevention of Header Injection: The current validation is insufficient to prevent header injection. The code should be modified to strictly parse headers and disallow injection attempts. Consider using a more robust header parsing library or implementing stricter checks to ensure that only intended headers are processed.
    - Limit Header Keys: Restrict the allowed header keys to a predefined safe list. If any header key outside of this list is provided via environment variables, it should be rejected.
    - Input Sanitization and Validation: Implement more rigorous input validation and sanitization for environment variables that are used to configure HTTP headers.

* **Preconditions:**
    - The application must be using OpenTelemetry OTLP exporter for gRPC or HTTP.
    - The application must be configured to read exporter configurations from environment variables (which is the default behavior).
    - An attacker must be able to control the environment variables of the application. In containerized environments or shared hosting, this might be possible through various means like manipulating container configurations or exploiting other vulnerabilities to set environment variables.

* **Source Code Analysis:**

    ```go
    // code/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig/envconfig.go (and otlptracehttp version)

    func stringToHeader(value string) map[string]string {
        headersPairs := strings.Split(value, ",")
        headers := make(map[string]string)

        for _, header := range headersPairs {
            n, v, found := strings.Cut(header, "=")
            if !found {
                global.Error(errors.New("missing '="), "parse headers", "input", header)
                continue
            }

            trimmedName := strings.TrimSpace(n)

            // Validate the key.
            if !isValidHeaderKey(trimmedName) {
                global.Error(errors.New("invalid header key"), "parse headers", "key", trimmedName)
                continue
            }

            // Only decode the value.
            value, err := url.PathUnescape(v) // Value is unescaped, but not sanitized
            if err != nil {
                global.Error(err, "escape header value", "value", v)
                continue
            }
            trimmedValue := strings.TrimSpace(value)

            headers[trimmedName] = trimmedValue // Header map is populated without injection prevention
        }

        return headers
    }

    func isValidHeaderKey(key string) bool {
        if key == "" {
            return false
        }
        for _, c := range key {
            if !isTokenChar(c) { // Only token chars are validated for key
                return false
            }
        }
        return true
    }
    ```

    **Visualization:**

    ```mermaid
    graph LR
        A[Start stringToHeader] --> B[Split value by comma]
        B --> C{Iterate through header pairs}
        C --> D{Cut header pair by "="}
        D -- No "=" --> E[Log Error: missing "="]
        D -- Found "=" --> F[Trim whitespace from key]
        F --> G{isValidHeaderKey(trimmedName)?}
        G -- No --> H[Log Error: invalid header key]
        G -- Yes --> I[URL PathUnescape value]
        I --> J{Error during unescape?}
        J -- Yes --> K[Log Error: escape header value]
        J -- No --> L[Trim whitespace from value]
        L --> M[headers[trimmedName] = trimmedValue]
        M --> C
        C -- No more pairs --> N[Return headers]
    ```


    **Source Code Walkthrough:**
    1. The `stringToHeader` function takes a string `value` representing headers, expected to be comma-separated key-value pairs.
    2. It splits the `value` string by commas into `headerPairs`.
    3. It iterates through each `header` in `headerPairs`.
    4. For each `header`, it attempts to split it into a key-value pair using `strings.Cut(header, "=")`.
    5. If the split by "=" fails (no "=" found), it logs an error and continues to the next header.
    6. It trims whitespace from the extracted key (`trimmedName`).
    7. It validates the `trimmedName` using `isValidHeaderKey` to ensure it contains only token characters.
    8. If the key is invalid, it logs an error and continues.
    9. It URL-path-unescapes the value part. Note: While the value is unescaped, it's not sanitized for header injection vulnerabilities.
    10. If unescaping fails, it logs an error and continues.
    11. It trims whitespace from the unescaped value (`trimmedValue`).
    12. It adds the `trimmedName` and `trimmedValue` to the `headers` map. **Crucially, no check is performed here to prevent header injection. The code directly populates the header map.**
    13. After processing all header pairs, it returns the `headers` map.

* **Security Test Case:**

    **Test Case Title:** HTTP Header Injection via Environment Variables Test

    **Description:** This test case verifies that the `stringToHeader` function is vulnerable to HTTP header injection when parsing environment variables for OTLP exporter configuration. It checks if an attacker can inject arbitrary headers into outgoing HTTP requests by crafting a malicious header string in the environment variable.

    **Preconditions:**
    - Set up a test environment with an OTLP HTTP exporter configured to send traces to a mock collector.
    - The mock collector should be capable of capturing and inspecting HTTP headers of incoming requests.

    **Test Steps:**
    1. Set the environment variable `OTEL_EXPORTER_OTLP_HEADERS` to a malicious string containing a header injection payload, for example: `OTEL_EXPORTER_OTLP_HEADERS="Valid-Header: valid-value,X-Injected-Header: injected-value"`.
    2. Initialize the OTLP HTTP exporter, ensuring it reads configurations from environment variables.
    3. Create and export a simple trace span using the initialized exporter.
    4. Inspect the HTTP headers received by the mock collector for the exported trace data.
    5. Verify that the injected header `X-Injected-Header: injected-value` is present in the HTTP headers captured by the mock collector, along with the `Valid-Header`.

    **Expected Result:**
    - The test should pass if the mock collector receives the HTTP request containing the injected header `X-Injected-Header: injected-value`. This confirms that the `stringToHeader` function is vulnerable to header injection and allows arbitrary headers to be added to outgoing HTTP requests via environment variables.