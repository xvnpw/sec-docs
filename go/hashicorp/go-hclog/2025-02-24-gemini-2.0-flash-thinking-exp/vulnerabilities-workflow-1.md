## Combined Vulnerability List for go-hclog

This document combines identified vulnerabilities in the `go-hclog` library, removing duplicates and presenting them in a structured format.

### Excessive Information Disclosure via Caller Location Logging

- **Description:**
    When the logger is configured with the option to include caller location information (by setting the `IncludeLocation` field in `LoggerOptions`), every log message is automatically appended with internal file paths and line numbers. An external attacker—for example, by sending unexpected inputs that trigger error logging—could cause these detailed log messages to be generated. If the logs (or a log viewer interface) are publicly accessible, the attacker can retrieve internal system details such as source file names and exact code line numbers. This information disclosure can help the attacker plan further targeted attacks.

- **Impact:**
    - Leakage of sensitive internal information including file paths and source code line numbers
    - Facilitation of targeted exploits by revealing system layout and code structure

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The logger already provides an option to include or omit caller location information (the `IncludeLocation` option). In development this is enabled for debugging purposes.

- **Missing Mitigations:**
    - No automatic enforcement is provided to disable caller location logging in production environments
    - No built‐in access control or output filtering is applied to protect log files from public access

- **Preconditions:**
    - The application is using go‑hclog with `IncludeLocation` set to true
    - Log output (or its viewer) is accessible by external attackers (for example, via an insecurely exposed log file or web-based log viewer)

- **Source Code Analysis:**
    - In the file [`intlogger.go`](./code/intlogger.go) within the `logPlain` function the following code block is executed when `l.callerOffset > 0`:
        - It calls `runtime.Caller(l.callerOffset)` to retrieve the file path and line number.
        - It then calls `trimCallerPath(file)` and writes the trimmed file name and line number directly into the log output.
        - The caller offset is set when `LoggerOptions.IncludeLocation` is true.

- **Security Test Case:**
    1. Configure a test instance to use go‑hclog with `IncludeLocation: true` (for example, via a test configuration file or environment variable).
    2. Trigger an error (or any log message) by submitting an input that the application cannot properly process.
    3. Retrieve the log output from the publicly accessible log file or log viewer.
    4. Verify that the log entries contain internal file names and line numbers (e.g. “`<filename>:<line>:`”) that expose sensitive internal information.
    5. As a follow‑up, verify that disabling `IncludeLocation` (or limiting log file access) prevents the leakage.

### Potential Cross‑Site Scripting (XSS) via Unescaped JSON Log Output

- **Description:**
    The logger supports a JSON output mode that is enabled when the `JSONFormat` option is true. By default, the JSON encoder escapes HTML characters. However, when a developer explicitly sets `JSONEscapeDisabled` to true, the line
    ```go
    encoder.SetEscapeHTML(l.jsonEscapeEnabled)
    ```
    in the `logJSON` function causes the encoder not to escape HTML characters. An external attacker who can inject malicious HTML/JavaScript code into untrusted log fields (for example, by manipulating HTTP headers or other user‑supplied data that is subsequently logged) may thereby cause unsanitized data to be recorded. If these JSON logs are later displayed in a web‑based log viewer that does not perform additional output encoding or sanitization, the malicious payload can be rendered and executed in the context of an administrator’s browser.

- **Impact:**
    - Execution of arbitrary JavaScript code in the context of a log-viewing interface
    - Compromise of administrative credentials or sensitive data accessed through the web interface

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - By default, `JSONEscapeDisabled` is false so that HTML characters are escaped in JSON output.
    - The library uses Go’s standard JSON encoding when formatting logs in JSON mode.

- **Missing Mitigations:**
    - The library does not enforce a safe default for logging in JSON mode if a developer enables `JSONEscapeDisabled`
    - There is no runtime check or warning to prevent unsanitized output when JSON escaping is disabled

- **Preconditions:**
    - The application is configured to output logs in JSON format with `JSONEscapeDisabled` explicitly set to true
    - A web‑based log viewer (or another publicly accessible mechanism) renders the JSON logs directly without additional sanitization
    - An attacker can control or inject log data via application inputs

- **Source Code Analysis:**
    - In [`intlogger.go`](./code/intlogger.go), the `logJSON` function creates an encoder with:
        ```go
        encoder := json.NewEncoder(l.writer)
        encoder.SetEscapeHTML(l.jsonEscapeEnabled)
        ```
        where `l.jsonEscapeEnabled` is the inverse of the user‑controlled option `JSONEscapeDisabled`.
    - When `JSONEscapeDisabled` is true the encoder does not escape HTML characters in logged data—allowing malicious payloads (e.g. `<script>alert('XSS');</script>`) to appear in the log output verbatim.

- **Security Test Case:**
    1. Create a test configuration that sets `JSONFormat: true` and `JSONEscapeDisabled: true` in `LoggerOptions`.
    2. Log a message (or use a logging function) that includes an untrusted field value containing a malicious payload such as:
        ```
        <script>alert('XSS');</script>
        ```
    3. Retrieve the JSON log output and verify that the malicious payload appears without escaping (i.e. the characters `<`, `>`, and `&` are present as entered).
    4. Open the JSON log output in a web‑based log viewer (or simulate such a viewer) that renders the log output as HTML.
    5. Verify that the script is executed in the browser (for example, confirming that an alert box appears).
    6. This demonstrates that disabling HTML escaping in JSON log output can lead to an XSS vulnerability if the logs are viewed in a web context.