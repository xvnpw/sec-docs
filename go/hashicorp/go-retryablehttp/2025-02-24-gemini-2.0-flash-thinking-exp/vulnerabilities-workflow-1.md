Here is the combined list of vulnerabilities in Markdown format:

## Combined Vulnerability List

### Sensitive Data Exposure via Inadequate URL Redaction in Logs

**Vulnerability Name:** Sensitive Data Exposure via Inadequate URL Redaction in Logs

**Description:**
When logging request details, the library uses the `redactURL` function which is intended to remove sensitive user authentication data from the URL. However, this redaction is inadequate in several scenarios, leading to potential exposure of sensitive information in logs.

- **Vulnerability Case 1: Basic Authentication Credentials in URLs:** While `redactURL` function aims to mask passwords embedded in the user info part of URLs, it's possible that basic authentication credentials embedded directly within the URL (e.g., `http://user:password@example.com/api/resource`) are still logged before redaction takes place, or in logging contexts where `redactURL` is not applied.
  - Step 1: An attacker gains access to application logs where `go-retryablehttp` library logs requests.
  - Step 2: The application makes HTTP requests using `go-retryablehttp` with basic authentication credentials embedded in the URL (e.g., `http://user:password@example.com/api/resource`).
  - Step 3: The `go-retryablehttp` library logs the request URL, potentially including the basic authentication credentials before the `redactURL` function can fully sanitize it, or in other logging contexts where redaction is not applied.
  - Step 4: The logs are stored or transmitted in a way that is accessible to the attacker.
  - Step 5: The attacker reads the logs and extracts the exposed basic authentication credentials.

- **Vulnerability Case 2: Sensitive Data in Query Parameters:** The `redactURL` function only redacts credentials in the user info part of the URL and does not sanitize other potentially sensitive components, such as query parameters. An attacker who can supply a URL containing sensitive information (for example, an API key or token passed as a query parameter) can cause that sensitive information to be logged in clear text when the library logs each request.
  - Step 1: An attacker can influence the URL used by the application in a `go-retryablehttp` request.
  - Step 2: The attacker provides a URL with sensitive information in the query parameters (e.g., `https://example.com/data?apiKey=super_secret`).
  - Step 3: The application uses this URL in a request, and the library logs the full URL as part of request details.
  - Step 4: The logs are stored or transmitted in a way that is accessible to the attacker.
  - Step 5: The attacker reads the logs and extracts the exposed sensitive information from the query parameters.

**Impact:**
Exposure of sensitive data (basic authentication credentials, API keys, tokens, etc.) if log files become accessible—either through misconfiguration or a breach. This leakage can facilitate further exploitation, unauthorized access to protected resources, or data breaches.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
The project includes a `redactURL` function in `client.go` that aims to mask passwords within URLs before logging. This function redacts basic authentication credentials in the user info part of the URL by replacing the password with the placeholder `"xxxxx"`. Changelog in `CHANGELOG.md` mentions "client: avoid potentially leaking URL-embedded basic authentication credentials in logs (#158)" in version 0.7.7, indicating a fix has been implemented for basic authentication in user info.

**Missing mitigations:**
While a mitigation has been implemented for basic authentication in user info, there are still missing mitigations:
- There is no sanitization or redaction of URL query parameters or other parts of the URL that may contain sensitive tokens or keys.
- A thorough review of all logging points is recommended to ensure no credentials are leaked in any circumstances, especially before redaction is applied.
- More robust credential scrubbing mechanisms could be considered beyond basic redaction.
- A configurable mechanism to specify which URL parameters should be redacted is not provided.
- Guidance to users to avoid embedding credentials in URLs and instead use header-based authentication or secret management practices would also be beneficial.

**Preconditions:**
- Application using `go-retryablehttp` library logs requests.
- Application either uses basic authentication by embedding credentials in the URL or handles URLs that may contain sensitive information in query parameters.
- An attacker gains access to the application logs (due to misconfiguration, insecure storage, etc.).

**Source code analysis:**
- In `client.go`, the `redactURL` function is used before logging the URL in `Client.Do` at debug and error level.
- `redactURL` function in `client.go`:
  ```go
  func redactURL(u *url.URL) string {
      if u == nil {
          return ""
      }
      ru := *u
      if _, has := ru.User.Password(); has {
          ru.User = url.UserPassword(ru.User.Username(), "xxxxx")
      }
      return ru.String()
  }
  ```
- The `redactURL` function specifically targets only the `url.User` part to redact the password. It does not sanitize or redact any other part of the URL, including query parameters.
- In the `Client.Do` method, logging statements such as:
  ```go
  v.Debug("performing request", "method", req.Method, "url", redactURL(req.URL))
  ```
  cause the `redactURL` function to be called, but only user info is processed, and the rest of the URL, including query parameters, are logged as is.

**Security test case:**
- Step 1: Set up a mock HTTP server (e.g., using `net/http/httptest`) that can be configured to require basic authentication or simply echo back the request URL.
- Step 2: Create a `retryablehttp.Client` instance in a test Go program.
- Step 3: Configure the `retryablehttp.Client` to use the standard `log.Logger` to capture logs to standard error or a buffer for inspection.
- Step 4: **Test Case 1: Basic Authentication in URL:** Construct a `retryablehttp.Request` with basic authentication credentials embedded in the URL (e.g., `http://user:password@localhost:<port>/api/resource`).
- Step 5: **Test Case 2: Sensitive Query Parameter:** Construct a `retryablehttp.Request` with a sensitive query parameter in the URL (e.g., `http://localhost:<port>/api/data?apiKey=super_secret`).
- Step 6: Execute both requests using `client.Do(req)`.
- Step 7: Inspect the logs captured by `log.Logger`.
- Step 8: **For Test Case 1:** Verify if the raw basic authentication credentials (like `user:password`) are present in the logs before any redaction is applied, or if redaction is effective only for user info and not in all logging contexts.
- Step 9: **For Test Case 2:** Verify if the sensitive query parameter (like `apiKey=super_secret`) is present in the logs in clear text.
- Step 10: If credentials or sensitive query parameters are found in the logs without proper redaction in all relevant log outputs, the vulnerability is present.

### Automatic Retry of Non‑Idempotent Requests Leading to Duplicate Operations

**Vulnerability Name:** Automatic Retry of Non‑Idempotent Requests Leading to Duplicate Operations

**Description:**
The library is designed to automatically retry HTTP requests on encountering errors (such as 500‑range responses) without differentiating whether the request is idempotent or not. In particular, non-idempotent methods like POST, PATCH, etc., may be retried on transient server failures. An external attacker who can influence the response (for example, by causing a transient 500-error) may force the client to resend a non-idempotent request. This can result in duplicate execution of state-changing operations.

**Impact:**
Duplicate operations (such as duplicate financial transactions, resource creation, sending duplicate emails, or other side-effects) may occur, leading to data inconsistency, financial loss, unintended notifications, or other unintended effects on the application’s state.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The library implements a mechanism to “rewind” the request body using a user‑provided function (`ReaderFunc`) so that a failed request can be retried. This is intended to allow retries to function correctly when a request body is consumed.
- The default retry policy (`DefaultRetryPolicy`) is applied uniformly on error responses (e.g., 500’series), regardless of the HTTP method.

**Missing Mitigations:**
- There is no built-in safeguard or differentiation for non-idempotent methods. It does not check the HTTP method (e.g., POST, PATCH, PUT, DELETE) before automatically retrying.
- The library does not offer an option to disable retries specifically for non-idempotent requests, or to configure different retry policies based on the HTTP method.
- No guidance or recommendations are provided to users on the risks of retrying non-idempotent requests and how to mitigate them at the application level.

**Preconditions:**
- The application must expose an endpoint wherein an outgoing request (using this library) is made with a non-idempotent HTTP method (e.g., POST, PATCH, PUT, DELETE).
- The non-idempotent request must perform a state-changing operation on the backend.
- An attacker must be able to cause the backend (or intermediate service) to respond with errors (e.g., 500-range status codes) that trigger the default retry policy. Transient errors are sufficient to trigger this vulnerability.

**Source Code Analysis:**
- In the `NewRequest`/`NewRequestWithContext` functions, the provided request (which may have a body) is wrapped for retry, including the body rewinding mechanism.
- In the `Client.Do` method, a loop is used to repeatedly execute the request. On each cycle, the body is “rewound” by calling `req.body()` and the request is re-sent if a retry is deemed necessary.
- The retry decision is made in the call to `CheckRetry`, which by default invokes `DefaultRetryPolicy`.
- The `DefaultRetryPolicy` function examines the response status (e.g., any 500-range code or connection errors) and returns “retry” if the response indicates an error that is considered retryable.  Critically, `DefaultRetryPolicy` does not check or consider the HTTP method of the request when making the retry decision.

**Visualization:**
```mermaid
graph LR
    A[Client Application] --> B{retryablehttp.Client.Do};
    B --> C{Request Execution Loop};
    C --> D{Underlying HTTP Client};
    D --> E[Server (Attacker Controlled)];
    E -- 500 Error --> D;
    D --> F{CheckRetry (DefaultRetryPolicy)};
    F -- Retry Signal --> C;
    C -- Re-execute Request --> D;
    D --> E;
    E -- 200 OK (or other success) --> D;
    D --> G{Process Response};
    G --> B;
    B --> A;
    style E fill:#f9f,stroke:#333,stroke-width:2px
    style F fill:#ccf,stroke:#333,stroke-width:2px
```
**Explanation:**
1. The Client Application initiates a request via `retryablehttp.Client.Do`.
2. Inside `Client.Do`, a loop begins to handle retries.
3. The request is executed by the underlying HTTP client towards the Server.
4. The Attacker Controlled Server is designed to return a 500 error (or other retryable error) initially.
5. The underlying HTTP client receives the 500 error.
6. The `CheckRetry` function (using `DefaultRetryPolicy`) is called, which, based on the 500 error, signals that a retry is needed. It does not consider the HTTP method.
7. The loop in `Client.Do` causes the same request (including a non-idempotent POST) to be re-executed.
8. If the server then returns a success (200 OK) on the retry attempt, or if the retry policy eventually allows the request to proceed despite errors, the application processes the potentially duplicated operation.

**Security Test Case:**
1. **Setup:** Deploy an instance of the application that uses `retryablehttp` to make an outgoing POST request to a backend service. Assume this POST request triggers a state–changing operation, such as creating a resource in a database or initiating a transaction.
2. **Backend Configuration:** Configure the backend service (or a controlled test server acting as the backend) to return a 500 Internal Server Error response on the *first* attempt for a specific endpoint, and then succeed (return 200 OK) on subsequent attempts for the same request (or simply succeed after the first attempt if transient error simulation is complex).
3. **Triggering the Vulnerability:** Use an external client (e.g., `curl`) to send a request to the application endpoint that triggers the outgoing POST request made with `retryablehttp`.
4. **Observation:** Monitor the backend database, service logs, or any observable state change to determine whether the state–changing operation triggered by the POST request is executed more than once. You might need to add logging to the backend to track the number of times the operation is invoked for the same request identifier (if applicable).
5. **Conclusion:** If the state-changing operation is executed multiple times (more than intended by a single initial request), the vulnerability is successfully demonstrated. This indicates that the automatic retry mechanism for non-idempotent POST requests leads to duplicate operations.

### Server-Side Request Forgery (SSRF) in Redirect Handling

**Vulnerability Name:** Server-Side Request Forgery (SSRF) in Redirect Handling

**Description:**
The `go-retryablehttp` library, when handling HTTP redirects, might not sufficiently validate the target URL of the redirect. This can be exploited by an attacker to perform a Server-Side Request Forgery (SSRF) attack.

Step-by-step trigger:
1.  An attacker crafts a malicious URL, which, when requested, will result in an HTTP redirect to an internal resource or an unintended external resource. For example, the malicious URL could initially point to an attacker-controlled server.
2.  The application using `go-retryablehttp` attempts to make an HTTP request to this malicious URL.
3.  The attacker-controlled server responds with an HTTP redirect (e.g., 302 Found) to a target URL. This target URL could be an internal service within the application's infrastructure (e.g., `http://localhost:8080/admin`) or an unintended external resource.
4.  If `go-retryablehttp`'s redirect policy does not properly validate the target URL, it will follow the redirect and make a request to the attacker-specified target URL on behalf of the server.
5.  The response from the target URL is then potentially processed by the application, potentially leading to information disclosure or further exploitation depending on the nature of the internal or unintended external resource.

**Impact:**
Successful exploitation of this SSRF vulnerability can have severe impacts:
*   **Access to Internal Resources:** An attacker can gain unauthorized access to internal services and resources that are not intended to be publicly accessible.
*   **Information Disclosure:** By accessing internal resources, an attacker can potentially read sensitive data, configuration files, or application secrets.
*   **Internal Port Scanning:** An attacker can use the vulnerable application as a proxy to scan internal networks and identify open ports and services.
*   **Denial of Service (Indirect):** In some cases, SSRF can be used to target internal services in a way that causes them to become overloaded, leading to a denial of service.
*   **Credential Exposure:** If internal services require authentication, an attacker might be able to capture or reuse credentials if the application inadvertently exposes them during the SSRF attack.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
There are no specific mitigations implemented in the `go-retryablehttp` library to prevent SSRF in redirect handling in the current version. The library relies on the default `http.Client` behavior for redirect handling, which might not include sufficient URL validation for security purposes.

**Missing mitigations:**
The following mitigations are missing to prevent SSRF vulnerabilities in redirect handling:
*   **Strict URL Validation:** Implement strict validation of redirect URLs before following them, including allowlisting, scheme validation and preventing redirects to private IP ranges.
*   **Customizable Redirect Policy:** Provide users of the library with the ability to customize the redirect policy, allowing them to implement their own validation logic or to completely disable automatic redirects.
*   **Logging and Monitoring:** Implement logging of redirect events to aid in detecting and responding to potential SSRF attacks.

**Preconditions:**
*   A publicly accessible application is using the `go-retryablehttp` library to make HTTP requests.
*   The application allows user-controlled input to influence the initial URL being requested by the `retryablehttp.Client`.
*   The application does not implement its own robust SSRF protection mechanisms when using `go-retryablehttp`.

**Source code analysis:**
The `go-retryablehttp` library uses the standard `net/http` package's `Client` for making HTTP requests and inherits its default redirect policy. By default, `net/http.Client` follows redirects and the default `CheckRedirect` function does not perform any validation on the redirect URL itself beyond limiting the number of redirects. This means that if `go-retryablehttp` does not override this behavior, it is vulnerable to SSRF through redirects.

**Visualization:**

```mermaid
graph LR
    A[Attacker] --> B(Application using go-retryablehttp);
    B --> C{go-retryablehttp Client};
    C --> D[Attacker Server];
    D -- 302 Redirect to internal/malicious URL --> C;
    C --> E{http.Client Redirect Logic};
    E -- Follow Redirect (No Validation) --> F[Internal Service / Malicious Target];
    F --> C;
    C --> B;
    B --> A;
```

**Security test case:**

**Pre-requisites:**
1.  Set up a publicly accessible instance of an application that uses the `go-retryablehttp` library to fetch URLs based on user input (e.g., via a URL parameter).
2.  Set up an attacker-controlled web server on a public IP address.
3.  Assume there is an internal service accessible from the application server which is not publicly accessible.

**Steps:**
1.  **Craft a malicious URL:** Configure the attacker's web server to respond to any request with a 302 redirect to the internal service URL.
2.  **Send a request to the vulnerable application:** Send a request to the application's endpoint, providing the attacker's server URL as the target URL.
3.  **Observe the response:** Check if the application returns the content from the internal service, which would indicate successful SSRF.
4.  **Analyze logs (if available):** Check the application's logs or network traffic to confirm that a request was indeed made to the internal service from the application server.

**Expected Result:**
Successful retrieval of content from the internal service or evidence of a request being made to the internal service from the application server, confirming the SSRF vulnerability.