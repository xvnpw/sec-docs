- **Vulnerability Name:** Automatic Retry of Non‑Idempotent Requests Leading to Duplicate Operations
  **Description:**
  The library is designed to automatically retry HTTP requests on encountering errors (such as 500‑range responses) without differentiating whether the request is idempotent or not. In particular, non-idempotent methods like POST may be retried on transient server failures. An external attacker who can influence the response (for example, by causing a transient 500-error) may force the client to resend a non-idempotent request. This can result in duplicate execution of state-changing operations.
  **Impact:**
  Duplicate operations (such as duplicate financial transactions, resource creation, or other side-effects) may occur, leading to data inconsistency, financial loss, or other unintended effects on the application’s state.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The library implements a mechanism to “rewind” the request body using a user‑provided function (ReaderFunc) so that a failed request can be retried.
  - The default retry policy (DefaultRetryPolicy) is applied uniformly on error responses (e.g. 500’series), regardless of the HTTP method.
  **Missing Mitigations:**
  - There is no built-in safeguard or differentiation for non-idempotent methods. It does not check the HTTP method (e.g. POST, PATCH) before automatically retrying, nor does it offer an option to disable retries for non-idempotent requests.
  **Preconditions:**
  - The application must expose an endpoint wherein an outgoing request (using this library) is made with a non-idempotent HTTP method.
  - An attacker must be able to cause the backend (or intermediate service) to respond with errors that trigger a retry.
  **Source Code Analysis:**
  - In the `NewRequest`/`NewRequestWithContext` functions, the provided request (which may have a body) is wrapped for retry.
  - In the `Client.Do` method, a loop is used to repeatedly execute the request. On each cycle, the body is “rewound” by calling `req.body()` and the request is re-sent.
  - The retry decision is made in the call to `CheckRetry`, which by default invokes `DefaultRetryPolicy`. This function examines the response status (e.g. any 500-range code) and returns “retry” if the response is in error; it does not check whether the method is safe to retry.
  - **Visualization:**
    - **Client.Do Loop:**
      • Retrieve the request body via the ReaderFunc
      • Execute the request using the underlying HTTP client
      • Call `CheckRetry(context, resp, err)` (which uses `DefaultRetryPolicy`)
      • If “retry” is signaled (for instance on a 500 error), the same request (including non-idempotent POST) is retried
  **Security Test Case:**
  1. **Setup:**
     - Deploy an instance of the application that uses retryablehttp to make an outgoing POST request (assume this POST triggers a state–changing operation).
  2. **Triggering the Vulnerability:**
     - Use an external client (for example, via curl) to send a request that causes the application to issue a POST.
     - Ensure that the backend (or a controlled test server) is configured to return a transient 500 response—even if only on the initial attempt.
  3. **Observation:**
     - Monitor the backend or database to determine whether the state–changing operation (e.g. a transaction or resource creation) is executed more than once.
  4. **Conclusion:**
     - If the operation occurs multiple times, the vulnerability is successfully demonstrated.

- **Vulnerability Name:** Sensitive Data Exposure via Inadequate URL Redaction in Logs
  **Description:**
  When logging request details, the library calls the helper function `redactURL` which is intended to remove sensitive user authentication data from the URL. Although this function correctly redacts credentials embedded in the URL’s user info, it does nothing to sanitize other potentially sensitive components such as query parameters. An attacker who is able to supply a URL containing sensitive information (for example, an API key or token passed as a query parameter) can cause that sensitive information to be logged in clear text when the library logs each request.
  **Impact:**
  If log files become accessible—either through misconfiguration or a breach—sensitive data (like API keys or tokens) may be exposed to attackers. This leakage can facilitate further exploitation, unauthorized access to services, or data breaches.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The `redactURL` function redacts basic authentication credentials by replacing the password with the placeholder `"xxxxx"`.
  **Missing Mitigations:**
  - There is no sanitization or redaction of URL query parameters or other parts of the URL that may contain sensitive tokens or keys.
  - A configurable mechanism to specify which parameters should be redacted is not provided.
  **Preconditions:**
  - The application must accept externally influenced URLs that include sensitive information (e.g. through query parameters).
  - The logs generated by the application must be accessible to an attacker (due to misconfiguration, insecure storage, etc.).
  **Source Code Analysis:**
  - The `redactURL` function is defined as follows:
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
  - This code only examines and redacts the URL’s user info. All other components (including query parameters) are returned unchanged.
  - In the `Client.Do` method, logging statements such as:
    ```go
    v.Debug("performing request", "method", req.Method, "url", redactURL(req.URL))
    ```
    cause the full URL (with unsanitized query parameters) to be logged.
  **Security Test Case:**
  1. **Setup:**
     - Deploy an instance of the application that uses retryablehttp to perform outbound HTTP requests.
  2. **Triggering the Vulnerability:**
     - Craft a URL that includes a sensitive query parameter. For example:
       `https://example.com/data?apiKey=super_secret`
     - Cause the application to use this URL in a request (for example, via an endpoint that accepts a URL as input).
  3. **Execution:**
     - Send a request to the application that triggers the use of the above URL.
  4. **Observation:**
     - Verify that the logged URL still contains the sensitive query parameter (`apiKey=super_secret`) in clear text.
  5. **Conclusion:**
     - The presence of unsanitized sensitive data in the logs confirms the vulnerability.