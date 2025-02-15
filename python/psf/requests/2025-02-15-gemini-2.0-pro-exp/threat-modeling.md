# Threat Model Analysis for psf/requests

## Threat: [Man-in-the-Middle Attack via Disabled Certificate Verification](./threats/man-in-the-middle_attack_via_disabled_certificate_verification.md)

*   **Description:** An attacker positions themselves between the application and the server (e.g., on a compromised network).  The application explicitly disables SSL/TLS certificate verification in the `requests` call, allowing the attacker to present a fake certificate and intercept/modify the communication without detection.
*   **Impact:**  Complete compromise of communication confidentiality and integrity.  The attacker can steal credentials, inject malicious data, or impersonate the server, leading to data breaches, account takeovers, and other severe consequences.
*   **Affected Component:**  Any `requests` function that makes HTTPS requests (e.g., `requests.get()`, `requests.post()`, etc.) when used with `verify=False`.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Never disable certificate verification in production:**  Always use `verify=True` (the default).  This is the most crucial mitigation.
    *   **Use trusted CAs:** Ensure the `certifi` package (used by `requests`) is up-to-date, providing a reliable set of root certificates.
    *   **Careful testing with self-signed certs:** If using self-signed certificates during development *only*, use a dedicated configuration setting that is *absolutely never* enabled in production.  Ideally, set up a temporary, trusted CA for development purposes.

## Threat: [Denial of Service via Missing Timeouts](./threats/denial_of_service_via_missing_timeouts.md)

*   **Description:** An attacker crafts requests to a slow or unresponsive server, or the target server becomes unresponsive for legitimate reasons.  The application does *not* set timeouts on `requests` calls.  The application will wait indefinitely for a response, consuming resources (threads, memory) and eventually becoming unresponsive itself, leading to a denial-of-service.
*   **Impact:** Application unavailability, resource exhaustion (potentially affecting other applications or the entire system if resources are shared), and potential for complete system failure in extreme cases.
*   **Affected Component:**  `requests.get()`, `requests.post()`, `requests.put()`, `requests.delete()`, `requests.head()`, `requests.options()`, `requests.patch()`, and any `requests.Session` methods that make network requests, when used *without* the `timeout` parameter.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Always set timeouts:** Use the `timeout` parameter in *all* `requests` calls (e.g., `requests.get(url, timeout=5)`).  This is the primary mitigation.
    *   **Choose appropriate timeouts:** Base timeout values on the expected response time of the target service, considering network latency and potential delays.  Start with relatively short timeouts and adjust as needed.
    *   **Implement retries with backoff (with a maximum timeout):** Use a retry mechanism with exponential backoff to handle transient network issues, but *always* enforce a maximum overall timeout to prevent indefinite waiting.

## Threat: [Sending Sensitive Data to Incorrect Endpoint](./threats/sending_sensitive_data_to_incorrect_endpoint.md)

* **Description:** Due to a coding error (e.g., incorrect variable usage, typo in a hardcoded URL, flawed logic in URL construction), sensitive data (credentials, API keys, PII) intended for a secure, trusted endpoint is accidentally sent to an external, untrusted, or even malicious endpoint controlled by an attacker.
* **Impact:**  Exposure of sensitive data to unauthorized parties, leading to potential data breaches, account compromise, financial loss, and reputational damage. The attacker gains access to information they should not have.
* **Affected Component:** Any `requests` function used to send data (e.g., `requests.get()`, `requests.post()`, `requests.put()`, `requests.request()`, etc.), where the URL argument is constructed or obtained incorrectly. This is a direct misuse of the *destination* to which `requests` sends data.
* **Risk Severity:** High
* **Mitigation Strategies:**
    *   **Code Review:** Thoroughly review code that constructs or handles URLs, paying close attention to variable assignments, string formatting, and any logic that determines the target endpoint.
    *   **Input Validation:** If URLs are derived from user input or external sources, rigorously validate them to ensure they conform to expected patterns and point to trusted endpoints.  Use allow-lists rather than deny-lists.
    *   **Environment Variables:** Use environment variables to manage endpoint URLs, making it easier to distinguish between internal/external and development/production environments, and reducing the risk of hardcoding errors.
    *   **Testing:** Implement comprehensive tests, including unit tests and integration tests, to verify that requests are sent to the *correct* endpoints, especially when dealing with sensitive data.
    *   **Service Discovery:** Consider using a service discovery mechanism to dynamically resolve endpoint URLs, reducing the reliance on hardcoded values and minimizing the risk of errors.

## Threat: [Denial of Service via Large Response Handling](./threats/denial_of_service_via_large_response_handling.md)

*   **Description:** An attacker crafts a request that results in a very large response (e.g., a large file download or an unexpectedly large JSON payload). The application does not use streaming and attempts to load the entire response into memory at once.
*   **Impact:**  Memory exhaustion, application crashes, denial of service. The application becomes unresponsive or terminates unexpectedly.
*   **Affected Component:**  Any `requests` function that receives a response, when used *without* `stream=True` and without proper handling of large responses (chunking). This directly relates to how `requests` handles the *response body*.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use streaming:**  Set `stream=True` in `requests` calls when expecting potentially large responses. This is the primary mitigation.
    *   **Process in chunks:** Use `response.iter_content()` or `response.iter_lines()` to process the response body in manageable chunks, avoiding loading the entire response into memory at once.
    *   **Set size limits:** Implement a maximum response size limit and abort the request if the `Content-Length` header (if present and reliable) indicates that the response will exceed this limit.  Even with streaming, consider a timeout to prevent excessively long downloads.

