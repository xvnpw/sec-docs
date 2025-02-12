# Attack Surface Analysis for expressjs/body-parser

## Attack Surface: [Large Payload Denial of Service (DoS)](./attack_surfaces/large_payload_denial_of_service__dos_.md)

*   **Description:** An attacker sends an excessively large request body, overwhelming server resources.
*   **`body-parser` Contribution:** `body-parser` is directly responsible for reading and parsing the request body. Without size limits, it will attempt to process arbitrarily large inputs, allocating memory and consuming CPU.
*   **Example:** An attacker sends a 10GB JSON payload to an endpoint expecting a small object.
*   **Impact:** Server becomes unresponsive, denying service to legitimate users. Memory exhaustion, CPU overload.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Set `limit` Option:**  This is *essential*. Configure the `limit` option for *each* parser used (e.g., `bodyParser.json({ limit: '100kb' })`). Choose limits appropriate for your application's expected input sizes.  This is the *primary* mitigation directly related to `body-parser`.
    *   **Reverse Proxy Limits:** (Indirect, but important) Configure request size limits in a reverse proxy (Nginx, HAProxy) or WAF *before* the request reaches the Node.js application.
    *   **Streaming (for large files):** (Indirect) For legitimate large file uploads, use streaming libraries (e.g., `busboy`, `multer`) *instead* of `body-parser` for those specific routes.

## Attack Surface: [Content-Type Spoofing with Large Payloads](./attack_surfaces/content-type_spoofing_with_large_payloads.md)

*   **Description:** An attacker sends a large payload with a misleading `Content-Type` header to bypass initial checks and still consume resources, even if parsing ultimately fails.
*   **`body-parser` Contribution:** `body-parser` uses the `Content-Type` header to determine which parser to use. A spoofed header can cause the wrong parser to be invoked, leading to resource consumption *before* an error is thrown, or potentially triggering unexpected parsing behavior.
*   **Example:** An attacker sends a 500MB text file, but sets the `Content-Type` to `application/json`.  `body-parser` might attempt to parse it as JSON, consuming resources before realizing it's invalid.
*   **Impact:** Resource exhaustion (memory, CPU), potentially leading to DoS.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict `type` Option:** This is *essential*. Use the `type` option to restrict accepted content types for each parser (e.g., `bodyParser.json({ type: 'application/json' })`). This prevents `body-parser` from attempting to parse unexpected content types. This is the *primary* mitigation directly related to `body-parser`.
    *   **Content-Type Validation Middleware:** (Indirect, but important) Implement custom middleware *before* `body-parser` to validate the `Content-Type` header against a strict allowlist. Reject requests with unexpected or missing `Content-Type` headers.

