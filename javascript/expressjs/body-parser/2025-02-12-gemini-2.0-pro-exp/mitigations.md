# Mitigation Strategies Analysis for expressjs/body-parser

## Mitigation Strategy: [Limit Payload Size (via `body-parser` options)](./mitigation_strategies/limit_payload_size__via__body-parser__options_.md)

**Description:**
1.  **Identify `body-parser` usage:** Locate all instances where `body-parser` middleware (e.g., `bodyParser.json()`, `bodyParser.urlencoded()`, `bodyParser.raw()`, `bodyParser.text()`) is used in your application.
2.  **Determine appropriate limits:** For *each* `body-parser` instance, determine the maximum expected size of the request body based on the route's purpose and the type of data it handles.
3.  **Set `limit` option:**  Within the options object passed to each `body-parser` middleware, set the `limit` property to the determined maximum size. Use units like 'kb', 'mb', or bytes.  Example:
    ```javascript
    app.use(bodyParser.json({ limit: '100kb' }));
    app.use(bodyParser.urlencoded({ limit: '50kb', extended: true }));
    app.use(bodyParser.raw({ limit: '1mb' }));
    ```
4.  **Test:** Send requests exceeding the limits to confirm that `body-parser` correctly rejects them with a 413 (Payload Too Large) error.

**List of Threats Mitigated:**
*   **Denial of Service (DoS) due to large payloads:** (Severity: High) - `body-parser` will reject oversized requests before they consume excessive server resources.
*   **Resource Exhaustion:** (Severity: Medium) - Limits help prevent excessive memory and CPU usage.

**Impact:**
*   **DoS:** Risk significantly reduced.  `body-parser` enforces the size limits.
*   **Resource Exhaustion:** Risk reduced.

**Currently Implemented:**
*   `/api/user`: `bodyParser.json({ limit: '100kb' })` - Implemented.
*   `/api/login`: `bodyParser.urlencoded({ limit: '50kb', extended: true })` - Implemented.

**Missing Implementation:**
*   `/api/upload`: No `limit` option set for `bodyParser.raw()`.
*   No global `body-parser` limits (as a fallback).

## Mitigation Strategy: [Strict Content-Type Handling (via `body-parser` options)](./mitigation_strategies/strict_content-type_handling__via__body-parser__options_.md)

**Description:**
1.  **Identify expected `Content-Type`:** For each route using `body-parser`, determine the *exact* expected `Content-Type` header (e.g., `application/json`).
2.  **Set `type` option:**  Within the options object for each `body-parser` middleware, set the `type` property to the expected `Content-Type`.  This restricts parsing to only requests with that specific header.
    ```javascript
    app.use(bodyParser.json({ type: 'application/json' }));
    app.use(bodyParser.urlencoded({ extended: true, type: 'application/x-www-form-urlencoded' }));
    ```
3.  **Test:** Send requests with incorrect or missing `Content-Type` headers to verify that `body-parser` *does not* parse them (you should handle the resulting error, ideally with a 415 response, but that's *outside* of `body-parser` itself).

**List of Threats Mitigated:**
*   **Content-Type Mismatch Attacks:** (Severity: Medium) - `body-parser` will only parse requests with the specified `Content-Type`.
*   **Bypassing Security Filters (that rely on Content-Type):** (Severity: Medium)

**Impact:**
*   **Content-Type Mismatch:** Risk significantly reduced.
*   **Bypassing Filters:** Risk reduced.

**Currently Implemented:**
*   `/api/data`: `bodyParser.json({ type: 'application/json' })` - Implemented.

**Missing Implementation:**
*   `/api/login`: No `type` option set for `bodyParser.urlencoded()`.
*   `/api/upload`: No `type` option set for `bodyParser.raw()`.

## Mitigation Strategy: [Choose `extended` Option Wisely (for `urlencoded` parser)](./mitigation_strategies/choose__extended__option_wisely__for__urlencoded__parser_.md)

**Description:**
1.  **Assess necessity of `extended: true`:** Determine if your application *needs* to parse complex, nested objects and arrays from URL-encoded data.
2.  **Prefer `extended: false`:** If nested objects are *not* required, use `bodyParser.urlencoded({ extended: false })`. This uses the built-in `querystring` module, which is generally safer.
3.  **If `extended: true` is required:** Be aware of the increased attack surface (primarily prototype pollution) and implement *additional* security measures (schema validation, input sanitization – *but these are outside the scope of direct `body-parser` configuration*).
4. **Test:** If using `extended:true`, ensure that your *other* security measures (validation, etc.) are working correctly.

**List of Threats Mitigated:**
*   **Prototype Pollution (when `extended: true` is used):** (Severity: High) - While `body-parser` itself doesn't *directly* mitigate this, choosing `extended: false` when possible *avoids* the increased risk associated with the `qs` library.  The actual mitigation is done through *other* layers (validation, sanitization).
*   **Unexpected Data Structures (when `extended: true` is used):** (Severity: Medium) - Similar to prototype pollution, choosing `extended: false` reduces the complexity and potential for unexpected input.

**Impact:**
*   **Prototype Pollution:** Risk *avoided* if `extended: false` is sufficient.  If `extended: true` is used, the risk is *not* mitigated by `body-parser` itself.
*   **Unexpected Data Structures:** Risk *reduced* by using `extended: false` when possible.

**Currently Implemented:**
*   `/api/login`: Uses `bodyParser.urlencoded({ extended: true })`.  This *might* be unnecessary.

**Missing Implementation:**
*   Review the `/api/login` route to determine if `extended: true` is truly required.  If not, change it to `extended: false`.

## Mitigation Strategy: [Strategic Parser Selection](./mitigation_strategies/strategic_parser_selection.md)

**Description:**
1. **Prioritize structured parsers:**  Favor `bodyParser.json()` and `bodyParser.urlencoded()` over `bodyParser.raw()` and `bodyParser.text()` whenever possible. The structured parsers offer more built-in security features and constraints.
2. **Avoid `raw` and `text` if possible:** Only use `bodyParser.raw()` or `bodyParser.text()` when absolutely necessary, and when you have a *very* strong understanding of the security implications and have implemented robust custom handling.
3. **Justify `raw` and `text` usage:** If using `raw` or `text`, document *why* the structured parsers are insufficient, and detail the specific security measures taken to mitigate the increased risk.

**List of Threats Mitigated:**
*   **Code Injection (if `raw` or `text` are misused):** (Severity: High) - By avoiding `raw` and `text`, you reduce the risk of mishandling the raw request body and introducing vulnerabilities.
*   **Data Corruption (if `raw` or `text` are parsed incorrectly):** (Severity: Medium)
*   **Increased Attack Surface (generally):** (Severity: Medium) - Structured parsers provide a more constrained and therefore safer environment.

**Impact:**
*   **Code Injection/Data Corruption:** Risk significantly reduced by preferring structured parsers.
*   **Increased Attack Surface:** Risk reduced.

**Currently Implemented:**
*   Generally good use of `json` and `urlencoded` where appropriate.

**Missing Implementation:**
*   `/api/upload` uses `bodyParser.raw()`.  This needs *very* careful review to determine if it's truly necessary and, if so, to ensure extremely robust security measures are in place (though those measures are *outside* of `body-parser` itself).

