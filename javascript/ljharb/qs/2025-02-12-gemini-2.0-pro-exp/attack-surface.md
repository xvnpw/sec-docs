# Attack Surface Analysis for ljharb/qs

## Attack Surface: [Excessive Nesting (Denial of Service)](./attack_surfaces/excessive_nesting__denial_of_service_.md)

*   **Description:** An attacker crafts a deeply nested query string to exhaust server resources.
*   **How `qs` Contributes:** `qs` allows nested objects/arrays, and the parsing process is recursive. The `depth` option controls this, but a high or missing value is dangerous. This is a *direct* feature of `qs`.
*   **Example:** `?a[b][c][d][e][f][g][h][i][j][k][l][m][n][o][p]=value` (repeated to extreme depth)
*   **Impact:** Server becomes unresponsive (DoS), potentially affecting all users.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Set the `depth` option in `qs.parse` to a low, application-specific value (e.g., 2 or 3).  *Never* allow unlimited depth or rely on the default without careful consideration.
    *   **Developer:** Implement resource monitoring (CPU, memory) and rate limiting to detect and prevent abuse.

## Attack Surface: [Excessive Array Elements (Denial of Service)](./attack_surfaces/excessive_array_elements__denial_of_service_.md)

*   **Description:** An attacker sends a query string with a massive number of array elements, overwhelming server memory.
*   **How `qs` Contributes:** `qs` parses arrays in query strings. The `arrayLimit` option controls the maximum number of elements, but a high or missing value is dangerous. This is a *direct* feature of `qs`.
*   **Example:** `?a[]=1&a[]=2&a[]=3...` (repeated thousands of times)
*   **Impact:** Server runs out of memory (DoS), potentially crashing the application.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Set the `arrayLimit` option in `qs.parse` to a low, justifiable value based on the application's needs.
    *   **Developer:** Implement input validation *before* `qs.parse` to limit the overall size of the query string.
    *   **Developer:** Monitor memory usage and implement rate limiting.

## Attack Surface: [Enabling Prototype Pollution (via `allowPrototypes`)](./attack_surfaces/enabling_prototype_pollution__via__allowprototypes__.md)

*   **Description:** An attacker injects properties into the object prototype, potentially affecting other parts of the application.
*   **How `qs` Contributes:** The `allowPrototypes` option in `qs.parse`, if set to `true`, *directly* allows setting properties on the object's prototype.  While the *exploitation* happens in the application, the *enabling mechanism* is a direct feature of `qs`.
*   **Example:** `?__proto__[polluted]=true` (if `allowPrototypes` is `true`)
*   **Impact:** Can lead to a wide range of vulnerabilities, including arbitrary code execution, depending on how the application uses the parsed object.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** *Never* set `allowPrototypes` to `true` unless absolutely necessary and with extreme caution. The default (`false`) is the secure setting.
    *   **Developer:** If `allowPrototypes: true` is *absolutely required* (highly discouraged), sanitize the parsed object *thoroughly* before using it. Use a safe object creation method (e.g., `Object.create(null)`) to avoid prototype inheritance.

## Attack Surface: [Custom Decoder/Encoder Vulnerabilities](./attack_surfaces/custom_decoderencoder_vulnerabilities.md)

*   **Description:** Vulnerabilities within custom `decoder` or `encoder` functions provided to `qs`.
*   **How `qs` Contributes:** `qs` *directly* allows providing custom functions for decoding and encoding. The security of these functions is now the responsibility of the developer using `qs`, but the *mechanism* to introduce this vulnerability is provided by `qs`.
*   **Example:** A custom decoder that is vulnerable to regular expression denial of service (ReDoS).
*   **Impact:** Depends on the specific vulnerability in the custom function; could range from DoS to code injection.
*   **Risk Severity:** Variable (depends on the custom function; potentially Critical)
*   **Mitigation Strategies:**
    *   **Developer:** Thoroughly audit and test any custom `decoder` or `encoder` functions for security vulnerabilities.
    *   **Developer:** Prefer the built-in `decoder` and `encoder` whenever possible. Avoid custom functions unless absolutely necessary.
    *   **Developer:** If using a custom function, apply secure coding practices specific to the type of operation being performed (e.g., avoid ReDoS in regular expressions).

