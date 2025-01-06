# Threat Model Analysis for expressjs/body-parser

## Threat: [JSON Payload Bomb (Denial of Service)](./threats/json_payload_bomb__denial_of_service_.md)

*   **Description:** An attacker sends a specially crafted JSON payload with deeply nested objects or extremely large arrays. The `bodyParser.json()` middleware attempts to parse this complex structure, consuming excessive CPU time and memory, leading to a denial of service.
    *   **Impact:** The application becomes unresponsive or crashes, preventing legitimate users from accessing the service. Server resources (CPU, memory) are exhausted due to `bodyParser.json()`'s parsing efforts.
    *   **Affected Component:** `bodyParser.json()` middleware.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   Configure the `limit` option in `bodyParser.json()` to restrict the maximum size of JSON payloads processed by the middleware.
        *   Consider the `parameterLimit` option (though primarily for URL-encoded, it can offer some protection against excessive parameters if nested structures are abused in JSON-like ways during parsing by `bodyParser.json()`).

## Threat: [URL-encoded Payload Bomb (Denial of Service)](./threats/url-encoded_payload_bomb__denial_of_service_.md)

*   **Description:** An attacker sends a URL-encoded payload with an extremely large number of parameters or deeply nested structures using array or object syntax. The `bodyParser.urlencoded()` middleware attempts to parse this complex structure, consuming excessive CPU time and memory, leading to a denial of service.
    *   **Impact:** The application becomes unresponsive or crashes, preventing legitimate users from accessing the service. Server resources (CPU, memory) are exhausted due to `bodyParser.urlencoded()`'s parsing efforts.
    *   **Affected Component:** `bodyParser.urlencoded()` middleware.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   Configure the `limit` option in `bodyParser.urlencoded()` to restrict the maximum size of URL-encoded payloads processed by the middleware.
        *   Configure the `parameterLimit` option in `bodyParser.urlencoded()` to limit the number of parameters parsed by the middleware.
        *   Configure the `extended` option in `bodyParser.urlencoded()`. Setting it to `false` uses the simpler `querystring` library which is generally less vulnerable to deep nesting attacks compared to the `qs` library used when `extended` is `true`, thus reducing the parsing complexity for `bodyParser.urlencoded()`.

