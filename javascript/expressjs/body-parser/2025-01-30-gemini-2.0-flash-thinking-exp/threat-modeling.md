# Threat Model Analysis for expressjs/body-parser

## Threat: [Large Request Body DoS](./threats/large_request_body_dos.md)

*   **Threat:** Large Request Body DoS
*   **Description:** An attacker sends excessively large HTTP request bodies to the server. `body-parser` attempts to parse these large bodies into memory, consuming server resources. This can be achieved by automated scripts or manual attacks sending very large payloads.
*   **Impact:**
    *   Server memory exhaustion, leading to application crashes or unresponsiveness.
    *   CPU exhaustion due to parsing extremely large bodies, significantly slowing down or halting the application.
    *   Denial of service for legitimate users, rendering the application unavailable.
*   **Affected body-parser component:** All parser modules (`json`, `urlencoded`, `raw`, `text`) are affected as they all parse the request body content.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **`limit` option:**  Configure the `limit` option within `body-parser` middleware (e.g., `bodyParser.json({ limit: '100kb' })`) to strictly enforce maximum request body sizes.
    *   **Reverse Proxy Limits:** Implement request body size limits at the reverse proxy level (e.g., using Nginx's `client_max_body_size` directive or Apache's `LimitRequestBody` directive) for an initial layer of defense before requests reach the application.
    *   **Rate Limiting:** Implement rate limiting to restrict the number of requests from a single IP address within a given timeframe. This can help mitigate rapid, automated DoS attempts.

