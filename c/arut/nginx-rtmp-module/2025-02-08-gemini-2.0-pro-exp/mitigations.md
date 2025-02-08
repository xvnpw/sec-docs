# Mitigation Strategies Analysis for arut/nginx-rtmp-module

## Mitigation Strategy: [Robust Authentication and Authorization (using `nginx-rtmp-module` directives)](./mitigation_strategies/robust_authentication_and_authorization__using__nginx-rtmp-module__directives_.md)

*   **Description:**
    1.  **`on_publish` and `on_play` Configuration:**  Configure the `on_publish` and `on_play` directives within the `rtmp` block of your `nginx.conf`.  These are *core* `nginx-rtmp-module` directives.  They specify URLs to which Nginx will send HTTP requests when a client attempts to publish or play a stream, respectively.
    2.  **Authentication Script/Service Interaction:** The external authentication script/service (which you must provide) receives data *from* `nginx-rtmp-module` via these HTTP requests.  This data typically includes the stream name, client IP, and potentially authentication credentials (or a token).
    3.  **Response Handling:** The script/service processes the request, validates credentials against a backend (database, LDAP, etc.), and returns an HTTP status code *to* `nginx-rtmp-module`.  `nginx-rtmp-module` then uses this status code to allow or deny the publish/play operation.  A `2xx` code allows; a `4xx` or `5xx` code denies.
    4.  **Token-Based Authentication (via `on_publish`):**  Implement token-based authentication by having your publishing clients include a token (usually as a query parameter in the RTMP URL).  Your `on_publish` handler script extracts and validates this token.  This is still *directly* using `nginx-rtmp-module`'s `on_publish` directive.
    5.  **`allow publish`/`deny publish` and `allow play`/`deny play` (Supplementary):**  Use these directives *within* the `rtmp` application block to add IP-based restrictions.  *However*, this should be a *supplementary* measure, not the primary authentication method, as IP addresses can be spoofed.  These are direct `nginx-rtmp-module` directives.

*   **Threats Mitigated:**
    *   **Unauthorized Publishing (High Severity):** Directly prevents unauthorized publishing by requiring authentication through the `on_publish` directive.
    *   **Unauthorized Playback (Medium to High Severity):** Directly prevents unauthorized playback through the `on_play` directive.
    *   **Stream Hijacking (High Severity):** Makes hijacking significantly harder by requiring authentication for both publishing and playing.
    *   **Replay Attacks (Medium Severity):** Mitigated when combined with token-based authentication and short token lifetimes (handled by your external script, but triggered by `nginx-rtmp-module`).

*   **Impact:**
    *   **Unauthorized Publishing:** Risk reduced from High to Low (with proper implementation).
    *   **Unauthorized Playback:** Risk reduced from Medium/High to Low (with proper implementation).
    *   **Stream Hijacking:** Risk reduced from High to Low.
    *   **Replay Attacks:** Risk reduced from Medium to Low (with token-based authentication).

*   **Currently Implemented:**
    *   Basic `on_publish` and `on_play` directives are configured, pointing to a PHP authentication script.

*   **Missing Implementation:**
    *   Token-based authentication is not fully integrated with `on_publish` (the script doesn't handle tokens).
    *   `allow/deny` directives are not used, even as a supplementary measure.

## Mitigation Strategy: [Bandwidth Limiting (using `nginx-rtmp-module`'s `limit_rate`)](./mitigation_strategies/bandwidth_limiting__using__nginx-rtmp-module_'s__limit_rate__.md)

*   **Description:**
    1.  **`limit_rate` Directive:** Use the `limit_rate` directive *within* the `rtmp` application or server block in your `nginx.conf`. This is a *direct* `nginx-rtmp-module` directive.  It controls the bandwidth allowed for RTMP connections.
    2.  **Configuration:**  Specify the desired bandwidth limit.  Examples: `limit_rate 1m;` (1 megabit per second), `limit_rate 500k;` (500 kilobits per second).  You can apply this globally or per-stream/application.

*   **Threats Mitigated:**
    *   **Bandwidth Exhaustion (Medium Severity):** Directly prevents individual RTMP connections from consuming excessive bandwidth, protecting server resources.
    *   **DoS (Partial Mitigation - Medium to High Severity):**  Helps mitigate DoS attacks that attempt to saturate bandwidth, although it's not a complete solution against sophisticated attacks.

*   **Impact:**
    *   **Bandwidth Exhaustion:** Risk reduced from Medium to Low.
    *   **DoS:** Risk reduced from Medium/High to Medium (limits the effectiveness, but doesn't eliminate the threat).

*   **Currently Implemented:**
    *   `limit_rate` is NOT implemented.

*   **Missing Implementation:**
    *   **Complete absence of `limit_rate` configuration.**  No bandwidth limits are enforced at the RTMP level.

## Mitigation Strategy: [RTMP-Specific Logging and Statistics (using `nginx-rtmp-module` features)](./mitigation_strategies/rtmp-specific_logging_and_statistics__using__nginx-rtmp-module__features_.md)

*   **Description:**
    1.  **`stat` Directive:** Use the `stat` directive within the `rtmp` block of your `nginx.conf`.  This is a *core* `nginx-rtmp-module` feature.  It exposes statistics about the RTMP server, typically accessible via an HTTP endpoint.
    2.  **Accessing Statistics:**  Configure a location block (in the `http` section of your `nginx.conf`) to handle requests to the `stat` URL.  This usually involves using the `rtmp_stat` directive.
    3.  **Data Provided:** The `stat` directive provides information like the number of active connections, bytes in/out, and details about individual streams (if configured).
    4.  **`nginx-rtmp-module` Specific Logging:** While general Nginx logging is important, ensure you're capturing logs *specifically* generated by `nginx-rtmp-module`.  This might involve adjusting log levels or using custom log formats within the `rtmp` block.  The exact options depend on the module's version and configuration.

*   **Threats Mitigated:**
    *   **All Threats (Indirectly):**  Provides crucial visibility into the RTMP server's operation, enabling detection of anomalies and facilitating incident response.  It's a *detection* and *response* enabler, not a direct preventative measure.
    *   **Slow Attacks/Probing (Medium Severity):**  Helps identify slow, stealthy attacks by monitoring connection patterns and resource usage.

*   **Impact:**
    *   **All Threats:** Improves detection and response capabilities.
    *   **Slow Attacks/Probing:** Risk reduced from Medium to Low (with effective monitoring).

*   **Currently Implemented:**
    *   The `stat` directive is NOT used.
    *   No specific `nginx-rtmp-module` logging beyond default Nginx logs.

*   **Missing Implementation:**
    *   **`stat` directive is completely absent.**  No RTMP-specific statistics are exposed.
    *   No dedicated monitoring of `nginx-rtmp-module`'s log output.

