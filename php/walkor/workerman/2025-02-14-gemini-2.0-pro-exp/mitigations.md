# Mitigation Strategies Analysis for walkor/workerman

## Mitigation Strategy: [Workerman Connection Timeout Configuration](./mitigation_strategies/workerman_connection_timeout_configuration.md)

1.  **Locate Configuration:** Identify where Workerman is initialized and configured (usually in a `start.php` file or similar).
2.  **`connectTimeout`:** Set the `connectTimeout` property (if available) on the `Worker` instance. This controls the timeout (in seconds) for establishing a new connection *to* a remote server (e.g., when your Workerman application acts as a client).  A typical value might be 1-5 seconds.
3.  **`readTimeout`:** Set the `readTimeout` property (if available) on the `Worker` instance or individual connection objects. This controls the timeout (in seconds) for reading data from a connection.  This is crucial for preventing Slowloris-type attacks.  A value of 5-30 seconds is common, depending on the expected data transfer rate.
4.  **`writeTimeout`:** Set the `writeTimeout` property (if available) on the `Worker` instance or individual connection objects. This controls the timeout (in seconds) for writing data to a connection.  A value similar to `readTimeout` is often appropriate.
5.  **Event Handler Timeouts:** Within event handlers (like `onMessage`), if you perform any blocking operations (e.g., database queries, external API calls), use the timeout features of *those* libraries.  Workerman's timeouts apply to the *connection* itself, not to operations performed *within* the connection handler.
6. **Test:** Simulate slow network conditions to verify that the timeouts are working as expected.

*   **Threats Mitigated:**
    *   **Slowloris Attacks (Severity: High):** `readTimeout` directly mitigates Slowloris by closing connections that send data too slowly.
    *   **Hanging Connections (Severity: Medium):** `connectTimeout`, `readTimeout`, and `writeTimeout` prevent the application from waiting indefinitely on unresponsive clients or servers.
    *   **Resource Exhaustion (Severity: Medium):** By preventing hanging connections, timeouts indirectly help prevent resource exhaustion.
    *   **Denial of Service (DoS) (Severity: High):** Mitigates DoS attacks that rely on slow or unresponsive connections.

*   **Impact:**
    *   **Slowloris Attacks:** Risk reduced significantly (from High to Low).
    *   **Hanging Connections:** Risk reduced significantly (from Medium to Low).
    *   **Resource Exhaustion:** Risk reduced moderately (from Medium to Low/Medium).
    *   **Denial of Service (DoS):** Risk reduced significantly (from High to Low/Medium).

*   **Currently Implemented:** (Example: `connectTimeout` is set, but `readTimeout` and `writeTimeout` are not.) *You need to fill this in.*

*   **Missing Implementation:** (Example: `readTimeout` and `writeTimeout` need to be configured on the `Worker` instance in `start.php`.  Timeouts for database queries within event handlers also need to be reviewed.) *You need to fill this in.*

## Mitigation Strategy: [Workerman Connection Limit Configuration](./mitigation_strategies/workerman_connection_limit_configuration.md)

1.  **Locate Configuration:** Identify where Workerman worker processes are started (usually in `start.php`).
2.  **`count` Property:** Set the `count` property on the `Worker` instance. This determines the *number* of worker processes that Workerman will start.  This is *indirectly* related to connection limits, as each process can handle a certain number of connections.  Choose a value appropriate for your server's resources (e.g., the number of CPU cores).
3.  **`maxConnections` (If Available):** If Workerman provides a `maxConnections` property (or a similar mechanism) on the `Worker` or connection objects, set this to a reasonable limit. This directly limits the *total* number of concurrent connections that the Workerman instance will accept.
4. **Monitor:** Use Workerman's built-in statistics (if available) to monitor the number of active connections and processes.  Adjust `count` and `maxConnections` as needed based on observed load and resource usage.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: High):** Prevents attackers from overwhelming the server with connection requests.
    *   **Resource Exhaustion (Severity: High):** Limits the resources (memory, file handles) consumed by connections.

*   **Impact:**
    *   **Denial of Service (DoS):** Risk reduced significantly (from High to Low/Medium).
    *   **Resource Exhaustion:** Risk reduced significantly (from High to Low/Medium).

*   **Currently Implemented:** (Example: `count` is set to 4, but `maxConnections` is not used.) *You need to fill this in.*

*   **Missing Implementation:** (Example: Check if `maxConnections` is available and applicable.  Implement monitoring of connection counts and adjust settings dynamically.) *You need to fill this in.*

## Mitigation Strategy: [Workerman Connection Context Usage](./mitigation_strategies/workerman_connection_context_usage.md)

1.  **Identify Connection-Specific Data:** Within event handlers (`onConnect`, `onMessage`, `onClose`), identify any data that is specific to a particular client connection (e.g., user ID, session data, request-specific state).
2.  **Use `$connection` Object:** Store this data *directly* on the `$connection` object provided by Workerman.  For example: `$connection->userId = $userId;`.  *Do not* use global variables, static variables, or class properties for this purpose.
3.  **Access Data:** Access the data using the same `$connection` object: `echo $connection->userId;`.
4.  **Automatic Cleanup:** Workerman automatically cleans up data stored on the `$connection` object when the connection closes.  This prevents memory leaks and data leakage between connections.  You *do not* need to manually `unset` this data.
5. **Avoid Large Objects:** Be mindful of storing very large objects directly on the connection context, as this could still contribute to memory pressure if you have many concurrent connections. For large data, consider using an external store (database, Redis) and storing only a reference (e.g., an ID) in the connection context.

*   **Threats Mitigated:**
    *   **Information Disclosure (Severity: Medium/High):** Prevents connection-specific data from being accidentally exposed to other clients.
    *   **State Corruption (Severity: Medium):** Ensures that data is associated with the correct connection, preventing unexpected behavior.
    *   **Memory Leaks (Severity: Medium):** Avoids memory leaks by relying on Workerman's automatic cleanup.

*   **Impact:**
    *   **Information Disclosure:** Risk reduced significantly (from Medium/High to Low).
    *   **State Corruption:** Risk reduced significantly (from Medium to Low).
    *   **Memory Leaks:** Risk reduced significantly (from Medium to Low).

*   **Currently Implemented:** (Example: Partially implemented; user ID is stored on `$connection`, but some session data is still in a global array.) *You need to fill this in.*

*   **Missing Implementation:** (Example: Review all event handlers to ensure *all* connection-specific data is stored on the `$connection` object. Refactor any code using global or static variables for this purpose.) *You need to fill this in.*

## Mitigation Strategy: [Workerman Graceful Reload/Restart](./mitigation_strategies/workerman_graceful_reloadrestart.md)

1.  **Signal Handling:** Workerman uses signals (e.g., `SIGUSR1`, `SIGTERM`) for control.  Understand how these signals work.
2.  **Graceful Reload (`SIGUSR1`):** Use the `SIGUSR1` signal to trigger a graceful reload of the Workerman worker processes.  This allows new code to be loaded *without* dropping existing connections.  Existing connections will continue to be handled by the old processes until they close, while new connections will be handled by the new processes.  This is essential for zero-downtime deployments. Send this signal using `posix_kill(posix_getppid(), SIGUSR1)` from within a worker process, or from an external process using the process ID of the *master* Workerman process.
3.  **Graceful Stop (`SIGTERM`):** Use the `SIGTERM` signal to trigger a graceful stop of Workerman.  This will stop accepting new connections and wait for existing connections to close before exiting.
4.  **Avoid `SIGKILL`:** *Never* use `SIGKILL` (or `kill -9`) to stop Workerman processes, as this will immediately terminate them, dropping all connections and potentially corrupting data.
5. **Deployment Scripts:** Integrate graceful reload/restart into your deployment scripts.  After deploying new code, send a `SIGUSR1` signal to the Workerman master process.
6. **Monitor:** After a reload, monitor the application to ensure that the new processes are working correctly and that the old processes have exited.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: Medium):** Prevents brief service interruptions during deployments or restarts.
    *   **Data Loss (Severity: Low/Medium):** Prevents data loss that could occur if connections are abruptly terminated.
    *   **Connection Dropping (Severity: Medium):** Avoids dropping active connections during updates.

*   **Impact:**
    *   **Denial of Service (DoS):** Risk reduced significantly (from Medium to Low).
    *   **Data Loss:** Risk reduced significantly (from Low/Medium to Low).
    *   **Connection Dropping:** Risk reduced significantly (from Medium to Low).

*   **Currently Implemented:** (Example: Deployment script uses `kill -9`, which is incorrect.) *You need to fill this in.*

*   **Missing Implementation:** (Example: Deployment script needs to be updated to use `posix_kill` with `SIGUSR1` for graceful reloads.  Monitoring needs to be added to verify successful reloads.) *You need to fill this in.*

## Mitigation Strategy: [Workerman WebSocket Origin Validation (If using WebSockets)](./mitigation_strategies/workerman_websocket_origin_validation__if_using_websockets_.md)

1. **`onWebSocketConnect` Handler:** Within the `onWebSocketConnect` event handler (or the equivalent handler if you're using a custom WebSocket implementation on top of Workerman), access the HTTP headers.
2. **`$connection->headers`:** Access the headers using `$connection->headers` (or the appropriate property provided by Workerman).
3. **`Origin` Header:** Retrieve the value of the `Origin` header: `$origin = $connection->headers['Origin'] ?? null;`. Handle the case where the header might be missing.
4. **Whitelist:** Compare the `$origin` value against a predefined whitelist of allowed origins (domains). This whitelist should be stored in a configuration file or environment variable, *not* hardcoded.
5. **Reject Invalid Connections:** If the origin is *not* in the whitelist (or if the `Origin` header is missing and you choose to reject such requests), close the connection using `$connection->close();`. You might also send a specific error code or message.
6. **Strict Comparison:** Use a strict comparison (e.g., `===`) when checking the origin against the whitelist to avoid potential bypasses.

*   **Threats Mitigated:**
    *   **Cross-Site WebSocket Hijacking (CSWSH) (Severity: High):** Prevents attackers from using malicious websites to establish WebSocket connections to your server on behalf of legitimate users.

*   **Impact:**
    *   **Cross-Site WebSocket Hijacking (CSWSH):** Risk reduced significantly (from High to Low).

*   **Currently Implemented:** (Example: No origin validation is currently implemented.) *You need to fill this in.*

*   **Missing Implementation:** (Example: Needs to be implemented within the `onWebSocketConnect` handler in `src/Handlers/WebSocketHandler.php`. The whitelist of allowed origins needs to be defined.) *You need to fill this in.*

