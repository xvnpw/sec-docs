# Mitigation Strategies Analysis for walkor/workerman

## Mitigation Strategy: [Connection Limits and Rate Limiting (Workerman Specific)](./mitigation_strategies/connection_limits_and_rate_limiting__workerman_specific_.md)

*   **Description:**
    1.  **Configure `maxConnections`:**  In your Workerman bootstrap script (e.g., `start.php`), utilize the `$worker->maxConnections` property. This Workerman setting directly limits the total number of concurrent client connections a worker process will accept. Set this value based on your server's capacity and expected load.  Example: `$worker->maxConnections = 1000;`
    2.  **Implement Per-IP Connection Limits (Custom Logic in `onConnect`):** Workerman's `onConnect` callback is the ideal place to implement custom per-IP connection limiting.
        *   Maintain an array or external storage (like Redis) to track connection counts per IP address.
        *   In the `onConnect` callback, retrieve the client's IP address using `$_SERVER['REMOTE_ADDR']` or `$connection->getRemoteIp()`. 
        *   Check if the connection count for this IP exceeds a defined threshold.
        *   If the limit is exceeded, close the connection using `$connection->close()` immediately within `onConnect` to prevent resource consumption.
    3.  **Rate Limiting in `onMessage` (Custom Logic):**  Workerman's `onMessage` callback allows you to implement request-based rate limiting.
        *   For each incoming message in `onMessage`, track the message frequency per connection or IP address within a time window.
        *   Use in-memory arrays, file-based storage, or external caching (like Redis) to store and check message timestamps.
        *   If the message rate exceeds a defined threshold, implement rate limiting actions:
            *   Ignore the message (drop it).
            *   Send a rate limit exceeded response to the client.
            *   Temporarily close the connection.
    4.  **Monitor Connection Counts (Workerman Statistics):** Leverage Workerman's built-in status monitoring or implement custom logging to track the number of active connections. This helps in observing the effectiveness of connection limits and identifying potential DoS attempts.

*   **Threats Mitigated:**
    *   Denial of Service (DoS) Attacks (High Severity) - By limiting connections and request rates directly within Workerman, you prevent resource exhaustion of the Workerman processes themselves.
    *   Resource Exhaustion (Medium Severity) - Prevents Workerman processes from being overwhelmed by excessive connections or rapid message streams.

*   **Impact:**
    *   Denial of Service (DoS) Attacks: High Reduction (specifically against Workerman process overload)
    *   Resource Exhaustion: High Reduction (for Workerman processes)

*   **Currently Implemented:** Basic `$worker->maxConnections` is set in `start.php`.

*   **Missing Implementation:**
    *   Per-IP connection limits using custom logic in `onConnect` are not implemented.
    *   Rate limiting within `onMessage` is completely missing.
    *   Detailed monitoring of connection counts beyond basic Workerman status is not in place.

## Mitigation Strategy: [Principle of Least Privilege for Workerman Processes (Workerman Specific User Configuration)](./mitigation_strategies/principle_of_least_privilege_for_workerman_processes__workerman_specific_user_configuration_.md)

*   **Description:**
    1.  **Configure `user` Property in Workerman:**  Workerman allows you to specify the user under which worker processes should run using the `$worker->user` property in your bootstrap script (`start.php`).
    2.  **Create Dedicated System User:** Create a dedicated, low-privilege system user specifically for running Workerman. Avoid using `root` or users with broad permissions. Example user: `workerman-app`.
    3.  **Set `worker->user`:** In your `start.php` file, set `$worker->user = 'workerman-app';` for each worker instance you define. Workerman will then switch to this user after initial startup (if started as root, which is generally discouraged).
    4.  **File Permissions for Workerman Files:** Ensure that the Workerman application files are owned by the dedicated user and have restricted permissions. This limits the impact if the Workerman process is compromised.

*   **Threats Mitigated:**
    *   Privilege Escalation (High Severity) - If an attacker compromises a Workerman process, running it under a low-privilege user limits the attacker's ability to escalate privileges and gain broader system access.
    *   System-Wide Compromise (High Severity) - Reduces the potential for a Workerman exploit to lead to a full system compromise because the process operates with restricted permissions.

*   **Impact:**
    *   Privilege Escalation: High Reduction (within the context of Workerman process compromise)
    *   System-Wide Compromise: High Reduction (limiting the scope of Workerman-related breaches)

*   **Currently Implemented:** Workerman is started by a non-root user, but it's still a user with broader permissions than ideal (`webapp` user).

*   **Missing Implementation:**
    *   A dedicated, truly low-privilege user (`workerman-app`) needs to be created specifically for Workerman.
    *   The `user` property in `start.php` needs to be explicitly set to this dedicated user to ensure Workerman runs with reduced privileges.

## Mitigation Strategy: [TLS/SSL Encryption Configuration in Workerman](./mitigation_strategies/tlsssl_encryption_configuration_in_workerman.md)

*   **Description:**
    1.  **Configure `transport` for TLS:** When creating Workerman listeners (e.g., `new Worker('websocket://...')`), use the `transport` option to specify `ssl` for TLS encryption. Example: `new Worker('websocket://0.0.0.0:8443', ['transport' => 'ssl', ...]);`
    2.  **Specify `context` Options for Certificates:**  Within the worker constructor's options array, use the `context` key to provide SSL context options.  Crucially, specify the paths to your SSL certificate (`local_cert`) and private key (`local_pk`).
        ```php
        $worker = new Worker('websocket://0.0.0.0:8443', [
            'transport' => 'ssl',
            'context' => [
                'ssl' => [
                    'local_cert'         => '/path/to/your/fullchain.pem', // Path to your certificate chain
                    'local_pk'           => '/path/to/your/privkey.pem',   // Path to your private key
                    'verify_peer'          => false, // Set to true for client certificate verification (optional)
                    'allow_self_signed' => true   // Set to false in production, true for testing self-signed certs
                ]
            ]
        ]);
        ```
    3.  **Enforce HTTPS Redirection (for HTTP Workers):** If using Workerman's HTTP server, configure redirection from `http://` to `https://` to ensure all web traffic is encrypted. This can be done in your HTTP request handling logic within Workerman.
    4.  **Secure TLS Protocol and Cipher Configuration (within `context`):**  Within the `context['ssl']` array, you can further configure TLS settings like:
        *   `crypto_method`:  Specify allowed TLS protocols (e.g., `STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER`).
        *   `ciphers`:  Define allowed cipher suites for stronger encryption.

*   **Threats Mitigated:**
    *   Man-in-the-Middle (MITM) Attacks (High Severity) - Workerman's TLS configuration directly encrypts communication channels, preventing eavesdropping and tampering.
    *   Data Eavesdropping (High Severity) - Encrypting Workerman's network traffic protects sensitive data transmitted through Workerman-based services.

*   **Impact:**
    *   Man-in-the-Middle (MITM) Attacks: High Reduction (for Workerman network communication)
    *   Data Eavesdropping: High Reduction (for data handled by Workerman)

*   **Currently Implemented:** TLS/SSL is enabled for the WebSocket server (`wss://`) using `transport => 'ssl'` and basic certificate paths in `context`.

*   **Missing Implementation:**
    *   HTTPS redirection for the HTTP server is not implemented. HTTP traffic remains unencrypted.
    *   Advanced TLS configuration options within `context['ssl']` (like `crypto_method` and `ciphers`) are not configured for stronger security. They are using defaults which might not be optimal.

