# Mitigation Strategies Analysis for ossrs/srs

## Mitigation Strategy: [Connection Limiting (`max_connections`)](./mitigation_strategies/connection_limiting___max_connections__.md)

*   **Mitigation Strategy:**  Configure the `max_connections` directive within SRS.

*   **Description:**
    1.  Open the SRS configuration file (`srs.conf` or similar).
    2.  Locate the `vhost` configuration block for your domain (or the default `vhost`).
    3.  Within the `vhost` block, set the `max_connections` parameter to a reasonable value based on your server's capacity and expected legitimate load.  Start conservatively and adjust based on monitoring.  Example:
        ```
        vhost yourdomain.com {
            max_connections 1000;
            ...
        }
        ```
    4.  Restart the SRS service for the changes to take effect.

*   **Threats Mitigated:**
    *   **Connection Exhaustion DoS (Severity: High):** Attackers flood the server with connection requests, preventing legitimate users from connecting.  This is a *partial* mitigation; external tools are needed for full protection.

*   **Impact:**
    *   **Connection Exhaustion DoS:** Risk *partially* reduced. Provides a hard limit on the *total* number of connections, but doesn't differentiate between legitimate and malicious connections.  Highly vulnerable to distributed attacks.

*   **Currently Implemented:**
    *   `max_connections` is set to 5000 in `srs.conf`.

*   **Missing Implementation:**
    *   This is a basic setting; more granular control (per-IP, per-stream) requires external tools.

## Mitigation Strategy: [Authentication and Authorization (Hooks)](./mitigation_strategies/authentication_and_authorization__hooks_.md)

*   **Mitigation Strategy:** Implement authentication for publishing and playback using SRS's `on_publish` and `on_play` hooks.

*   **Description:**
    1.  **Publish Authentication (`on_publish`):**
        *   Create a script (e.g., Python, Bash, or an HTTP endpoint) that SRS will call when a client attempts to publish a stream.
        *   This script receives information from SRS (client IP, stream name, etc.) via environment variables or HTTP request parameters.
        *   The script *must* authenticate the client against a database, LDAP server, or other *external* authentication provider.  SRS does *not* handle the authentication logic itself; it only calls the external script.
        *   The script returns a success (0) or failure (non-zero) exit code to SRS.
        *   Configure the `on_publish` hook in `srs.conf`:
            ```
            vhost yourdomain.com {
                publish {
                    on_publish http://127.0.0.1:8085/auth-publish; // Or a script path
                }
                ...
            }
            ```
    2.  **Play Authentication (`on_play`):**
        *   Create a similar script (or HTTP endpoint) for the `on_play` hook, called when a client attempts to play a stream.
        *   This script authenticates clients attempting to *view* streams, using the same external authentication provider as `on_publish`.
        *   Configure the `on_play` hook in `srs.conf`.
    3. **`on_connect`, `on_close`, `on_unpublish`, `on_stop`:** Consider using these additional hooks for more fine-grained control and logging, always calling external scripts for any security-critical decisions.

*   **Threats Mitigated:**
    *   **Unauthorized Publishing (Severity: High):** Attackers inject unwanted streams.  Mitigation relies entirely on the *external* authentication script.
    *   **Unauthorized Playback (Severity: High):** Attackers view unauthorized streams.  Mitigation relies entirely on the *external* authentication script.

*   **Impact:**
    *   **Unauthorized Publishing/Playback:** Risk is *entirely dependent* on the security and correctness of the *external* authentication scripts called by the hooks.  SRS itself only provides the *mechanism* to call these scripts.

*   **Currently Implemented:**
    *   Basic `on_publish` authentication is implemented, calling an external script.  The script's security is *not* assessed here, as it's external to SRS.

*   **Missing Implementation:**
    *   `on_play` authentication is *not* implemented.

## Mitigation Strategy: [Configuration File Security (Limited Scope)](./mitigation_strategies/configuration_file_security__limited_scope_.md)

*   **Mitigation Strategy:** Restrict access to the SRS configuration file.  This is *partially* within SRS's scope, as SRS must be able to read the file.

*   **Description:**
    1.  **File Permissions:** Use `chown` and `chmod` to set the owner and permissions of the `srs.conf` file.  Typically, the user running the SRS process should be the owner, and the permissions should be `600` (read/write for the owner only).  Example:
        ```bash
        chown srs_user:srs_group /path/to/srs.conf
        chmod 600 /path/to/srs.conf
        ```
        Replace `srs_user` and `srs_group` with the appropriate user and group.
    2. **Avoid Storing Secrets Directly (Indirectly related to SRS):** While SRS *reads* the configuration, the best practice is to *not* store secrets (passwords, API keys) directly within it. This is more about secure development practices than SRS itself, but it's crucial. Use environment variables or a secrets management system, and have your *external* authentication scripts access those.

*   **Threats Mitigated:**
    *   **Configuration File Tampering (Severity: High):** Attackers modify the configuration to gain access or disrupt service. *Partially* mitigated by file permissions.
    *   **Credential Theft (Severity: Medium):** If credentials *were* stored in the file (which they shouldn't be), attackers could read them.

*   **Impact:**
    *   **Configuration File Tampering:** Risk *partially* reduced. File permissions prevent unauthorized users from modifying the file, but the SRS process itself could be compromised.
    *   **Credential Theft:** Risk is related to *how* credentials are used, not directly to SRS's configuration file security.

*   **Currently Implemented:**
    *   File permissions are set to `644` (read/write for owner, read for group and others) - *This is insecure*.

*   **Missing Implementation:**
    *   File permissions should be `600`.
    *   Secrets management is not addressed within SRS itself.

## Mitigation Strategy: [SRS Logging](./mitigation_strategies/srs_logging.md)

*   **Mitigation Strategy:** Configure SRS's built-in logging.

*   **Description:**
    1.  In `srs.conf`, set the `log_level` directive.  Options include `trace`, `verbose`, `info`, `warn`, `error`.  `info` or `warn` are generally appropriate for production.
    2.  Configure the `log_file` directive to specify the path to the log file.
    3.  Consider using the `log_tank` directive to control log output (e.g., to console, file, or both).
    4.  SRS *does not* handle log rotation; this must be done externally (e.g., with `logrotate`).

*   **Threats Mitigated:**
    *   **Undetected Attacks (Severity: High):** Attacks may go unnoticed without proper logging.
    *   **Delayed Incident Response (Severity: Medium):** Without logs, it's harder to investigate and respond to incidents.

*   **Impact:**
    *   **Undetected Attacks/Delayed Response:** Logging provides *visibility*, but does not *prevent* attacks.  The effectiveness depends on *external* log monitoring and analysis.

*   **Currently Implemented:**
    *   SRS logging is enabled with the default `info` level.
    *   Logs are written to a file.

*   **Missing Implementation:**
    *   Log rotation is *not* handled by SRS; it's an external concern.
    *   Log monitoring and analysis are external.

## Mitigation Strategy: [DTLS Certificate (WebRTC - Limited Scope)](./mitigation_strategies/dtls_certificate__webrtc_-_limited_scope_.md)

*    **Mitigation Strategy:** Configure SRS to use a DTLS certificate for WebRTC.
*    **Description:**
    1. Obtain a TLS/DTLS certificate. This can be self-signed (for testing) or from a Certificate Authority (CA) for production.
    2. In the `srs.conf` file, within the `vhost` configuration, set the `dtls_cert` and `dtls_key` directives to point to the certificate and key files, respectively. Example:
        ```
        vhost yourdomain.com {
            webrtc {
                enabled on;
                dtls_cert ./your_cert.pem;
                dtls_key ./your_key.pem;
            }
        }
        ```
    3. Restart the SRS service.

*   **Threats Mitigated:**
    *   **Man-in-the-Middle (MitM) Attacks (Severity: High):** Attackers intercept and modify WebRTC communication. *Partially* mitigated; the security depends on the certificate's validity and the trustworthiness of the CA (if used).
    *   **Data Eavesdropping (Severity: High):** Attackers listen in on unencrypted WebRTC media streams.

*   **Impact:**
    *   **MitM/Eavesdropping:** Risk is reduced if a valid certificate is used. Self-signed certificates offer *some* protection against passive eavesdropping but are vulnerable to MitM attacks.

*   **Currently Implemented:**
    *   A self-signed certificate is used.

*   **Missing Implementation:**
    *   A certificate from a trusted CA is recommended for production.

