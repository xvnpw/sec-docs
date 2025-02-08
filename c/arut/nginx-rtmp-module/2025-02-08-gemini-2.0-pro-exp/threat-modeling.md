# Threat Model Analysis for arut/nginx-rtmp-module

## Threat: [Stream Hijacking via Spoofed Publisher Identity](./threats/stream_hijacking_via_spoofed_publisher_identity.md)

*   **Threat:** Stream Hijacking via Spoofed Publisher Identity

    *   **Description:** An attacker impersonates a legitimate publisher by using a stolen or guessed stream key and/or application name. The attacker sends their own content, replacing the legitimate stream. This directly exploits the `nginx-rtmp-module`'s authentication and stream handling mechanisms.
    *   **Impact:** Loss of control over the stream content; distribution of malicious, inappropriate, or unauthorized content to viewers; reputational damage; potential legal consequences.
    *   **Affected Component:** `on_publish` callback (if implemented, but bypassed or improperly configured), authentication logic within the module, stream key validation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Implement robust authentication using the `on_publish` callback to verify publisher credentials against a secure backend (e.g., database, authentication service).  Do *not* rely solely on stream keys.
        *   Use strong, randomly generated, and frequently rotated stream keys.
        *   Consider IP address whitelisting for known publishers (but be aware of spoofing limitations). This can be done within the `nginx-rtmp-module` configuration or at the firewall level.
        *   Implement two-factor authentication (2FA) for publishers, if feasible (this would likely be handled outside the module itself, but would enhance overall security).

## Threat: [Denial of Service (DoS) via Connection Flooding](./threats/denial_of_service__dos__via_connection_flooding.md)

*   **Threat:** Denial of Service (DoS) via Connection Flooding

    *   **Description:** An attacker opens a large number of RTMP connections to the server, exceeding configured limits within the `nginx-rtmp-module` or exhausting server resources. This directly targets the module's connection handling capabilities.
    *   **Impact:**  Legitimate publishers and viewers are unable to connect; service interruption; potential financial losses.
    *   **Affected Component:**  `nginx-rtmp-module` connection management, Nginx core connection handling (as configured by the module).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Configure `limit_conn` and `limit_req` directives *within the `nginx-rtmp-module` context* in `nginx.conf` to restrict the number of connections and requests per IP address or other criteria. This is a direct mitigation within the module.
        *   Set appropriate connection and read/write timeouts (`client_body_timeout`, `client_header_timeout`, `send_timeout`) within the RTMP context to prevent slow connections from consuming resources. These are often configurable within the RTMP block in `nginx.conf`.

## Threat: [Denial of Service (DoS) via Bandwidth Consumption](./threats/denial_of_service__dos__via_bandwidth_consumption.md)

*   **Threat:** Denial of Service (DoS) via Bandwidth Consumption

    *   **Description:** An attacker publishes a very high-bandwidth stream (or multiple streams), saturating the server's network uplink or downlink, preventing legitimate streams from being delivered. This directly impacts the `nginx-rtmp-module`'s bandwidth handling.
    *   **Impact:**  Degraded stream quality for viewers; inability to deliver streams reliably; potential financial losses.
    *   **Affected Component:** `nginx-rtmp-module`'s bandwidth handling (specifically, the `bandwidth` directive, if used).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use the `bandwidth` directive *within the `nginx-rtmp-module` configuration* to limit the bandwidth allowed per publisher or per application. This is a direct mitigation provided by the module.

## Threat: [Exploitation of `nginx-rtmp-module` Vulnerability](./threats/exploitation_of__nginx-rtmp-module__vulnerability.md)

*   **Threat:** Exploitation of `nginx-rtmp-module` Vulnerability

    *   **Description:** An attacker exploits a vulnerability (e.g., buffer overflow, code injection) in the `nginx-rtmp-module` code itself. This is a direct attack on the module.
    *   **Impact:**  Denial of service; arbitrary code execution on the server; complete server compromise; data breaches.
    *   **Affected Component:**  The `nginx-rtmp-module` itself (specific vulnerable functions or code sections).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Crucially:** Keep the `nginx-rtmp-module` and Nginx updated to the *latest* versions.  This addresses known vulnerabilities.
        *   Monitor security advisories and vulnerability databases (e.g., CVE) for reports related to the module.
        *   Run Nginx with the least necessary privileges (not as root). This limits the *impact* of a successful exploit, but doesn't directly address the module vulnerability itself.
        *   Implement system-level security measures (SELinux, AppArmor) to contain the impact of a successful exploit. Again, this is a mitigation of impact, not a direct fix for the module.

## Threat: [Unauthorized Access to Recorded Streams](./threats/unauthorized_access_to_recorded_streams.md)

* **Threat:** Unauthorized Access to Recorded Streams

    * **Description:** If recording is enabled (using the `record` directive *within* `nginx-rtmp-module`), an attacker gains unauthorized access to the recorded video files. While file system permissions are involved, the vulnerability stems from enabling and configuring recording within the module.
    * **Impact:** Disclosure of sensitive content; privacy violations; potential legal consequences.
    * **Affected Component:** `record` directive within `nginx-rtmp-module`, file system permissions (influenced by the module's configuration).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   Store recorded files in a directory with restricted access permissions. Use strong file system permissions (e.g., `chmod`, `chown`). This is influenced by where the `record` directive points.
        *   Do *not* make the recording directory directly accessible via HTTP unless absolutely necessary and properly secured (e.g., with authentication). This is a configuration choice related to how the module's output is handled.
        *   If serving recorded files via HTTP, use Nginx's access control features (e.g., `auth_basic`, `allow`/`deny`) to restrict access. This is a configuration choice related to how the module's output is handled.
        * Consider encrypting recorded files.

