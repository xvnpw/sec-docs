# Attack Surface Analysis for arut/nginx-rtmp-module

## Attack Surface: [1. Unauthorized Stream Publishing/Injection](./attack_surfaces/1__unauthorized_stream_publishinginjection.md)

*   **Description:** Attackers publish a live stream without authorization, injecting malicious content or disrupting legitimate streams.
*   **`nginx-rtmp-module` Contribution:** The module's *primary function* is to handle RTMP publishing.  Without proper configuration using its directives, it inherently accepts any incoming publishing request. This is a direct and fundamental aspect of the module.
*   **Example:** An attacker connects to `rtmp://yourserver/live/malicious_stream` and broadcasts unwanted content.
*   **Impact:** Content integrity compromise, service disruption, resource exhaustion, reputational damage.
*   **Risk Severity:** High to Critical.
*   **Mitigation Strategies:**
    *   **Implement `on_publish` Callbacks:** *Crucially*, use the module's `on_publish` directive to trigger a callback to an external application for authentication and authorization *before* the stream starts. This is the *primary* module-provided defense.
    *   **Strong Stream Keys:** Require publishers to use strong, unique stream keys, enforced through the `on_publish` callback logic.
    *   **Rate Limiting (via `on_publish` logic):** While nginx has `limit_req`, controlling publishing *attempts* is best done within the `on_publish` callback logic to reject unauthorized attempts *before* they consume significant resources.

## Attack Surface: [2. Unauthorized Stream Playback](./attack_surfaces/2__unauthorized_stream_playback.md)

*   **Description:** Attackers access live streams without authorization, eavesdropping on private content.
*   **`nginx-rtmp-module` Contribution:** The module directly handles RTMP playback requests.  Without configuration using its directives, it serves any requested stream. This is a core function of the module.
*   **Example:** An attacker connects to `rtmp://yourserver/live/private_stream` and views the content.
*   **Impact:** Confidentiality breach, privacy violation, potential legal issues.
*   **Risk Severity:** High to Critical.
*   **Mitigation Strategies:**
    *   **Implement `on_play` Callbacks:** *Crucially*, use the module's `on_play` directive to trigger a callback to an external application for authentication and authorization *before* allowing playback. This is the *primary* module-provided defense.
    *   **Secure Tokens (validated via `on_play`):** Generate and validate time-limited tokens within the `on_play` callback logic. The module itself doesn't generate tokens, but it *must* be configured to use them via the callback.

## Attack Surface: [3. Command Injection (via `exec` Directives)](./attack_surfaces/3__command_injection__via__exec__directives_.md)

*   **Description:** Attackers execute arbitrary commands on the server by exploiting vulnerabilities in how the module's `exec` directives handle user-supplied data.
*   **`nginx-rtmp-module` Contribution:** The module *provides* the `exec`, `exec_pull`, `exec_push`, and `exec_static` directives, which are the *direct source* of this vulnerability if misused. This is entirely within the module's functionality.
*   **Example:** `exec /usr/bin/my_script $name;` with a stream name of `; rm -rf / ;`.
*   **Impact:** Complete server compromise, data loss, data modification.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Avoid `exec` if Possible:** The *best* mitigation is to avoid using these directives entirely. Use HTTP callbacks to a separate, secured application instead.
    *   **Strict Input Sanitization (if `exec` is unavoidable):** If `exec` *must* be used, *meticulously* sanitize and validate *all* input passed to the command. Use a whitelist approach.  *Never* directly embed user-supplied data. This is a *critical* responsibility when using these module features.
    *   **Parameterization (Ideal, but often not directly supported):** If the external command *and* the calling method support it, use parameterized execution to prevent injection. This is often *not* directly available with simple shell scripts.
    * **Least Privilege (nginx and script):** Run both nginx and any executed scripts with minimal necessary permissions.

## Attack Surface: [4.  Denial of Service (DoS) - RTMP Specific](./attack_surfaces/4___denial_of_service__dos__-_rtmp_specific.md)

*   **Description:**  Attackers overwhelm the server with RTMP-specific actions, exhausting resources.  This focuses on attacks *leveraging the RTMP protocol itself*.
*   **`nginx-rtmp-module` Contribution:** The module is the *direct handler* of all RTMP traffic, making it the focal point for RTMP-specific DoS attacks.
*   **Example:**  Massive numbers of connection attempts, rapid publishing attempts to invalid stream names, or slow-sending of RTMP data to keep connections open.
*   **Impact:** Service unavailability.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Timeouts (Module-Specific):** Configure appropriate `timeout`, `play_timeout`, and `publish_timeout` values *within the `rtmp` block* of the nginx configuration. These are *directly* provided by the module to handle RTMP-specific timeouts.
    *   **`max_streams` (Module-Specific):** Set a reasonable limit on the maximum number of concurrent streams using the module's `max_streams` directive. This directly controls a resource limit within the RTMP context.
    *   **Connection Limiting (nginx general, but relevant):** Use nginx's `limit_conn` (though this is a general nginx feature, it's relevant here).
    *   **Rate Limiting (Best done via `on_publish` callback):**  For *publishing* attempts, rate limiting is best implemented within the logic of the `on_publish` callback, allowing for more granular control and earlier rejection of malicious attempts.

