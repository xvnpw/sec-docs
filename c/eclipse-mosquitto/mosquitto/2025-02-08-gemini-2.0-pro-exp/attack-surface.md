# Attack Surface Analysis for eclipse-mosquitto/mosquitto

## Attack Surface: [Unauthenticated Access](./attack_surfaces/unauthenticated_access.md)

*   **Description:**  Clients connecting to the broker without providing any credentials.
*   **Mosquitto Contribution:** Mosquitto's `allow_anonymous` setting directly controls whether unauthenticated connections are permitted.  Defaults may vary, making this a critical check.
*   **Example:** An attacker connects without credentials and subscribes to all topics (`#`).
*   **Impact:**  Complete compromise of the MQTT system; read/publish to all topics.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Disable Anonymous Access:**  Explicitly set `allow_anonymous false` in `mosquitto.conf`.
    *   **Require Authentication:** Enforce username/password or client certificate authentication.

## Attack Surface: [Unencrypted Communication (Plaintext MQTT)](./attack_surfaces/unencrypted_communication__plaintext_mqtt_.md)

*   **Description:**  Data transmitted without TLS encryption.
*   **Mosquitto Contribution:** Mosquitto *supports* both encrypted and unencrypted listeners.  The configuration determines which are active.  The presence of an active `listener 1883` without TLS is the direct vulnerability.
*   **Example:**  An attacker captures network traffic and sees MQTT messages in plain text.
*   **Impact:**  Complete data exposure; eavesdropping and potential Man-in-the-Middle attacks.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Disable Plaintext Listener:**  Comment out or remove any `listener 1883` (or any unencrypted listener) configuration in `mosquitto.conf`.
    *   **Enable and Enforce TLS:** Configure a `listener 8883` with a valid certificate and key.  Ensure clients use TLS.

## Attack Surface: [Weak Authentication/Authorization](./attack_surfaces/weak_authenticationauthorization.md)

*   **Description:**  Easily guessable passwords, default credentials, or overly permissive Access Control Lists (ACLs).
*   **Mosquitto Contribution:** Mosquitto's authentication mechanisms (password file, plugins) and its ACL system (`acl_file` or plugin-based ACLs) are the *direct* points of vulnerability if misconfigured.
*   **Example:**  An attacker brute-forces a weak password, or an ACL grants a client excessive topic access.
*   **Impact:**  Unauthorized access; the extent depends on the compromised client's privileges and the ACL configuration.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Strong Passwords:** Enforce strong password policies.
    *   **Secure Authentication:** Use robust authentication methods (database, LDAP, or a well-vetted plugin).  Avoid the default password file if possible.
    *   **Principle of Least Privilege (ACLs):**  Meticulously configure ACLs to grant *only* the necessary topic access to each client.  Regularly audit ACLs.

## Attack Surface: [Denial-of-Service (DoS) - Mosquitto-Specific](./attack_surfaces/denial-of-service__dos__-_mosquitto-specific.md)

*   **Description:** Attacks targeting Mosquitto's resource handling to make it unavailable.  This focuses on attacks exploiting Mosquitto's *internal* handling, not general network floods.
*   **Mosquitto Contribution:** Mosquitto's internal handling of connections, message queues, and memory allocation can be targeted.  Specific configuration options like `max_connections`, `max_queued_messages`, and `memory_limit` (if available) directly influence susceptibility.
*   **Example:** An attacker sends a large number of connection requests *within the limits of a general network flood*, but crafted to exploit how Mosquitto handles connection establishment internally.  Or, they send many small, persistent connections to exhaust file descriptors.
*   **Impact:** Broker unavailability; legitimate clients cannot connect or communicate.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Connection Limits:** Use `max_connections` in `mosquitto.conf` appropriately.
    *   **Mosquitto-Specific Rate Limiting:** If available (through `per_listener_settings` or plugins), implement rate limiting *specifically within Mosquitto* to control message frequency per client.  This is distinct from general network rate limiting.
    *   **Resource Limits (Mosquitto-Specific):** If Mosquitto provides options like `memory_limit` or similar resource controls, use them judiciously.
    *   **Keep Updated:**  Newer Mosquitto versions often include performance and robustness improvements that mitigate DoS vectors.

