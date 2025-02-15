# Mitigation Strategies Analysis for matrix-org/synapse

## Mitigation Strategy: [Federation Domain Whitelisting/Blacklisting](./mitigation_strategies/federation_domain_whitelistingblacklisting.md)

*   **Mitigation Strategy:** Federation Domain Whitelisting/Blacklisting

    *   **Description:**
        1.  **Identify Trusted Servers:** Identify known, trusted Matrix homeservers.
        2.  **Configure `federation_domain_whitelist`:** In `homeserver.yaml`, add trusted server domains to the `federation_domain_whitelist` list. Each domain on a new line.
        3.  **Configure `federation_domain_blacklist` (Optional):** Add domains of known malicious servers to `federation_domain_blacklist` in `homeserver.yaml`.
        4.  **Restart Synapse:** Restart Synapse for changes to take effect.
        5.  **Monitor and Refine:** Regularly monitor server logs and federation traffic. Adjust lists as needed.

    *   **Threats Mitigated:**
        *   **Malicious Federated Servers (Severity: High):** Reduces interaction with known malicious servers.
        *   **Compromised Federated Servers (Severity: High):** Limits damage from a compromised server.
        *   **Federation-Based DoS Attacks (Severity: Medium):** Reduces the attack surface.

    *   **Impact:**
        *   **Malicious Federated Servers:** Significant reduction (80-90%).
        *   **Compromised Federated Servers:** Reduces risk (60-70%).
        *   **Federation-Based DoS Attacks:** Moderate reduction (30-40%).

    *   **Currently Implemented:** (Hypothetical) Partially. Basic `federation_domain_whitelist` exists, but isn't regularly updated. No `federation_domain_blacklist`. Config in `/etc/synapse/homeserver.yaml`.

    *   **Missing Implementation:** (Hypothetical)
        *   No formal review/update process for the whitelist.
        *   No blacklist.
        *   Insufficient federation traffic monitoring.

## Mitigation Strategy: [Federation Rate Limiting](./mitigation_strategies/federation_rate_limiting.md)

*   **Mitigation Strategy:** Federation Rate Limiting

    *   **Description:**
        1.  **Understand Parameters:** Familiarize yourself with Synapse's federation rate limiting parameters in `homeserver.yaml`: `federation_rc_window_size`, `federation_rc_sleep_limit`, `federation_rc_sleep_delay`, `federation_rc_reject_limit`, `federation_rc_concurrent`.
        2.  **Baseline Traffic:** Monitor normal federation traffic to establish a baseline.
        3.  **Configure Parameters:** Adjust parameters in `homeserver.yaml` based on baseline and desired protection. Start conservatively.
        4.  **Restart Synapse:** Restart Synapse.
        5.  **Monitor and Tune:** Continuously monitor effectiveness and adjust.

    *   **Threats Mitigated:**
        *   **Federation-Based DoS Attacks (Severity: High):** Directly mitigates by limiting request rates.
        *   **Resource Exhaustion (Severity: Medium):** Prevents a server from consuming excessive resources.
        *   **Spam from Federated Servers (Severity: Medium):** Can help reduce spam volume.

    *   **Impact:**
        *   **Federation-Based DoS Attacks:** Significant reduction (70-80%).
        *   **Resource Exhaustion:** High impact (80-90%).
        *   **Spam from Federated Servers:** Moderate impact (40-50%).

    *   **Currently Implemented:** (Hypothetical) Partially. Default values are in place, but not tuned. Config in `/etc/synapse/homeserver.yaml`.

    *   **Missing Implementation:** (Hypothetical)
        *   No baseline traffic analysis.
        *   Insufficient monitoring of effectiveness.

## Mitigation Strategy: [Room Moderation and Permissions (Synapse-Native)](./mitigation_strategies/room_moderation_and_permissions__synapse-native_.md)

*   **Mitigation Strategy:** Room Moderation and Permissions (Synapse-Native)

    *   **Description:**
        1.  **Default Room Permissions:** Configure sensible default room permissions in `homeserver.yaml`. Restrict who can send messages in new rooms, for example.
        2. **Room-Specific Permissions (via Synapse Admin API or Clients):** Use Synapse Admin API or clients supporting room permission management to:
            * Set `m.room.power_levels`: Define power levels for user roles.
            * Set `m.room.join_rules`: Control how users join (invite-only, public).
            * Set `events_default`: Default power level to send messages.
            * Set `invite`: Power level to invite users.
        3. **Use Synapse Admin API for Moderation:** Utilize the Synapse Admin API for tasks like:
            * Kicking/banning users.
            * Deleting messages.
            * Shutting down rooms.
            * Querying room state.

    *   **Threats Mitigated:**
        *   **Spam and Abuse in Rooms (Severity: High):** Empowers moderators.
        *   **Illegal Content in Rooms (Severity: High):** Reduces distribution.
        *   **Room Hijacking (Severity: Medium):** Permissions prevent unauthorized control.
        *   **Unmanageable Large Rooms (Severity: Medium):** Moderation helps control.

    *   **Impact:**
        *   **Spam and Abuse in Rooms:** High impact (70-80%) with active moderation.
        *   **Illegal Content in Rooms:** High impact (70-80%).
        *   **Room Hijacking:** Moderate impact (50-60%).
        *   **Unmanageable Large Rooms:** Moderate impact (40-50%).

    *   **Currently Implemented:** (Hypothetical) Partially. Basic permissions are in place, some moderators active.

    *   **Missing Implementation:** (Hypothetical)
        *   Inconsistent application of room permissions.
        *   Full utilization of the Synapse Admin API for moderation is not standardized.

## Mitigation Strategy: [Media Repository Restrictions (Synapse-Native)](./mitigation_strategies/media_repository_restrictions__synapse-native_.md)

*   **Mitigation Strategy:** Media Repository Restrictions (Synapse-Native)

    *   **Description:**
        1.  **Set `max_upload_size`:** In `homeserver.yaml`, configure `max_upload_size` to limit upload sizes.
        2.  **Configure `allowed_mimetypes` and `blocked_mimetypes`:** Use these in `homeserver.yaml` to control allowed/blocked file types. Restrict executables.
        3. **Restart Synapse:** Restart for changes to take effect.

    *   **Threats Mitigated:**
        *   **Malicious File Uploads (Severity: High):** Reduces malware uploads.
        *   **Media Repository DoS Attacks (Severity: Medium):** Size limits help.
        *   **Storage Exhaustion (Severity: Medium):** Size limits prevent excessive storage use.

    *   **Impact:**
        *   **Malicious File Uploads:** Moderate impact (50-60%, higher with external scanning).
        *   **Media Repository DoS Attacks:** Moderate impact (40-50%).
        *   **Storage Exhaustion:** High impact (90-100%).

    *   **Currently Implemented:** (Hypothetical) Partially. `max_upload_size` is set, but MIME types are not restricted.

    *   **Missing Implementation:** (Hypothetical)
        *   MIME type restrictions are not enforced.

## Mitigation Strategy: [Secure Application Service (AS) Management (Synapse-Native)](./mitigation_strategies/secure_application_service__as__management__synapse-native_.md)

*   **Mitigation Strategy:** Secure Application Service (AS) Management (Synapse-Native)

    *   **Description:**
        1.  **Strict Registration:** Require approval for AS registrations.
        2.  **Strong Authentication:** Use unique tokens and TLS for AS connections (configured in AS registration file).
        3.  **Namespace Restrictions:** Define user ID and room alias namespaces each AS controls (in AS registration file).  Prevents impersonation.
        4. **Monitor AS Activity:** Use Synapse's logs and metrics to watch for suspicious AS behavior.

    *   **Threats Mitigated:**
        *   **Malicious Application Services (Severity: High):** Reduces risk.
        *   **Compromised Application Services (Severity: High):** Limits damage.
        *   **Impersonation Attacks (Severity: Medium):** Namespace restrictions prevent.

    *   **Impact:**
        *   **Malicious Application Services:** High impact (80-90%).
        *   **Compromised Application Services:** High impact (70-80%).
        *   **Impersonation Attacks:** High impact (90-100%).

    *   **Currently Implemented:** (Hypothetical) Partially. Registration requires approval, but the process isn't rigorous. Namespace restrictions exist, but aren't always enforced.

    *   **Missing Implementation:** (Hypothetical)
        *   No formal, documented AS approval process.
        *   Inconsistent namespace restriction enforcement.
        *   Insufficient AS activity monitoring.

## Mitigation Strategy: [Push Notification Content Control (Synapse-Native)](./mitigation_strategies/push_notification_content_control__synapse-native_.md)

* **Mitigation Strategy:** Push Notification Content Control (Synapse-Native)

    * **Description:**
        1. **Configure `push.pusher_implementation`:**  In `homeserver.yaml`, review the settings under the `push` section, specifically `push.pusher_implementation`.
        2. **Set `template`:**  Within the `push` configuration, use the `template` setting to control the level of detail in push notifications.  Choose `low_detail` or `no_content` to minimize sensitive information. Example:
           ```yaml
           push:
             pusher_implementation: "simple"
             template: "low_detail"
           ```
        3. **Restart Synapse:** Restart for changes to take effect.

    * **Threats Mitigated:**
        * **Sensitive Information Leakage via Push (Severity: Medium):** Reduces the amount of sensitive data exposed in push notifications.

    * **Impact:**
        * **Sensitive Information Leakage via Push:** High impact (70-80% reduction) when using `low_detail` or `no_content`.

    * **Currently Implemented:** (Hypothetical) Partially implemented. The default `simple` pusher is used, but the `template` setting is not explicitly configured for low detail.

    * **Missing Implementation:** (Hypothetical)
        * Explicit configuration of the `template` setting to `low_detail` or `no_content` is missing.

