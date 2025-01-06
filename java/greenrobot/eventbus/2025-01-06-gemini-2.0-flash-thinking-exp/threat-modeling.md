# Threat Model Analysis for greenrobot/eventbus

## Threat: [Exposure of Sensitive Data via Sticky Events](./threats/exposure_of_sensitive_data_via_sticky_events.md)

*   **Description:** If a sticky event contains sensitive information, a newly registered component (even one that shouldn't have access) will immediately receive this information upon registration. An attacker could exploit this by registering a malicious component or by compromising an existing component and registering it to receive sensitive sticky events.
*   **Impact:** Unintended exposure of sensitive data to unauthorized components, potentially leading to data breaches or further exploitation.
*   **Affected Component:** Sticky Event functionality within EventBus.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Avoid using sticky events for transmitting highly sensitive information.
    *   If sticky events are necessary for sensitive data, implement strict authorization checks within the subscribers that handle these events.
    *   Carefully consider the lifecycle and accessibility of sticky events.

## Threat: [Denial of Service via Event Flooding](./threats/denial_of_service_via_event_flooding.md)

*   **Description:** An attacker could publish a large number of events rapidly, overwhelming the EventBus and its subscribers. This could be achieved by exploiting a vulnerability in a publishing component or by gaining control of a legitimate publisher.
*   **Impact:** Performance degradation, application unresponsiveness, or even crashes due to resource exhaustion in the EventBus or subscribing components. This can lead to service disruption and impact user experience.
*   **Affected Component:** EventBus instance.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement rate limiting or throttling mechanisms on event publication.
    *   Implement safeguards in subscribers to prevent them from being overwhelmed by a large number of events.
    *   Monitor event traffic for anomalies that might indicate an event flooding attack.

