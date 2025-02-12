# Threat Model Analysis for greenrobot/eventbus

## Threat: [Malicious Event Injection (Spoofing)](./threats/malicious_event_injection__spoofing_.md)

*   **Threat:** Malicious Event Injection (Spoofing)

    *   **Description:** An attacker crafts and posts a fraudulent event to the EventBus.  The attacker leverages the `post()` method to inject an event that mimics a legitimate one, but with malicious data or intent.  This bypasses intended application flow by directly interacting with the EventBus mechanism. The attacker needs a way to call `EventBus.post()`, which could be through a compromised component, or another vulnerability.
    *   **Impact:**  Unintended actions are triggered in subscribers, leading to:
        *   Unauthorized access to resources or functionality.
        *   Bypassing security checks (e.g., payment processing, authentication).
        *   Data corruption or modification.
    *   **Affected Component:**
        *   `EventBus.post()`: This is the *direct* point of attack. The attacker uses this method to inject the malicious event.
        *   Subscribers (`@Subscribe` annotated methods):  Subscribers that do not adequately validate the incoming event data are indirectly affected.
    *   **Risk Severity:** Critical to High (depending on the specific event and subscriber logic).
    *   **Mitigation Strategies:**
        *   **Strict Event Validation:** Within each subscriber, *before* any action, rigorously validate the event. Use specific event classes. Check data types, ranges, and formats.
        *   **Use Custom Event Classes:** Define specific event classes for each type of event. This provides a clear contract and makes validation easier.
        *   **Sender Verification (Limited/Indirect):** While not a direct EventBus feature, if possible, add a non-sensitive identifier to events to help subscribers identify the *intended* source. This is *not* a replacement for input validation.

## Threat: [Event Sniffing (Information Disclosure)](./threats/event_sniffing__information_disclosure_.md)

*   **Threat:** Event Sniffing (Information Disclosure)

    *   **Description:** An attacker registers a malicious subscriber to the EventBus using `EventBus.register()`.  They intentionally subscribe to events they should not have access to, aiming to intercept and collect sensitive data transmitted through those events. This is a direct attack on the EventBus's subscription mechanism.
    *   **Impact:**  Leakage of sensitive data, such as:
        *   Internal application state.
        *   PII (Personally Identifiable Information).
        *   Business-sensitive data.
    *   **Affected Component:**
        *   `EventBus.register()`: This is the *direct* point of attack. The attacker uses this method to register their malicious subscriber.
        *   `@Subscribe` annotated methods: The attacker's malicious subscriber method.
    *   **Risk Severity:** High to Critical (depending on the sensitivity of the disclosed information).
    *   **Mitigation Strategies:**
        *   **Restricted Subscriber Registration:**  Do *not* use a single, global EventBus instance for all events.
        *   **Multiple EventBus Instances:** Create separate EventBus instances for different security contexts or modules (e.g., UI, authentication, background). This is a *direct* mitigation against unauthorized subscriptions.
        *   **Access Control in Subscribers (Indirect):** Within each subscriber, perform an access control check *before* processing. This is a defense-in-depth measure, but the primary mitigation is controlling registration.
        *   **Avoid Sensitive Data in Events:**  *Never* include sensitive data directly in event payloads. Pass identifiers or references instead. This minimizes the impact of sniffing.

