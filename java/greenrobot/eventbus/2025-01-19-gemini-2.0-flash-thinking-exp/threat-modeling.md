# Threat Model Analysis for greenrobot/eventbus

## Threat: [Malicious Event Publication](./threats/malicious_event_publication.md)

**Description:** An attacker, having compromised a component with the ability to publish events, could craft and publish malicious event objects using `EventBus.getDefault().post(event)`. These events could contain unexpected data, trigger unintended actions in subscribers, or exploit vulnerabilities in event handlers.

**How:** The attacker might exploit a vulnerability in a publisher component to gain control and use the `EventBus.getDefault().post(event)` method to send malicious events.

**Impact:** Data corruption, unauthorized state changes, bypassing security checks, triggering other vulnerabilities within the subscribing components, or causing denial of service by flooding the event bus with malicious events.

**Affected EventBus Component:** `EventBus.getDefault().post(event)` method.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement robust input validation in event handlers to check the integrity and expected format of event data.
* Enforce authorization checks before subscribers perform critical actions based on received events.
* Secure publisher components to prevent them from being compromised.
* Consider implementing a mechanism to verify the source or authenticity of events (though this is not a built-in feature of EventBus).

## Threat: [Unintended Event Reception by Malicious Subscriber](./threats/unintended_event_reception_by_malicious_subscriber.md)

**Description:** An attacker could introduce a malicious component that registers as a subscriber using `EventBus.getDefault().register(subscriber)` to various event types, including those containing sensitive information. This allows the attacker to eavesdrop on application activity and potentially exfiltrate sensitive data.

**How:** The attacker might inject a malicious component into the application and use `EventBus.getDefault().register(subscriber)` to subscribe to relevant events.

**Impact:** Disclosure of sensitive data, including user information, internal application state, or business logic.

**Affected EventBus Component:** `EventBus.getDefault().register(subscriber)` method and the event delivery mechanism within EventBus.

**Risk Severity:** High

**Mitigation Strategies:**
* Design event types to be as specific as possible to minimize the risk of unintended recipients.
* Implement access controls or authorization mechanisms for registering subscribers, if feasible within the application's architecture.
* Regularly review registered subscribers and remove any suspicious or unauthorized ones.
* Consider using more fine-grained event bus implementations or patterns if strict access control is required.

## Threat: [Exploiting Sticky Events for Information Disclosure](./threats/exploiting_sticky_events_for_information_disclosure.md)

**Description:** An attacker could register a subscriber after a sensitive sticky event has been posted using `EventBus.getDefault().postSticky(event)`. The attacker's subscriber would then receive this sticky event, potentially gaining access to information it should not have.

**How:** The attacker might inject a malicious component and register it after a sensitive sticky event has been published using `EventBus.getDefault().postSticky(event)`. The newly registered component will automatically receive this sticky event.

**Impact:** Disclosure of sensitive information that was intended for a specific point in time or a limited set of subscribers.

**Affected EventBus Component:** `EventBus.getDefault().postSticky(event)` and the sticky event storage mechanism within EventBus.

**Risk Severity:** High

**Mitigation Strategies:**
* Avoid storing highly sensitive information in sticky events.
* Carefully consider the lifecycle and potential recipients of sticky events.
* If sensitive data must be conveyed via sticky events, clear them promptly after their intended use with `EventBus.getDefault().removeStickyEvent(event)`.
* Implement checks within subscribers to validate the context and relevance of received sticky events.

