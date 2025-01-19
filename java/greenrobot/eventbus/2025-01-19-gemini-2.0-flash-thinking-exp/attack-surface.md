# Attack Surface Analysis for greenrobot/eventbus

## Attack Surface: [Malicious Event Injection](./attack_surfaces/malicious_event_injection.md)

**Description:** An attacker gains the ability to post arbitrary, crafted events onto the EventBus.

**How EventBus Contributes:** EventBus provides a global, accessible mechanism (`EventBus.getDefault().post()`) for publishing events. This inherent functionality allows for the propagation of any event object passed to it, regardless of its origin or malicious intent, if access to the posting mechanism is not controlled.

**Example:** A vulnerable component allows an attacker to influence the data used in a call to `EventBus.getDefault().post()`, injecting a malicious event that triggers unintended actions in subscribers.

**Impact:** Can lead to unauthorized state changes, execution of malicious code within subscribers, data manipulation, or triggering unintended application behavior.

**Risk Severity:** High

**Mitigation Strategies:**
* **Developer:**
    * Enforce strict access controls on components that can directly call `EventBus.getDefault().post()`. Limit posting capabilities to authorized modules.
    * Design event structures to minimize the risk of malicious payloads.

## Attack Surface: [Malicious Subscriber Registration](./attack_surfaces/malicious_subscriber_registration.md)

**Description:** An attacker registers a malicious subscriber to intercept and potentially manipulate events.

**How EventBus Contributes:** EventBus allows any component with access to the `EventBus` instance to register as a subscriber using methods like `register()`. This open registration mechanism, if not properly secured, allows attackers to inject malicious listeners.

**Example:** A vulnerability allows an attacker to execute code that calls `EventBus.getDefault().register(maliciousSubscriber)`, enabling the attacker to intercept sensitive data from subsequent events.

**Impact:** Information disclosure, data theft, manipulation of application state by intercepting and potentially modifying events before they reach legitimate subscribers.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Developer:**
    * Restrict access to the `EventBus` instance and the registration methods (`register()`, `register(Object subscriber, int priority)`).
    * Implement secure subscriber registration mechanisms, potentially requiring authentication or authorization before allowing registration.

## Attack Surface: [Exploiting Sticky Events](./attack_surfaces/exploiting_sticky_events.md)

**Description:** An attacker posts a malicious sticky event that affects subsequent legitimate subscribers.

**How EventBus Contributes:** EventBus's sticky event feature retains events and delivers them to new subscribers upon registration using methods like `register(Object subscriber)`. This persistence allows attackers to inject malicious state that will automatically affect future components.

**Example:** An attacker with the ability to post events calls `EventBus.getDefault().postSticky(maliciousEvent)`. A legitimate component registering later receives this malicious sticky event and acts upon it, leading to compromise.

**Impact:** Persistent attacks affecting new components, potential for widespread misconfiguration or compromise, exposure of sensitive information stored in sticky events.

**Risk Severity:** High

**Mitigation Strategies:**
* **Developer:**
    * Exercise extreme caution when using sticky events. Avoid storing sensitive or critical data in them.
    * Implement mechanisms to clear or update sticky events when they are no longer needed or when application state changes using methods like `removeStickyEvent(Object event)`.

## Attack Surface: [Information Disclosure through Event Content](./attack_surfaces/information_disclosure_through_event_content.md)

**Description:** Sensitive information is included in event objects, and an attacker can register a subscriber to access this information.

**How EventBus Contributes:** EventBus broadcasts event data to all registered subscribers for a specific event type. This inherent broadcasting mechanism makes any data within the event accessible to all listeners, including potentially malicious ones if registration is compromised.

**Example:** An event object containing user credentials is posted using `EventBus.getDefault().post()`. An attacker who has managed to register a subscriber receives this event and gains access to the credentials.

**Impact:** Unauthorized access to sensitive data, potential for further attacks using the disclosed information.

**Risk Severity:** High

**Mitigation Strategies:**
* **Developer:**
    * Avoid including sensitive information directly in event objects that are broadcasted via EventBus.
    * If sensitive information must be conveyed, use secure methods outside of EventBus.

