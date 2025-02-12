# Mitigation Strategies Analysis for greenrobot/eventbus

## Mitigation Strategy: [Strict Event Type Hierarchy and Validation](./mitigation_strategies/strict_event_type_hierarchy_and_validation.md)

**1. Mitigation Strategy: Strict Event Type Hierarchy and Validation**

*   **Description:**
    1.  **Define a Base Event Class:** Create an abstract base class (e.g., `BaseEvent`) for all events.
    2.  **Create Specific Event Subclasses:**  Create distinct subclasses of `BaseEvent` for each event type (e.g., `UserLoginEvent`, `DataUpdatedEvent`).
    3.  **Use `instanceof` Checks:** In *every* subscriber's `@Subscribe` method, *always* check the event type using `instanceof` *before* processing.  This leverages EventBus's type filtering but adds a crucial extra layer of defense.
    4.  **Handle Unexpected Types:**  Log, throw an exception, or ignore unexpected event types. *Never* process them.

*   **Threats Mitigated:**
    *   **Unauthorized Event Posting (Spoofing):** (Severity: High) - Prevents processing of incorrectly typed events, even if they are posted to the bus.
    *   **Event Modification (Tampering):** (Severity: Medium) - Indirectly helps by ensuring only validated types are processed.
    *   **Denial of Service (DoS) via Event Flooding:** (Severity: Low) - Malformed events are rejected early.

*   **Impact:**
    *   **Unauthorized Event Posting (Spoofing):** Risk significantly reduced.
    *   **Event Modification (Tampering):** Risk slightly reduced (type safety).
    *   **Denial of Service (DoS):** Risk slightly reduced.

*   **Currently Implemented:**
    *   Partially. `BaseEvent` exists, most subscribers use `instanceof`, but `NetworkManager.java` is missing the check in `onNetworkStatusEvent`.

*   **Missing Implementation:**
    *   `NetworkManager.java`: Add `instanceof` check to `onNetworkStatusEvent`.
    *   Review all subscribers for consistency.

## Mitigation Strategy: [Use of Custom EventBus Instances](./mitigation_strategies/use_of_custom_eventbus_instances.md)

**2. Mitigation Strategy: Use of Custom EventBus Instances**

*   **Description:**
    1.  **Identify Security Contexts:**  Determine distinct security contexts (e.g., UI, background, secure operations).
    2.  **Create Separate Instances:** Create separate `EventBus` instances for each context (e.g., `uiBus = new EventBus();`, `secureBus = new EventBus();`).
    3.  **Register Subscribers Appropriately:** Register subscribers *only* to the relevant `EventBus` instance.
    4.  **Post Events to the Correct Instance:**  When posting, use the *correct* `EventBus` instance.

*   **Threats Mitigated:**
    *   **Unauthorized Event Subscription (Eavesdropping):** (Severity: Medium) - Isolates events, limiting eavesdropping scope.
    *   **Unauthorized Event Posting (Spoofing):** (Severity: Medium) - Prevents cross-context interference.

*   **Impact:**
    *   **Unauthorized Event Subscription (Eavesdropping):** Risk reduced (compartmentalization).
    *   **Unauthorized Event Posting (Spoofing):** Risk reduced (limits impact).

*   **Currently Implemented:**
    *   Not implemented.  We use `EventBus.getDefault()` everywhere.

*   **Missing Implementation:**
    *   Create separate `EventBus` instances (UI, background, secure).
    *   Refactor code to use the correct instances for registration and posting.

## Mitigation Strategy: [Asynchronous Event Handling (Thread Pools)](./mitigation_strategies/asynchronous_event_handling__thread_pools_.md)

**3. Mitigation Strategy: Asynchronous Event Handling (Thread Pools)**

*   **Description:**
    1.  **Use `@Subscribe(threadMode = ThreadMode.ASYNC)`:**  Annotate subscriber methods that are *not* UI-related and might be long-running with `@Subscribe(threadMode = ThreadMode.ASYNC)`. This directly utilizes EventBus's threading mechanism.
    2. **Configure Thread Pool (Rarely Needed):** EventBus manages its thread pool; custom configuration is usually unnecessary.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) via Event Flooding:** (Severity: Medium) - Prevents main thread blocking.

*   **Impact:**
    *   **Denial of Service (DoS):** Risk reduced (offloads processing).

*   **Currently Implemented:**
    *   Partially. Some subscribers use `ThreadMode.ASYNC`, but it's inconsistent.

*   **Missing Implementation:**
    *   Identify subscribers doing I/O, network requests, or blocking tasks.
    *   Ensure they use `ThreadMode.ASYNC`.

## Mitigation Strategy: [Restricted Event Visibility (Sticky Events)](./mitigation_strategies/restricted_event_visibility__sticky_events_.md)

**4. Mitigation Strategy: Restricted Event Visibility (Sticky Events)**
* **Description:**
    1. **Minimize Sticky Event Usage:** Avoid using sticky events (`postSticky`) unless absolutely necessary.
    2. **Prompt Removal:** If sticky events *must* be used, remove them *immediately* after they are no longer needed using `removeStickyEvent()`. This is a direct interaction with the EventBus API.
    3. **Consider Alternatives:** Explore alternatives like direct communication or other data-sharing methods.

* **Threats Mitigated:**
    * **Unauthorized Event Subscription (Eavesdropping):** (Severity: Medium) - Reduces the window of opportunity for unintended subscribers to receive sticky events.

* **Impact:**
    * **Unauthorized Event Subscription (Eavesdropping):** Risk reduced by limiting the persistence of sensitive events.

* **Currently Implemented:**
    * Partially implemented. Sticky events are used, but removal is not always immediate.

* **Missing Implementation:**
    * Review all uses of `postSticky`.
    * Ensure `removeStickyEvent` is called promptly after the event is no longer needed.
    * Consider replacing sticky events with alternatives where possible.


