# Attack Surface Analysis for ruby-concurrency/concurrent-ruby

## Attack Surface: [Unbounded Task Queues in Thread Pools/Executors](./attack_surfaces/unbounded_task_queues_in_thread_poolsexecutors.md)

**Description:** Thread pools or executors configured with unbounded queues can accumulate an unlimited number of pending tasks.

* **How Concurrent Ruby Contributes:** `concurrent-ruby` provides mechanisms for creating and configuring thread pools and executors. If developers don't set limits on the queue size, it defaults to unbounded.
* **Example:** A malicious user or a compromised system floods the application with numerous requests that create tasks for the thread pool. The unbounded queue grows indefinitely, consuming excessive memory.
* **Impact:** Denial of Service (DoS) due to memory exhaustion, application slowdown, and potential crashes.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Set Maximum Queue Size: Configure thread pools and executors with a reasonable maximum queue size using options like `max_queue`.
    * Implement Backpressure: Introduce mechanisms to limit the rate at which tasks are submitted to the executor, preventing queue overflow.
    * Monitor Queue Length: Implement monitoring to track the queue length and trigger alerts if it exceeds a threshold.

## Attack Surface: [Actor Mailbox Flooding](./attack_surfaces/actor_mailbox_flooding.md)

**Description:** An attacker sends a large number of messages to a specific actor, overwhelming its mailbox and processing capabilities.

* **How Concurrent Ruby Contributes:** `concurrent-ruby` provides the `Actor` model, which relies on message passing. If an actor's mailbox is not protected, it can be flooded.
* **Example:** A malicious actor repeatedly sends messages to a critical actor responsible for processing user requests. The actor becomes unresponsive, and the application's functionality is impaired.
* **Impact:** Denial of Service (DoS) for specific functionalities handled by the targeted actor, potential resource exhaustion on the actor's thread.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Implement Mailbox Limits: Configure actors with a maximum mailbox size to prevent unbounded growth.
    * Message Throttling/Rate Limiting: Implement mechanisms to limit the rate at which messages are accepted by an actor, potentially based on the sender.
    * Message Prioritization: If appropriate, prioritize important messages to ensure they are processed even under load.

## Attack Surface: [Malicious Callbacks in Futures/Promises](./attack_surfaces/malicious_callbacks_in_futurespromises.md)

**Description:** If the application allows users to provide callbacks that are executed within the context of futures or promises, a malicious actor could inject harmful code.

* **How Concurrent Ruby Contributes:** `concurrent-ruby`'s `Future` and `Promise` objects allow attaching callbacks (e.g., using `then`, `rescue`). If these callbacks are derived from untrusted sources, it introduces risk.
* **Example:** An attacker manipulates input that is used to define a callback function for a promise. This callback, when executed, could perform actions like accessing sensitive data or executing arbitrary commands.
* **Impact:** Remote Code Execution (RCE), information disclosure, data manipulation, depending on the capabilities of the injected callback.
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * Avoid Accepting Arbitrary Code as Callbacks: Do not allow users to directly define or provide arbitrary code for callbacks.
    * Use Predefined, Safe Callbacks: Offer a limited set of predefined, safe callback functions that the application controls.
    * Sanitize and Validate Data Passed to Callbacks: If user-provided data is used within callbacks, rigorously sanitize and validate it to prevent injection attacks.

## Attack Surface: [Resource Exhaustion via Excessive Future/Promise Creation](./attack_surfaces/resource_exhaustion_via_excessive_futurepromise_creation.md)

**Description:** Creating a very large number of futures or promises, even if they don't have malicious callbacks, can consume significant system resources.

* **How Concurrent Ruby Contributes:** `concurrent-ruby` provides the `Future` and `Promise` constructs. Improper usage or malicious intent can lead to excessive creation.
* **Example:** An attacker repeatedly triggers actions that create numerous futures or promises that are never properly resolved or garbage collected, leading to memory leaks and eventual application instability.
* **Impact:** Denial of Service (DoS) due to memory exhaustion, application slowdown, and potential crashes.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Limit the Number of Concurrent Operations: Implement controls to limit the number of concurrent operations that can create futures or promises.
    * Properly Manage Future/Promise Lifecycles: Ensure that futures and promises are eventually resolved or cancelled to allow for resource cleanup.
    * Monitor Resource Usage: Track the number of active futures and promises to detect potential abuse.

