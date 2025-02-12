# Attack Tree Analysis for lmax-exchange/disruptor

Objective: DoS or Data Corruption via Disruptor Exploitation

## Attack Tree Visualization

Goal: DoS or Data Corruption via Disruptor Exploitation
├── 1. Disruptor Configuration Attacks [HIGH RISK]
│   ├── 1.1.  Inadequate Wait Strategy Configuration [HIGH RISK]
│   │   └── 1.1.1.  Exploit BusySpinWaitStrategy (CPU Exhaustion) [CRITICAL]
│   ├── 1.2.  Insufficient Ring Buffer Size [CRITICAL]
│   ├── 1.3.  Improper ProducerType (Single vs. Multi) [CRITICAL]
│   └── 1.4.  Weak Exception Handling in Event Handlers [HIGH RISK][CRITICAL]
└── 2. Disruptor Data Manipulation Attacks
    └── 2.2.  Event Data Corruption (via Shared Mutable Objects) [HIGH RISK][CRITICAL]

## Attack Tree Path: [1. Disruptor Configuration Attacks [HIGH RISK]](./attack_tree_paths/1__disruptor_configuration_attacks__high_risk_.md)

*   **General Description:** This category encompasses attacks that exploit misconfigurations of the Disruptor itself. Incorrect settings can lead to resource exhaustion, denial of service, or even data corruption.

## Attack Tree Path: [1.1. Inadequate Wait Strategy Configuration [HIGH RISK]](./attack_tree_paths/1_1__inadequate_wait_strategy_configuration__high_risk_.md)

*   **General Description:** The `WaitStrategy` determines how consumers wait for events.  An inappropriate choice can lead to excessive CPU usage or deadlocks.

## Attack Tree Path: [1.1.1. Exploit BusySpinWaitStrategy (CPU Exhaustion) [CRITICAL]](./attack_tree_paths/1_1_1__exploit_busyspinwaitstrategy__cpu_exhaustion___critical_.md)

*   **Action:** An attacker floods the Disruptor with events at a rate faster than the consumers can process them. Because `BusySpinWaitStrategy` continuously polls for new events without yielding, this leads to 100% CPU utilization on the consumer threads.
*   **Likelihood:** Medium (If `BusySpinWaitStrategy` is used, which is discouraged).
*   **Impact:** High (DoS, system unresponsiveness).
*   **Effort:** Low.
*   **Skill Level:** Novice.
*   **Detection Difficulty:** Easy (High CPU usage is easily observable).
*   **Mitigation:** Avoid using `BusySpinWaitStrategy` unless absolutely necessary and the performance implications are fully understood. Use `BlockingWaitStrategy`, `TimeoutBlockingWaitStrategy`, or `YieldingWaitStrategy` instead, with careful consideration of their trade-offs.

## Attack Tree Path: [1.2. Insufficient Ring Buffer Size [CRITICAL]](./attack_tree_paths/1_2__insufficient_ring_buffer_size__critical_.md)

*   **Action:** An attacker sends a burst of events that exceeds the capacity of the ring buffer.  This causes producers to either block (if using a blocking wait strategy) or throw exceptions (if configured to do so), leading to a denial of service.
*   **Likelihood:** Medium (If the buffer size is not adequately provisioned for peak loads).
*   **Impact:** High (DoS, producer blocking or exceptions).
*   **Effort:** Low.
*   **Skill Level:** Novice.
*   **Detection Difficulty:** Easy (Monitoring the remaining capacity of the ring buffer reveals the issue).
*   **Mitigation:** Choose a ring buffer size that is large enough to handle expected bursts of events without blocking producers, but not so large that it wastes memory. Monitor the remaining capacity at runtime.

## Attack Tree Path: [1.3. Improper ProducerType (Single vs. Multi) [CRITICAL]](./attack_tree_paths/1_3__improper_producertype__single_vs__multi___critical_.md)

*   **Action:** The application is configured to use `ProducerType.SINGLE` (indicating that only one thread will publish events), but in reality, multiple threads *are* publishing. This creates race conditions on the sequence counter, leading to potential data corruption or out-of-order processing.
*   **Likelihood:** Low (Requires a specific coding error).
*   **Impact:** High (Data corruption, unpredictable behavior).
*   **Effort:** Very Low (This is typically an accidental misconfiguration, not a deliberate exploit).
*   **Skill Level:** Novice.
*   **Detection Difficulty:** Hard (Data corruption may be subtle and difficult to trace back to the root cause).
*   **Mitigation:** Ensure that `ProducerType.MULTI` is used if multiple threads will be publishing to the Disruptor. Use `ProducerType.SINGLE` *only* if you are absolutely certain that only one thread will ever publish. Thorough code reviews are essential.

## Attack Tree Path: [1.4. Weak Exception Handling in Event Handlers [HIGH RISK][CRITICAL]](./attack_tree_paths/1_4__weak_exception_handling_in_event_handlers__high_risk__critical_.md)

*   **Action:** An attacker crafts malicious events that, when processed by the event handlers, trigger unhandled exceptions. If the exception handling strategy is not robust (e.g., the default `IgnoreExceptionHandler`), this can cause the consumer thread to terminate, leading to a denial of service.
*   **Likelihood:** Medium (If exception handling is not robust or if event handlers have vulnerabilities).
*   **Impact:** High (DoS, consumer thread crash).
*   **Effort:** Medium (Requires understanding of the event handler logic and potentially crafting specific input to trigger vulnerabilities).
*   **Skill Level:** Intermediate.
*   **Detection Difficulty:** Medium (Exceptions may be logged, but root cause analysis is needed to determine if it's an attack).
*   **Mitigation:** Use a robust exception handling strategy in all event handlers.  The default `IgnoreExceptionHandler` is generally *not* recommended.  Consider using `FatalExceptionHandler` or a custom handler that logs the error and potentially shuts down the application gracefully or retries the event (if appropriate). Never allow exceptions to propagate and crash the consumer thread. Thorough input validation and fuzz testing of event handlers are crucial.

## Attack Tree Path: [2. Disruptor Data Manipulation Attacks](./attack_tree_paths/2__disruptor_data_manipulation_attacks.md)

*   **General Description:** These attacks aim to corrupt the data being processed by the Disruptor.

## Attack Tree Path: [2.2. Event Data Corruption (via Shared Mutable Objects) [HIGH RISK][CRITICAL]](./attack_tree_paths/2_2__event_data_corruption__via_shared_mutable_objects___high_risk__critical_.md)

*   **Action:** The events passed through the Disruptor are mutable objects, and these objects are shared between threads *without* proper synchronization *outside* of the Disruptor. An attacker modifies the event data *after* it has been published to the ring buffer but *before* it is consumed by the event handler. This leads to data corruption and unpredictable application behavior.
*   **Likelihood:** Medium (If mutable objects are used without proper synchronization, which is a common programming error).
*   **Impact:** High (Data corruption, unpredictable behavior, potential for further exploitation).
*   **Effort:** Medium (Requires understanding of the event handling logic and how shared objects are used).
*   **Skill Level:** Intermediate.
*   **Detection Difficulty:** Hard (Data corruption may be subtle and difficult to trace back to the root cause).
*   **Mitigation:** *Use immutable objects for events.* This is the most effective mitigation. If mutable objects *must* be used, ensure proper synchronization (e.g., using locks or atomic operations) *outside* the Disruptor to prevent concurrent modification. This is a critical area for code review.

