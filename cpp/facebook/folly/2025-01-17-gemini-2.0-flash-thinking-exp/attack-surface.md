# Attack Surface Analysis for facebook/folly

## Attack Surface: [Uncontrolled Asynchronous Task Creation](./attack_surfaces/uncontrolled_asynchronous_task_creation.md)

**Description:** An attacker can trigger the creation of a large number of asynchronous tasks, potentially overwhelming system resources.

**How Folly Contributes:** Folly's `Futures`, `Promises`, and `Coroutines` provide powerful mechanisms for asynchronous programming. If the creation of these tasks is tied to external, unvalidated input, an attacker can exploit this.

**Example:** A web server using Folly to handle requests creates a new `Future` for each incoming connection. An attacker sends a flood of connection requests without proper rate limiting, causing the server to create an excessive number of `Futures`, leading to CPU and memory exhaustion.

**Impact:** Denial of Service (DoS), application unresponsiveness, potential system crashes.

**Risk Severity:** High

**Mitigation Strategies:**
- Implement rate limiting on external inputs that trigger asynchronous task creation.
- Set maximum limits on the number of concurrent asynchronous operations.
- Use Folly's features for managing concurrency, such as thread pools with bounded sizes.
- Implement timeouts for asynchronous operations to prevent indefinite resource consumption.

## Attack Surface: [Race Conditions in Shared State with Asynchronous Operations](./attack_surfaces/race_conditions_in_shared_state_with_asynchronous_operations.md)

**Description:** Multiple asynchronous operations access and modify shared data concurrently without proper synchronization, leading to unpredictable and potentially exploitable behavior.

**How Folly Contributes:** Folly's asynchronous features, while providing concurrency, require careful management of shared state. Without proper use of Folly's concurrency primitives (like `Atomic`, `Mutex`), race conditions can occur.

**Example:** Two asynchronous tasks increment a shared counter. Due to a race condition, both tasks might read the same initial value before either increments, resulting in the counter being incremented only once instead of twice. In a security context, this could lead to incorrect authorization checks or data manipulation.

**Impact:** Data corruption, inconsistent application state, potential for privilege escalation or unauthorized access.

**Risk Severity:** High

**Mitigation Strategies:**
- Use Folly's concurrency primitives (`Atomic`, `Mutex`, `Semaphore`) to protect access to shared mutable state.
- Favor immutable data structures where possible to reduce the need for synchronization.
- Carefully design asynchronous workflows to minimize shared state and potential for conflicts.

## Attack Surface: [Vulnerabilities in Custom Protocol Handling with AsyncSocket](./attack_surfaces/vulnerabilities_in_custom_protocol_handling_with_asyncsocket.md)

**Description:** When implementing custom network protocols using Folly's `AsyncSocket`, vulnerabilities in parsing or handling the protocol can be exploited.

**How Folly Contributes:** Folly's `AsyncSocket` provides a flexible interface for building network applications, but it's the developer's responsibility to implement secure protocol parsing and handling.

**Example:** An application uses `AsyncSocket` to implement a custom protocol where message lengths are read from the network. If the application doesn't properly validate the received length, an attacker could send a crafted message with an extremely large length, leading to a buffer overflow when the application attempts to allocate memory.

**Impact:** Remote code execution, denial of service, information disclosure.

**Risk Severity:** Critical

**Mitigation Strategies:**
- Implement robust input validation and sanitization for all data received over the network.
- Use safe parsing techniques that prevent buffer overflows (e.g., reading data in chunks, using length prefixes).
- Consider using established and well-vetted network protocol libraries instead of implementing custom protocols from scratch.

## Attack Surface: [Time-of-Check-to-Time-of-Use (TOCTOU) Vulnerabilities with Time Utilities](./attack_surfaces/time-of-check-to-time-of-use__toctou__vulnerabilities_with_time_utilities.md)

**Description:** Security-sensitive decisions based on time values obtained using Folly's time utilities can be vulnerable if the time value can change between the check and the use.

**How Folly Contributes:** Folly provides utilities for working with time (`Clock`, `TimePoint`). If these are used in security-critical contexts without proper synchronization or safeguards, TOCTOU vulnerabilities can arise.

**Example:** An application checks the validity of a timestamp in a request. After the check, but before the timestamp is used for authorization, an attacker might be able to manipulate the system clock or the timestamp itself, bypassing the security check.

**Impact:** Authorization bypass, privilege escalation, data manipulation.

**Risk Severity:** High

**Mitigation Strategies:**
- Avoid making security-sensitive decisions based directly on system time if possible.
- If time-based checks are necessary, ensure atomicity or use synchronization mechanisms to prevent changes between the check and the use.
- Consider using monotonic clocks where appropriate, as they are less susceptible to manipulation.

