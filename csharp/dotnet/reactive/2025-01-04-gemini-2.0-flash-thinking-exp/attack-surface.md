# Attack Surface Analysis for dotnet/reactive

## Attack Surface: [Injection via Untrusted Observable Sources](./attack_surfaces/injection_via_untrusted_observable_sources.md)

*   **Description:** Attackers inject malicious data into an Observable stream originating from an untrusted external source.
*   **How Reactive Contributes:** Rx facilitates the direct consumption of external data streams as Observables, potentially without intermediate validation. This makes the application directly susceptible to malicious data flowing through the reactive pipeline.
*   **Example:** An Observable connected to a network socket receives a crafted JSON payload containing malicious code that is then processed by downstream operators and observers without sanitization, leading to code execution.
*   **Impact:** Remote code execution, data corruption, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:
    *   Sanitize and validate data *before* it enters the Observable stream.
    *   Use appropriate data types and encoding to limit the potential for injection.
    *   Implement strict input validation rules at the source of the Observable.
    *   Consider using dedicated data transformation and sanitization operators early in the stream.

## Attack Surface: [Vulnerable Observer Logic](./attack_surfaces/vulnerable_observer_logic.md)

*   **Description:** The logic within the `OnNext`, `OnError`, or `OnCompleted` methods of an Observer contains vulnerabilities that can be exploited by malicious data in the stream.
*   **How Reactive Contributes:** Rx relies on these methods to process data. If these methods are not securely implemented, the reactive pipeline becomes a direct path for exploiting those vulnerabilities.
*   **Example:** An `OnNext` method in an Observer directly constructs a SQL query using data from the stream without proper sanitization, leading to SQL injection.
*   **Impact:** Data breaches, unauthorized access, data manipulation.
*   **Risk Severity:** High
*   **Mitigation Strategies:
    *   Implement robust input validation within the `OnNext`, `OnError`, and `OnCompleted` methods of Observers.
    *   Follow secure coding practices when implementing observer logic, such as using parameterized queries to prevent SQL injection.
    *   Avoid performing direct, unsafe operations based on untrusted data within observers.

## Attack Surface: [Resource Exhaustion via Operators](./attack_surfaces/resource_exhaustion_via_operators.md)

*   **Description:**  Malicious actors exploit the behavior of certain Rx operators to consume excessive system resources (CPU, memory), leading to denial of service.
*   **How Reactive Contributes:** Rx operators like `Buffer`, `Window`, or those involving time-based operations can, if not configured carefully, be used to create unbounded collections or perform resource-intensive computations on large streams.
*   **Example:** An attacker floods an Observable connected to a network stream, causing a `Buffer` operator with a large window to consume excessive memory, eventually crashing the application.
*   **Impact:** Denial of service, application instability.
*   **Risk Severity:** High
*   **Mitigation Strategies:
    *   Set appropriate limits on buffer sizes and window durations for operators like `Buffer` and `Window`.
    *   Implement backpressure mechanisms to control the rate of data flow and prevent overwhelming operators.
    *   Carefully consider the resource implications of operators dealing with time and large data volumes.

## Attack Surface: [Uncontrolled Broadcasting through Subjects](./attack_surfaces/uncontrolled_broadcasting_through_subjects.md)

*   **Description:** When using `Subject` or similar constructs, attackers can inject malicious data into the stream, which is then broadcast to all subscribed Observers, potentially affecting multiple parts of the application.
*   **How Reactive Contributes:** `Subject` acts as both an Observable and an Observer, allowing external code to push data into the reactive stream. Without proper access control, this becomes an injection point.
*   **Example:** A `Subject` is used as a communication channel between different modules. An attacker gains access to this `Subject` and injects malicious commands that are then processed by other modules subscribed to the `Subject`.
*   **Impact:**  Widespread impact across application components, potential for privilege escalation or data corruption.
*   **Risk Severity:** High
*   **Mitigation Strategies:
    *   Restrict access to `Subject` instances and control which components can push data into them.
    *   Implement validation and sanitization on data pushed into `Subject` instances.
    *   Consider alternative patterns if uncontrolled broadcasting poses a significant risk.

## Attack Surface: [Deserialization Vulnerabilities in Reactive Streams](./attack_surfaces/deserialization_vulnerabilities_in_reactive_streams.md)

*   **Description:** If Observables are transmitting serialized data, vulnerabilities related to insecure deserialization can be exploited if the data is not properly validated before deserialization.
*   **How Reactive Contributes:** Rx can be used to process streams of serialized objects. If the deserialization process is vulnerable, attackers can craft malicious serialized payloads that, when deserialized, execute arbitrary code.
*   **Example:** An Observable receives serialized objects from an external source. The application uses a vulnerable deserialization library, allowing an attacker to send a crafted payload that executes arbitrary code upon deserialization.
*   **Impact:** Remote code execution.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:
    *   Avoid deserializing data from untrusted sources if possible.
    *   Use secure deserialization libraries and techniques.
    *   Implement validation of serialized data before deserialization.
    *   Consider using safer data exchange formats like JSON where deserialization vulnerabilities are less common.

