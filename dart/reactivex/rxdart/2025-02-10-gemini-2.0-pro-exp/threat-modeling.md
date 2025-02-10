# Threat Model Analysis for reactivex/rxdart

## Threat: [Uncontrolled Stream Emission (DoS)](./threats/uncontrolled_stream_emission__dos_.md)

*   **Description:** An attacker manipulates a data source (e.g., a compromised sensor, a malicious network connection, or even flawed application logic that *directly interacts with an RxDart Subject*) to cause an RxDart stream to emit an excessive number of events or excessively large data payloads in a short period. This overwhelms the application's processing capacity. The key here is the direct interaction with an RxDart component that allows for uncontrolled emission.
*   **Impact:** Denial of Service (DoS). The application becomes unresponsive, crashes, or consumes excessive resources (CPU, memory, network bandwidth), making it unavailable to legitimate users.
*   **RxDart Component Affected:** Any `Stream` source, *particularly* `Subject` variants (`PublishSubject`, `BehaviorSubject`, `ReplaySubject`) if they are exposed to external input or are fed by uncontrolled logic *and* the attacker can directly call `add`, `addError`, or `addStream` on them. Also affects any downstream operators that don't implement backpressure.
*   **Risk Severity:** High to Critical (depending on the application's criticality and the ease of triggering the attack).
*   **Mitigation Strategies:**
    *   **Backpressure Operators:** Use RxDart operators designed for flow control:
        *   `debounce(Duration)`: Emit only the last item after a specified quiet period.
        *   `throttle(Duration)`: Emit the first item, then ignore subsequent items for a specified duration.
        *   `buffer(Stream)` or `bufferTime(Duration)`: Collect items into a list and emit the list periodically.
        *   `window(Stream)` or `windowTime(Duration)`: Similar to `buffer`, but emits a `Stream` of items instead of a list.
        *   `sample(Stream)` or `sampleTime(Duration)`: Emit the most recent item at a regular interval.
    *   **Input Validation (at the point of Subject interaction):** Rigorously validate *all* data *before* it is added to a `Subject` using `add`, `addError`, or `addStream`. This includes validating the rate and size of data.
    *   **Rate Limiting (if controlling the Subject):** If the application logic directly controls the `Subject`, implement rate limiting *before* adding data to the `Subject`.
    *   **Timeout Operator:** Use the `timeout(Duration)` operator to prevent the stream from hanging indefinitely if a source stops emitting or becomes unresponsive. This is particularly important for streams that rely on external data sources.

## Threat: [Sensitive Data Exposure Through Streams](./threats/sensitive_data_exposure_through_streams.md)

*   **Description:** Sensitive data (passwords, API keys, personal information) is inadvertently passed through an RxDart stream that is exposed to unauthorized parties. This could happen through logging, debugging tools, or a compromised subscriber *if the stream itself is not properly protected*. The focus here is on the RxDart stream as the conduit for the leak.
*   **Impact:** Information Disclosure. Sensitive data is leaked, potentially leading to identity theft, financial loss, or privacy violations.
*   **RxDart Component Affected:** Any `Stream` carrying sensitive data, and any operators that process or transform that data. The vulnerability lies in the *unintentional exposure* of the stream itself.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Data Sanitization/Redaction:** Transform or redact sensitive data *before* it enters the stream.  For example, replace passwords with placeholders or hash API keys. This is the *primary* mitigation.
    *   **Avoid Unnecessary Exposure:** Don't pass sensitive data through streams unless absolutely necessary.
    *   **Controlled Subscriptions:** Carefully control who can subscribe to streams that might contain sensitive data. Avoid exposing such streams globally or to untrusted components. This is about limiting *access* to the stream.
    *   **Secure Logging:** If logging stream data (which should be avoided for sensitive streams), ensure that sensitive information is masked, encrypted, or omitted from the logs. Use a secure logging framework and *never* log the raw stream contents if they might contain sensitive data.
    *   **Disable Debugging in Production:** Remove or disable any debugging code that might expose stream contents (e.g., printing stream values to the console) in a production environment.

## Threat: [Stream Source Spoofing (Direct Subject Manipulation)](./threats/stream_source_spoofing__direct_subject_manipulation_.md)

*   **Description:** An attacker gains *direct* access to an RxDart `Subject` (e.g., `PublishSubject`, `BehaviorSubject`, `ReplaySubject`) and uses its `add`, `addError`, or `addStream` methods to inject fabricated data or errors. This differs from general input validation issues; it requires the attacker to be able to directly call methods on the `Subject` instance.
*   **Impact:** Spoofing/Tampering. The application behaves incorrectly based on the false data, potentially leading to security vulnerabilities, incorrect decisions, or data corruption.
*   **RxDart Component Affected:** `Subject` variants (`PublishSubject`, `BehaviorSubject`, `ReplaySubject`) where the attacker can directly call `add`, `addError`, or `addStream`.
*   **Risk Severity:** High to Critical (depending on the sensitivity of the data and the consequences of incorrect behavior).
*   **Mitigation Strategies:**
    *   **Restrict Subject Access:**  *Do not expose `Subject` instances directly to untrusted code*.  This is the most crucial mitigation.  Instead, expose only the `Stream` part of the `Subject` (using `subject.stream`) to consumers. This prevents external code from directly adding data.
    *   **Internal Validation (within the Subject's owner):** If a component *owns* a `Subject` and adds data to it, that component should rigorously validate the data *before* adding it. This acts as a second layer of defense.
    *   **Consider Alternatives to Subjects:** If possible, use alternative stream creation methods that don't involve mutable `Subject` instances, such as `Stream.fromIterable`, `Stream.fromFuture`, or custom stream controllers with limited exposure.

