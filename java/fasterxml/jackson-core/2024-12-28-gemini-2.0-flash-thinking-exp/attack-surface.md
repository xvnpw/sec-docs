*   **Attack Surface: Malformed JSON Leading to Denial of Service (DoS)**
    *   **Description:**  An attacker sends specially crafted, malformed JSON payloads that exploit inefficiencies in `jackson-core`'s parsing logic, causing excessive resource consumption (CPU, memory) and potentially leading to application unavailability.
    *   **How Jackson-core Contributes:** `jackson-core` is responsible for the initial parsing and tokenization of the JSON input. Inefficient handling of certain malformed structures can lead to resource exhaustion during this phase.
    *   **Example:** Sending a JSON payload with extremely deep nesting (e.g., hundreds of nested objects or arrays) can cause `jackson-core` to consume excessive stack space or memory while attempting to parse it.
    *   **Impact:** Application slowdown, temporary unavailability, or complete crash due to resource exhaustion.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement request size limits at the application or infrastructure level to prevent excessively large payloads.
        *   Configure `jackson-core`'s parser limits (if available in higher-level modules like `databind`) to restrict the depth of nesting or the size of individual elements.
        *   Implement timeouts for JSON parsing operations to prevent indefinite processing.

*   **Attack Surface: Malformed JSON Leading to Stack Overflow**
    *   **Description:**  Specifically crafted malformed JSON, particularly with deeply nested structures, can cause `jackson-core`'s recursive parsing logic to exceed the stack size, resulting in a `StackOverflowError` and application crash.
    *   **How Jackson-core Contributes:** The recursive nature of JSON parsing within `jackson-core` makes it susceptible to stack overflow errors when encountering deeply nested structures.
    *   **Example:** A JSON payload with thousands of nested arrays or objects without proper closure can exhaust the call stack during parsing.
    *   **Impact:** Application crash due to `StackOverflowError`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Limit the maximum depth of JSON structures allowed by the application. This can be enforced at the application level or potentially through configuration in higher-level Jackson modules.
        *   Consider alternative parsing strategies if extremely deep nesting is a legitimate use case, though this might involve using different libraries or custom parsing logic.