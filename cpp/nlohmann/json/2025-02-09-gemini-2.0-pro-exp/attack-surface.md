# Attack Surface Analysis for nlohmann/json

## Attack Surface: [Deeply Nested JSON (Denial of Service)](./attack_surfaces/deeply_nested_json__denial_of_service_.md)

*   **Description:**  An attacker crafts a JSON payload with excessive levels of nesting (objects within objects, arrays within arrays, etc.).
*   **JSON Contribution:** The library's recursive parsing mechanism is exploited to consume resources.  This is a *direct* consequence of how the library handles JSON.
*   **Example:**  `{"a":{"b":{"c":{"d":{"e":{"f": ... }}}}}}}` (repeated many times).
*   **Impact:**
    *   Stack Overflow (crash).
    *   Heap Exhaustion (crash).
    *   CPU Exhaustion (unresponsiveness).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:**  Limit the maximum nesting depth allowed in JSON input *before* passing to `nlohmann/json`.
    *   **Resource Limits:**  Set limits on memory and CPU time for parsing.
    *   **Iterative Parsing (if possible):** Explore if a less-recursive approach is feasible (though likely complex).

## Attack Surface: [Large JSON Payloads (Denial of Service)](./attack_surfaces/large_json_payloads__denial_of_service_.md)

*   **Description:** An attacker sends a very large JSON payload (e.g., many megabytes or gigabytes).
*   **JSON Contribution:** The library needs to allocate memory to store the *entire* parsed JSON data in its internal representation. This is inherent to how the library operates.
*   **Example:** A JSON array containing millions of small objects, or a single object with a very long string value.
*   **Impact:**
    *   Heap Exhaustion (crash).
    *   CPU Exhaustion (unresponsiveness).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:**  Enforce a strict limit on the maximum size of the JSON payload *before* parsing.
    *   **Streaming (if possible):**  If the application logic *and* the chosen library allow, consider a streaming approach (though this might necessitate a different library or custom handling). This is a significant architectural change.
    *   **Resource Limits:** Set overall memory limits for the application.

## Attack Surface: [Unintentional Data Exposure (Information Disclosure)](./attack_surfaces/unintentional_data_exposure__information_disclosure_.md)

*   **Description:**  The application accidentally serializes sensitive data into JSON.
*   **JSON Contribution:** The library is the *direct tool* used to convert internal data structures (potentially containing secrets) into JSON format.
*   **Example:**  Serializing a user object that contains a password hash or internal API keys.
*   **Impact:**  Exposure of sensitive information.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Careful Serialization:**  Explicitly control which fields are serialized.  *Never* blindly serialize entire objects, especially those representing internal state or user data. Use Data Transfer Objects (DTOs) designed specifically for external communication.
    *   **Data Masking/Redaction:**  Mask or redact sensitive data *before* it is passed to the serialization function.

