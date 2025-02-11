# Attack Surface Analysis for alibaba/fastjson2

## Attack Surface: [AutoType Deserialization (Arbitrary Code Execution)](./attack_surfaces/autotype_deserialization__arbitrary_code_execution_.md)

*   **Description:**  Attackers can craft malicious JSON input that leverages the AutoType feature (if enabled) to instantiate arbitrary classes and execute code during deserialization. This is the most significant risk.
*   **How `fastjson2` Contributes:** `fastjson2`'s AutoType feature is the *direct* mechanism that enables this vulnerability.  Even with improvements, bypasses are possible if not configured with extreme care.
*   **Example:**
    ```json
    {"@type":"com.example.vulnerable.Gadget", "command":"touch /tmp/pwned"}
    ```
    (Where `com.example.vulnerable.Gadget` is a class with a setter, getter, or constructor that executes the provided command, or triggers other malicious behavior).
*   **Impact:**  Complete system compromise.  The attacker can potentially gain full control over the application and the underlying server.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Disable AutoType:** If not absolutely essential, *completely disable* AutoType. This is the most effective mitigation. Use `ParserConfig.getGlobalInstance().setAutoTypeSupport(false);` or equivalent configuration.
    *   **Enable `safeMode`:** If AutoType is required, *always* enable `safeMode`. This significantly restricts the classes that can be deserialized.
    *   **Explicit Type Mapping:**  Avoid using `@type` in the JSON.  Instead, predefine the mapping between JSON structures and Java classes in the application code. This removes the attacker's control over type selection.
    *   **Custom `ObjectReaderProvider`:** Implement a custom provider for the highest level of control over the deserialization process, allowing only specific, trusted classes to be instantiated.
    *   **Input Validation (Pre-Deserialization):**  Reject any JSON containing the `@type` key if AutoType is not intentionally used. Use a JSON Schema to enforce expected structure and data types *before* the JSON reaches `fastjson2`.

## Attack Surface: [Denial of Service (DoS) - Large Payloads](./attack_surfaces/denial_of_service__dos__-_large_payloads.md)

*   **Description:**  Attackers send excessively large JSON payloads to consume server resources (memory, CPU), leading to a denial-of-service condition.
*   **How `fastjson2` Contributes:** `fastjson2` is *directly* responsible for parsing the JSON payload.  If the payload is too large, `fastjson2`'s processing can exhaust available memory or CPU.
*   **Example:**  A JSON document containing a multi-gigabyte string or a very large array.
*   **Impact:**  Application unavailability, service disruption.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Input Size Limits:** Enforce strict limits on the maximum size of the JSON input that the application will accept. This limit should be applied *before* the data reaches `fastjson2`.
    *   **Streaming Parsing (If Applicable):** If the application's logic allows, use `fastjson2`'s streaming API (`JSONReader.of(InputStream)`) to process the JSON input incrementally. This avoids loading the entire payload into memory at once, mitigating the risk of memory exhaustion.

## Attack Surface: [Denial of Service (DoS) - Deeply Nested JSON](./attack_surfaces/denial_of_service__dos__-_deeply_nested_json.md)

*   **Description:**  Attackers send JSON with many levels of nested objects or arrays, potentially causing a stack overflow and a denial-of-service.
*   **How `fastjson2` Contributes:** `fastjson2`'s recursive processing of nested structures is *directly* responsible for consuming stack space. Deep nesting can lead to stack exhaustion.
*   **Example:**  A JSON document with hundreds or thousands of nested objects: `{"a":{"b":{"c":{"d": ... }}}}`.
*   **Impact:**  Application crash, service disruption.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Nesting Depth Limits:** Configure `fastjson2` (through parser configuration) to limit the maximum depth of nested JSON structures that it will process. This is a *direct* mitigation within `fastjson2`.
    *   **Input Validation:** Validate JSON structure *before* passing to `fastjson2` to enforce nesting limits.

## Attack Surface: [Denial of Service (DoS) - Slow Processing](./attack_surfaces/denial_of_service__dos__-_slow_processing.md)

*   **Description:** Attackers craft JSON input that, while not necessarily large or deeply nested, takes a disproportionately long time to process, consuming CPU resources and potentially leading to DoS.
*   **How `fastjson2` Contributes:** Certain JSON structures or data combinations might trigger inefficient processing paths *within `fastjson2`*. While `fastjson2` is designed for performance, vulnerabilities or performance bugs are always possible.
*   **Example:** Difficult to provide a concrete example without specific knowledge of potential `fastjson2` performance bottlenecks. The principle is to find input that triggers slow code paths *within the library*.
*   **Impact:** Application slowdown, potential service disruption.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Timeouts:** Set strict timeouts for JSON processing operations *specifically around calls to `fastjson2`*. If processing takes longer than the timeout, terminate the operation.
    *   **Resource Monitoring:** Monitor CPU usage during JSON processing *specifically when `fastjson2` is active* to detect unusually slow operations.
    *   **Fuzz Testing:** Use fuzz testing to send a wide variety of malformed and unexpected JSON inputs *directly to `fastjson2`* and observe its behavior, looking for performance issues or crashes. This helps identify potential vulnerabilities *within the library itself*.

