# Attack Surface Analysis for fasterxml/jackson-core

## Attack Surface: [Malformed JSON Input Leading to Denial of Service (DoS)](./attack_surfaces/malformed_json_input_leading_to_denial_of_service__dos_.md)

**Description:**  Providing specially crafted, invalid JSON input can cause the `jackson-core` parser to consume excessive resources (CPU, memory), leading to a denial of service.

* **How Jackson-core Contributes:** The library's parsing logic needs to handle various JSON structures. Complex or deeply nested invalid structures can trigger inefficient parsing paths or resource exhaustion within the library.
* **Example:** Sending a JSON payload with an extremely large number of nested arrays or objects, or with missing closing brackets/braces.
* **Impact:** Application becomes unresponsive or crashes, impacting availability for legitimate users.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Implement input size limits on the incoming JSON payload.
    * Configure timeouts for the parsing process to prevent indefinite resource consumption.

## Attack Surface: [JSON Bomb (Billion Laughs Equivalent) Leading to Resource Exhaustion](./attack_surfaces/json_bomb__billion_laughs_equivalent__leading_to_resource_exhaustion.md)

**Description:** Crafting a JSON payload with deeply nested structures and repeated elements can cause exponential memory consumption during parsing, leading to a denial of service. This is analogous to the XML "Billion Laughs" attack.

* **How Jackson-core Contributes:** The recursive nature of parsing nested JSON structures can lead to excessive memory allocation if the nesting is very deep.
* **Example:**  A JSON payload like `{"a": {"a": {"a": ...}}}` repeated many times, or `{"a": ["b", "b", "b", ... ]}` where "b" is a large string and the array is very long.
* **Impact:** Severe resource exhaustion, potentially crashing the application or the underlying system.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Implement limits on the maximum nesting depth allowed for JSON structures.
    * Set limits on the maximum size of arrays or objects within the JSON payload.
    * Configure timeouts for the parsing process.

