# Attack Surface Analysis for fasterxml/jackson-databind

## Attack Surface: [Polymorphic Deserialization (Untrusted Data)](./attack_surfaces/polymorphic_deserialization__untrusted_data_.md)

**Description:** Deserializing JSON data from untrusted sources, where the JSON includes type information that Jackson uses to instantiate objects of various classes. This is the core vulnerability and the primary attack vector.
**How `jackson-databind` Contributes:** `jackson-databind`'s polymorphic type handling features (e.g., `enableDefaultTyping()`, `@JsonTypeInfo`, or even implicit type handling in some configurations) allow the instantiation of arbitrary classes based on the input JSON. This is a *direct* feature of the library.
**Example:**
```json
["com.example.MyClass", {
    "@type": "org.apache.commons.collections.functors.InvokerTransformer",
    "iMethodName": "exec",
    "iParamTypes": ["java.lang.String"],
    "iArgs": ["calc.exe"]
}]
```
This JSON, if deserialized with a vulnerable configuration, could attempt to execute `calc.exe` (on Windows) using a known gadget class.
**Impact:** Remote Code Execution (RCE), allowing an attacker to execute arbitrary code on the server. This can lead to complete system compromise.
**Risk Severity:** **Critical**
**Mitigation Strategies:**
*   **Avoid Untrusted Data:** Do not deserialize JSON from untrusted sources if possible.
*   **`PolymorphicTypeValidator` (PTV):** Implement a strict `PolymorphicTypeValidator` to whitelist *only* the specific classes allowed for polymorphic deserialization. Deny by default, allow by exception. Use `BasicPolymorphicTypeValidator.builder()` for fine-grained control.
*   **`@JsonTypeInfo` and `@JsonSubTypes`:** Use these annotations for controlled polymorphism, explicitly defining allowed subtypes. This is generally safer than `enableDefaultTyping()`.
*   **Disable `enableDefaultTyping()`:** Avoid using this method unless absolutely necessary, and only with a very restrictive PTV.
*   **Regular Updates:** Keep `jackson-databind` updated to the latest version to benefit from security patches.
*   **Minimize Dependencies:** Reduce the number of libraries on the classpath to limit the pool of potential gadget classes.
*   **Input Validation:** Validate the structure of the JSON *before* deserialization (this is a secondary defense).

## Attack Surface: [Denial of Service (DoS) via Deeply Nested JSON](./attack_surfaces/denial_of_service__dos__via_deeply_nested_json.md)

**Description:** Processing deeply nested JSON structures can consume excessive CPU and memory, leading to a denial-of-service condition.
**How `jackson-databind` Contributes:** `jackson-databind`'s parsing process is directly responsible for handling the nested structure. The recursive nature of parsing nested objects is a *direct* contributor to the vulnerability.
**Example:**
```json
{"a":{"a":{"a":{"a":{"a":{"a": ... }}}}}}
```
(Repeated nesting to a very high depth)
**Impact:** Application unavailability. The server becomes unresponsive or crashes due to resource exhaustion.
**Risk Severity:** **High**
**Mitigation Strategies:**
*   **Limit Input Size:** Enforce a maximum size for incoming JSON payloads.
*   **Limit Nesting Depth:** Configure Jackson to reject JSON with excessive nesting depth. This is a *direct* mitigation within `jackson-databind` (e.g., using a custom `JsonParser.Feature` or `DeserializationContext`).
*   **Resource Monitoring:** Monitor CPU and memory usage (this is a general mitigation, not specific to Jackson).

## Attack Surface: [Denial of Service (DoS) via Large Numbers/Strings](./attack_surfaces/denial_of_service__dos__via_large_numbersstrings.md)

**Description:** Deserializing extremely large numbers or strings can consume excessive memory and processing time.
**How `jackson-databind` Contributes:** `jackson-databind`'s parsing and object creation logic *directly* handles these large values and allocates memory for them.
**Example:**
```json
{"largeNumber": 1e308, "longString": "a".repeat(1000000)}
```
**Impact:** Application unavailability.
**Risk Severity:** **High**
**Mitigation Strategies:**
*   **Input Validation:** Validate the range of numeric values and the length of strings *before* deserialization (this is a good practice, but not a direct Jackson feature).
*   **Configuration Limits:** Explore Jackson's configuration options to limit the size of numbers and strings it will process. This is a *direct* mitigation if available.

## Attack Surface: [Denial of Service (DoS) via Excessive Object Creation](./attack_surfaces/denial_of_service__dos__via_excessive_object_creation.md)

**Description:** A JSON payload can be crafted to cause the creation of a very large number of objects, leading to memory exhaustion.
**How `jackson-databind` Contributes:** `jackson-databind`'s data binding process *directly* creates the objects based on the JSON structure.
**Example:**
```json
{"list": [{}, {}, {}, ... ]} // A very long list of empty objects
```
**Impact:** Application unavailability due to memory exhaustion.
**Risk Severity:** **High**
**Mitigation Strategies:**
*   **Input Validation:** Validate the structure of the JSON to prevent unexpected object creation (good practice, but not Jackson-specific).
*   **Limit Collection Sizes:** Use annotations or custom deserializers to limit the maximum size of collections (lists, maps, etc.) within your data model. This is a *direct* mitigation using Jackson's features.

