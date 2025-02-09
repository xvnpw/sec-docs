# Threat Model Analysis for nlohmann/json

## Threat: [Deeply Nested JSON Denial of Service](./threats/deeply_nested_json_denial_of_service.md)

*   **Description:** An attacker sends a JSON payload with excessively deep nesting (e.g., thousands of nested arrays or objects).  The recursive nature of the default parsing algorithm can lead to stack exhaustion and a crash, or excessive CPU consumption.
*   **Impact:** Denial of service (DoS). The application becomes unresponsive or crashes, preventing legitimate users from accessing it.
*   **JSON Component Affected:**  `parse()` function (default recursive parsing behavior).  Specifically, the stack usage during recursive descent.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Limit Parsing Depth:** Use the `parse(input, nullptr, true, max_depth)` overload and set a reasonable `max_depth` value (e.g., 16, 32).  Reject input that exceeds this depth.
    *   **Input Size Limit:**  Enforce a strict maximum size limit on the incoming JSON payload *before* parsing.
    *   **Resource Monitoring:** Monitor CPU and memory usage during parsing; terminate if thresholds are exceeded.
    *   **Consider SAX Parsing:** For very large, potentially deeply nested documents, use the SAX parsing interface (`nlohmann::json::sax_parse`) for incremental processing.

## Threat: [Large JSON Payload Denial of Service](./threats/large_json_payload_denial_of_service.md)

*   **Description:** An attacker sends a very large JSON payload (e.g., hundreds of megabytes or gigabytes) without excessive nesting.  This can exhaust available memory, leading to a crash or severe performance degradation.
*   **Impact:** Denial of service (DoS).  Application becomes unresponsive or crashes.
*   **JSON Component Affected:**  `parse()` function (memory allocation during parsing). The entire library's memory management is potentially affected.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Input Size Limit:**  Enforce a strict maximum size limit on the incoming JSON payload *before* parsing.  This is the primary defense.
    *   **Resource Monitoring:** Monitor memory usage during parsing; terminate if thresholds are exceeded.
    *   **Consider SAX Parsing:**  For very large documents, use the SAX parsing interface (`nlohmann::json::sax_parse`) to process the JSON incrementally, minimizing memory footprint.
    *   **Streaming Input:** If possible, stream the JSON input rather than loading it entirely into memory before parsing.

## Threat: [Numeric Overflow/Underflow](./threats/numeric_overflowunderflow.md)

*   **Description:** An attacker provides very large or very small numeric values in the JSON that exceed the limits of the C++ data types used to store them after parsing (e.g., `int`, `long`, `double`). While the library *parses* these values, the *application's* use of `get<T>()` without bounds checking can lead to issues. This is a direct consequence of how the library presents parsed numeric data.
*   **Impact:**  Application instability, incorrect calculations, potential security vulnerabilities if the overflow/underflow affects security-critical logic.
*   **JSON Component Affected:**  `parse()` function (number parsing).  Accessors like `get<int>()`, `get<double>()`, etc. The library's internal representation of numbers.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Range Checks:**  After extracting numeric values from the JSON using `get<T>()`, perform range checks to ensure they are within the acceptable bounds for the intended data types.
    *   **Use Appropriate Data Types:**  Choose C++ data types that are large enough to accommodate the expected range of values. Consider using `long long` or `double` if necessary, but be aware of potential precision issues with floating-point numbers.
    *   **Schema Validation:** Use a JSON schema to define the allowed range of numeric values. This helps prevent the application from even attempting to `get<T>()` an out-of-range value.

## Threat: [Type Confusion](./threats/type_confusion.md)

*   **Description:** An attacker provides a JSON value of an unexpected type (e.g., a string where a number is expected). While the library correctly *parses* the JSON, the application's failure to use `is_...()` methods before `get<T>()` can lead to crashes. This is a direct consequence of the library's dynamic typing.
*   **Impact:** Application crashes, incorrect behavior, potential security vulnerabilities.
*   **JSON Component Affected:** Accessors like `get<T>()`, `is_number()`, `is_string()`, `is_object()`, etc. The type system of the `json` object.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Type Checks:** *Always* use the `is_...()` methods (e.g., `is_number()`, `is_string()`, `is_object()`) to check the type of a JSON value *before* attempting to access it using `get<T>()`.
    *   **Schema Validation:** Use a JSON schema to define the expected types. This provides a strong, declarative way to enforce type safety.
    *   **Defensive Programming:** Handle unexpected types gracefully.

