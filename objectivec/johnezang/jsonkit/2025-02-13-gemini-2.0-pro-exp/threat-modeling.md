# Threat Model Analysis for johnezang/jsonkit

## Threat: [Denial of Service (DoS) via Deeply Nested Objects (Internal Recursion)](./threats/denial_of_service__dos__via_deeply_nested_objects__internal_recursion_.md)

*   **Description:** An attacker sends a JSON payload with excessively deep nesting.  Even if the *overall* input size is limited, `jsonkit`'s *internal* recursive parsing functions might not have adequate stack depth checks, leading to a stack overflow and application crash. This is a vulnerability *within* `jsonkit`'s implementation.
    *   **Impact:** Application crash (denial of service).
    *   **Affected Component:** `jsonkit`'s core parsing functions (specifically recursive functions handling object and array deserialization).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Library Modification (If Possible/Open Source):** Directly modify `jsonkit`'s source code to add explicit stack depth checks within the recursive parsing functions.  Return an error if the depth exceeds a safe limit. This is the most direct mitigation, but requires modifying the library.
        *   **Custom Unmarshaler (If Supported):** If `jsonkit` allows for custom unmarshalers, implement one that tracks nesting depth and returns an error if a threshold is exceeded. This avoids modifying the core library, but depends on `jsonkit`'s features.
        *   **Library Replacement:** Switch to a JSON library with built-in protection against stack overflow attacks (e.g., Go's `encoding/json` is generally well-tested in this regard). This is the most reliable mitigation if modifying `jsonkit` is not feasible.

## Threat: [Denial of Service (DoS) via Large Arrays/Strings (Internal Allocation)](./threats/denial_of_service__dos__via_large_arraysstrings__internal_allocation_.md)

*   **Description:**  Even with an overall input size limit, an attacker could send a JSON payload containing a single, very large array or string that is *just below* the overall limit.  If `jsonkit` attempts to allocate memory for the entire array/string *internally* without incremental processing, it could still exhaust memory and crash the application. This is a vulnerability in how `jsonkit` manages memory *during* parsing, even if the total input size is bounded.
    *   **Impact:** Application crash (denial of service) due to memory exhaustion.
    *   **Affected Component:** `jsonkit`'s parsing functions for arrays and strings, specifically the memory allocation logic.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Streaming Parser (If Supported):** If `jsonkit` provides a streaming API, use it to process arrays and strings incrementally.  This avoids allocating a large buffer for the entire element at once.  The application would need to handle the streamed data and enforce its own limits on individual element sizes.
        *   **Library Modification (If Possible):** Modify `jsonkit`'s source code to implement incremental parsing and memory allocation for arrays and strings.  Allocate memory in smaller chunks and process the data as it's read, rather than allocating a single large buffer upfront.
        *   **Library Replacement:** Use a JSON library designed for handling potentially large arrays and strings, ideally with streaming capabilities or built-in limits on individual element sizes.

