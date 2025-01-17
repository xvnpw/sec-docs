# Attack Surface Analysis for google/flatbuffers

## Attack Surface: [Buffer Overflows during Deserialization](./attack_surfaces/buffer_overflows_during_deserialization.md)

- **Description:** A malformed FlatBuffers binary payload contains offsets or sizes that, when processed, cause the application to read or write beyond the allocated buffer.
- **How FlatBuffers Contributes:** The binary format relies on offsets and sizes within the data itself. If these are manipulated, the generated code might access memory outside the intended bounds. FlatBuffers itself doesn't inherently prevent the creation of such malformed data.
- **Example:** A crafted payload specifies a vector length that, when multiplied by the element size, results in a value larger than the allocated buffer, leading to an out-of-bounds write when accessing elements.
- **Impact:** Memory corruption, crashes, potential for arbitrary code execution if the overflow can overwrite critical data or code.
- **Risk Severity:** Critical
- **Mitigation Strategies:**
    - Implement strict input validation on the received FlatBuffers binary before deserialization, checking for unreasonable sizes and offsets.
    - Utilize FlatBuffers' built-in size limits and validation options where available.

## Attack Surface: [Integer Overflows during Deserialization](./attack_surfaces/integer_overflows_during_deserialization.md)

- **Description:** Large values within the FlatBuffers binary (e.g., vector lengths, string sizes) cause integer overflows during calculations within the generated code.
- **How FlatBuffers Contributes:** The binary format uses integer types for lengths and offsets. If these values are maliciously large, standard integer arithmetic can overflow, leading to unexpected and potentially dangerous results.
- **Example:** A crafted payload specifies an extremely large vector length. When the generated code calculates the total memory needed for the vector, the multiplication overflows, resulting in a much smaller allocation than required, leading to a subsequent buffer overflow.
- **Impact:** Incorrect memory allocation, leading to buffer overflows or other memory corruption issues. Potential for denial of service or code execution.
- **Risk Severity:** High
- **Mitigation Strategies:**
    - Implement checks for excessively large values in the FlatBuffers binary before or during deserialization.
    - Use data types with sufficient range to prevent overflows during size calculations within the application.

## Attack Surface: [Out-of-Bounds Access via Accessors](./attack_surfaces/out-of-bounds_access_via_accessors.md)

- **Description:** The generated accessor methods for vectors or strings don't perform sufficient bounds checking, allowing access to memory outside the allocated buffer.
- **How FlatBuffers Contributes:** The generated code relies on the correctness of the offsets and lengths within the binary data. If these are manipulated, accessor methods might attempt to access invalid memory locations.
- **Example:** A crafted payload specifies a vector with a certain length, but the application code attempts to access an element beyond that length using the generated accessor.
- **Impact:** Memory corruption, crashes, potential for information disclosure.
- **Risk Severity:** High
- **Mitigation Strategies:**
    - Always validate the indices before accessing elements of vectors or strings using the generated accessors.
    - Utilize the size information provided by FlatBuffers (e.g., `vector_length()`) to ensure access is within bounds.

