# Attack Surface Analysis for google/flatbuffers

## Attack Surface: [Out-of-Bounds Reads via Malformed Binary Data](./attack_surfaces/out-of-bounds_reads_via_malformed_binary_data.md)

* **Description:** An attacker sends FlatBuffers binary data with invalid offsets that point outside the allocated buffer.
    * **How FlatBuffers Contributes:** FlatBuffers uses offsets within the binary data to access fields without explicit parsing. Malformed offsets can bypass bounds checks if not implemented carefully in the application.
    * **Example:** A crafted buffer with an offset pointing beyond the end of a vector could lead to reading arbitrary memory.
    * **Impact:** Information Disclosure (reading sensitive data), potential for crashes or unexpected behavior.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *  Implement robust validation of offsets before accessing data.
        *  Use the generated accessor methods provided by FlatBuffers, as they often include basic bounds checks.
        *  Consider adding additional bounds checks in critical sections of the application.
        *  Utilize memory-safe languages and compiler flags where possible.

## Attack Surface: [Integer Overflows/Underflows in Size or Offset Fields](./attack_surfaces/integer_overflowsunderflows_in_size_or_offset_fields.md)

* **Description:** Manipulating size or offset fields within the binary data to cause integer overflows or underflows.
    * **How FlatBuffers Contributes:** FlatBuffers relies on integer values for sizes and offsets. If these values are not validated, attackers can manipulate them to cause unexpected behavior.
    * **Example:** A large value for a vector size could lead to an integer overflow when calculating memory allocation, potentially resulting in a small buffer being allocated and subsequent buffer overflows.
    * **Impact:** Buffer overflows, memory corruption, potential for code execution, Denial of Service.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        *  Thoroughly validate size and offset fields against reasonable limits.
        *  Use data types large enough to accommodate expected maximum values.
        *  Employ safe integer arithmetic libraries or compiler features that detect overflows.

