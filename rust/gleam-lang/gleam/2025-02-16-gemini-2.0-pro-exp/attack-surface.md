# Attack Surface Analysis for gleam-lang/gleam

## Attack Surface: [Unsafe `binary_to_term` Deserialization (RCE)](./attack_surfaces/unsafe__binary_to_term__deserialization__rce_.md)

*   **Description:** Attackers exploit unsafe deserialization of Erlang terms (accessible through Gleam) to achieve remote code execution.
    *   **Gleam Contribution:** Gleam code can directly call Erlang's `binary_to_term` (or equivalent functions/libraries that use it internally). This is a *critical* inherited vulnerability that Gleam code must actively avoid.
    *   **Example:** A Gleam application receives data from an untrusted source (e.g., a network request) and deserializes it using a function that ultimately relies on `binary_to_term`, allowing the attacker to inject malicious code.
    *   **Impact:** Complete system compromise; attacker can execute arbitrary code.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   *Never* use `binary_to_term` (or any function that might use it internally) on data received from untrusted sources.
            *   Use safer serialization formats like JSON or Protocol Buffers for external communication. Gleam has libraries for these.
            *   If Erlang terms *must* be used for external communication, implement a strict, well-defined protocol and use a custom parser/serializer that validates the structure and content of the terms *before* deserialization.  This parser should be extremely cautious and ideally use a whitelist of allowed term structures.
        *   **Users/Deployers:**
            *   No direct mitigation; this is entirely a developer responsibility to avoid this dangerous pattern.

## Attack Surface: [Atom Table Exhaustion (DoS)](./attack_surfaces/atom_table_exhaustion__dos_.md)

*   **Description:** Attackers exhaust the BEAM's atom table, leading to a VM crash and denial of service.
    *   **Gleam Contribution:** Gleam code directly uses atoms.  If Gleam code converts uncontrolled user input into atoms, it creates this vulnerability.
    *   **Example:** A Gleam web application takes user-provided usernames and directly converts them to atoms without any limits or validation. An attacker can register a large number of users with unique names, exhausting the atom table.
    *   **Impact:** Denial of service; the application crashes and becomes unavailable.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   *Strictly avoid* converting user-supplied strings directly to atoms. This is the most important mitigation.
            *   Use a controlled, predefined set of atoms for internal identifiers whenever possible.
            *   For data that originates from user input, use alternative data structures like maps (dictionaries) or binaries (strings) instead of atoms.
            *   If atom creation from external input is absolutely unavoidable (which should be extremely rare), implement strict validation and whitelisting of allowed values.  This whitelist should be as small as possible.
        *   **Users/Deployers:**
            *   Monitor the atom table size and set up alerts for unusually high usage. This can provide early warning of an attack.

## Attack Surface: [Unsafe FFI Calls](./attack_surfaces/unsafe_ffi_calls.md)

*   **Description:** Vulnerabilities introduced through incorrect or insecure use of Gleam's Foreign Function Interface (FFI) to call code in other languages (e.g., C, Rust).
    *   **Gleam Contribution:** Gleam *provides* the FFI mechanism, making it possible to introduce vulnerabilities if used incorrectly. The responsibility for safe FFI usage lies entirely with the Gleam developer.
    *   **Example:** A Gleam application uses the FFI to call a C library for image processing.  If the Gleam code doesn't properly handle memory allocation and deallocation when interacting with the C library, it could lead to a buffer overflow or other memory corruption vulnerability, potentially exploitable for code execution.
    *   **Impact:** Varies widely; can range from application crashes to remote code execution (RCE), depending on the target language of the FFI call and the nature of the vulnerability.
    *   **Risk Severity:** High (potentially Critical)
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Use the FFI with *extreme caution and only when absolutely necessary*.
            *   Thoroughly vet any external libraries used via the FFI, paying close attention to their security track record and code quality.
            *   Ensure *meticulous* type conversions and memory management when passing data between Gleam and the foreign language.  This is often the source of errors.
            *   Prefer using well-established and audited Erlang/OTP libraries whenever possible, rather than writing custom FFI code. Erlang libraries are generally safer due to the BEAM's memory management.
            *   Implement robust error handling for all FFI calls, and be prepared to handle unexpected behavior or crashes in the foreign code.
        *   **Users/Deployers:**
            *   No direct mitigation; this is entirely a developer responsibility to use the FFI safely.

