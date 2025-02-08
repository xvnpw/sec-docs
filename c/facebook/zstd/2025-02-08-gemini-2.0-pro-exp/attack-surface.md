# Attack Surface Analysis for facebook/zstd

## Attack Surface: [1. Maliciously Crafted Compressed Data (Decompression)](./attack_surfaces/1__maliciously_crafted_compressed_data__decompression_.md)

*   **Description:** An attacker provides specially crafted compressed input designed to exploit vulnerabilities *within the zstd decompression algorithm itself*.
*   **How zstd Contributes:** The core decompression logic (Huffman decoding, FSE, repcode handling, sequence decoding, frame header parsing) contains potential points for exploitation via crafted input.  This is *not* about simply providing a large input, but about exploiting bugs in the *implementation* of the decompression process.
*   **Example:**
    *   A crafted input that triggers a buffer overflow within zstd's Huffman decoding routine due to an integer overflow in a length calculation.
    *   A crafted input that exploits a flaw in zstd's repcode handling, causing it to write data outside of the allocated buffer.
    *   A crafted input that causes an out-of-bounds read within zstd's FSE decoding logic.
*   **Impact:**
    *   Arbitrary Code Execution (ACE) - allowing the attacker to run their own code.
    *   Denial of Service (DoS) - crashing the application.
    *   Information Disclosure (less likely, but possible if the overflow reads from unintended memory).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Fuzzing:**  Extensive fuzzing of the *zstd library itself* (and the application's integration) is paramount. This should focus on generating malformed compressed data that targets the internal components of the decompression algorithm.
    *   **Upstream Updates:**  Keep the zstd library meticulously up-to-date.  Security vulnerabilities in zstd are actively researched and patched.  Rely on the official releases.
    *   **Memory Safety (Library Level):** While the application developer can't directly control zstd's internal memory safety, choosing a memory-safe language for the *application* helps contain the impact of any zstd vulnerabilities.
    *   **Sandboxing (Process Isolation):**  If feasible, run the zstd decompression in a separate, sandboxed process with limited privileges. This contains the impact of a successful exploit.

## Attack Surface: [2. Dictionary-Related Attacks (Malicious Dictionaries)](./attack_surfaces/2__dictionary-related_attacks__malicious_dictionaries_.md)

*   **Description:** An attacker provides a *malicious zstd dictionary* designed to exploit vulnerabilities in the dictionary parsing or usage *within zstd*.
*   **How zstd Contributes:** The zstd library's handling of dictionaries introduces a potential attack vector if the dictionary itself is crafted to trigger bugs.
*   **Example:**
    *   A malicious dictionary file containing specially crafted data that, when parsed by zstd, causes a buffer overflow within the dictionary loading routine.
    *   A malicious dictionary designed to trigger an integer overflow during dictionary-based decompression.
*   **Impact:**
    *   Arbitrary Code Execution (ACE).
    *   Denial of Service (DoS).
*   **Risk Severity:** High (if custom dictionaries are used, especially from untrusted sources)
*   **Mitigation Strategies:**
    *   **Trusted Sources (Strict):**  *Never* load zstd dictionaries from untrusted sources.  If dictionaries are absolutely necessary, they should be generated and managed internally by the application and treated as highly sensitive assets.
    *   **Fuzzing (Dictionary Handling):** Fuzz the zstd library's dictionary loading and processing routines specifically.
    *   **Avoid Custom Dictionaries (If Possible):** If the performance benefits of custom dictionaries are not *essential*, avoid using them entirely. This eliminates this attack vector.
    *   **Upstream Updates:** As with the core library, keep zstd updated to benefit from any security patches related to dictionary handling.

## Attack Surface: [3. Resource Exhaustion (Decompression - Algorithmic Complexity)](./attack_surfaces/3__resource_exhaustion__decompression_-_algorithmic_complexity_.md)

*   **Description:** An attacker provides input that, while not necessarily a "compression bomb" in the traditional sense, is crafted to exploit edge cases in the zstd decompression algorithm, leading to excessive CPU consumption. This is distinct from simply providing a large output size.
*   **How zstd Contributes:** While zstd is designed for speed, vulnerabilities or inefficiencies in the decompression algorithm *could* be exploited to cause excessive CPU usage.
*   **Example:**
    *   An attacker crafts input that triggers a worst-case scenario in zstd's repcode handling or sequence decoding, causing the decompression process to take an unexpectedly long time. This is *not* about the output size, but about the *complexity* of the decompression process itself.
*   **Impact:** Denial of Service (DoS) - CPU exhaustion.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Fuzzing (Targeted):** Fuzzing should specifically try to identify inputs that cause disproportionately high CPU usage during decompression.
    *   **Resource Monitoring (Strict):**  Closely monitor CPU usage during zstd decompression.  Terminate the process if it exceeds a predefined threshold *even if the output size is within limits*.
    *   **Timeouts (Aggressive):** Implement relatively aggressive timeouts for zstd decompression operations.
    *   **Upstream Updates:** Keep zstd updated, as performance improvements often address potential algorithmic complexity issues.

## Attack Surface: [4. API Misuse (Directly Affecting zstd)](./attack_surfaces/4__api_misuse__directly_affecting_zstd_.md)

*   **Description:** Incorrect usage of the zstd API functions that directly lead to vulnerabilities *within the context of zstd's operation*.
*   **How zstd Contributes:** Misusing zstd's API functions, particularly those related to buffer management, can create vulnerabilities.
*   **Example:**
    *   Providing an `outBuffer` to `ZSTD_decompress()` or `ZSTD_decompressStream()` that is smaller than the value returned by `ZSTD_getFrameContentSize()` (or the actual decompressed size, if the content size is unknown), leading to a buffer overflow *within zstd's memory*.
    *   Failing to check the return value of `ZSTD_decompressStream()` and continuing to use the `outBuffer` even if `ZSTD_isError()` returns true, potentially leading to the application processing corrupted data *originating from a zstd error*.
*   **Impact:**
    *   Buffer Overflows (within zstd's memory).
    *   Data Corruption (passed back to the application).
    *   Denial of Service (DoS).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Careful Buffer Sizing:** Always ensure that output buffers provided to zstd functions are large enough to hold the decompressed data. Use `ZSTD_getFrameContentSize()` when possible, and be prepared to handle cases where the content size is unknown (using a progressively growing buffer and checking for errors).
    *   **Strict Error Handling:** *Always* check the return values of *all* zstd API functions. Use `ZSTD_isError()` to determine if an error occurred, and if so, *immediately* stop processing and do *not* use any data from the output buffer.
    *   **API Review and Code Reviews:** Thoroughly review the zstd API documentation and conduct code reviews to ensure correct usage.
    *   **Wrapper Functions:** Create wrapper functions around the zstd API to enforce correct usage and provide a more secure and consistent interface. This can help prevent common mistakes.
    * **Static Analysis:** Use static analysis tools that are aware of zstd's API to detect potential misuse.

