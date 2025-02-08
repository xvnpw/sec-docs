# Threat Model Analysis for facebook/zstd

## Threat: [Integer Overflow/Underflow in zstd](./threats/integer_overflowunderflow_in_zstd.md)

*   **Description:** An attacker crafts a specially designed compressed input that exploits a hypothetical (but possible) integer overflow or underflow vulnerability within the zstd library's code.  Successful exploitation could lead to unexpected behavior, potentially allowing for arbitrary code execution. This relies on a bug *within* zstd's implementation.
*   **Impact:** Potential for arbitrary code execution (ACE), data corruption, denial of service. The severity depends on the specific vulnerability and how it can be triggered.
*   **Affected zstd Component:** Any part of the `libzstd` library, particularly code dealing with integer arithmetic, frame parsing, Huffman coding, or other complex data manipulation. This is a vulnerability *within* zstd itself.
*   **Risk Severity:** Critical (If exploitable for ACE), High (If only DoS).
*   **Mitigation Strategies:**
    *   **Keep zstd Updated:** This is the *primary* and most crucial mitigation. Apply security updates from the zstd developers promptly. Monitor release notes and security advisories.
    *   **Memory-Safe Language (Partial Mitigation):** If the application is written in a memory-safe language (e.g., Rust), the *impact* of a C-level vulnerability might be reduced (e.g., a crash instead of ACE), but the underlying vulnerability in zstd still exists.
    *   **Sandboxing (Advanced):** Isolate the decompression process in a sandboxed environment with limited privileges and resources to contain the potential damage from a successful exploit.

## Threat: [Decompression Bomb (Resource Exhaustion) - *Specifically targeting zstd's limits*](./threats/decompression_bomb__resource_exhaustion__-_specifically_targeting_zstd's_limits.md)

*   **Description:** While zstd is designed to be resistant to traditional zip bombs, an attacker might attempt to craft input that, while technically valid according to zstd's specifications, still pushes the library to its resource limits. This differs from simple API misuse; it involves finding edge cases or weaknesses in zstd's resource management *despite* its built-in protections. The attacker is trying to find a way to make zstd *itself* consume excessive resources, even with correct API usage.
*   **Impact:** Denial of service (DoS), application crash, system instability due to excessive memory or CPU consumption during decompression.
*   **Affected zstd Component:** Primarily the decompression functions: `ZSTD_decompressDCtx`, `ZSTD_decompressStream`, and related functions within the `libzstd` library. The core decompression algorithm and its resource management are the targets.
*   **Risk Severity:** High (Can lead to complete service unavailability).
*   **Mitigation Strategies:**
    *   **Strict Input Size Limits:** Enforce reasonable limits on the *compressed* input size *before* any decompression attempts. This is a crucial first line of defense, even though the attack targets zstd directly.
    *   **Decompression Output Size Limits:** Use zstd's API features to limit the maximum size of the decompressed output. Specifically, use functions like `ZSTD_decompressStream` with careful output buffer management and error handling. Terminate decompression if the output exceeds the limit.
    *   **Resource Monitoring:** Actively monitor memory and CPU usage during the decompression process. If resource consumption exceeds predefined thresholds, terminate the decompression and log the event.
    *   **Fuzz Testing:** Regularly and extensively fuzz test the application's zstd integration, specifically targeting the decompression functionality with a wide variety of malformed, highly compressed, and edge-case inputs. This helps identify potential weaknesses in zstd's handling of unusual inputs.
    * **Keep zstd Updated:** Although this threat targets zstd's limits, newer versions may include improvements in resource handling and robustness.

## Threat: [Oversized Allocation via `ZSTD_getFrameContentSize` - *Exploiting zstd's estimation*](./threats/oversized_allocation_via__zstd_getframecontentsize__-_exploiting_zstd's_estimation.md)

*   **Description:** The application uses `ZSTD_getFrameContentSize` to estimate the decompressed size. An attacker crafts a malicious zstd frame that causes `ZSTD_getFrameContentSize` to return a very large, but *incorrect*, value, leading the application to allocate an excessively large buffer. This exploits a potential weakness in zstd's size estimation logic, even if the application checks for `ZSTD_CONTENTSIZE_UNKNOWN` and `ZSTD_CONTENTSIZE_ERROR`.
*   **Impact:** Memory exhaustion, denial of service.
*   **Affected zstd Component:** `ZSTD_getFrameContentSize` function within `libzstd`, and the interaction between this function and the application's memory allocation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Handle `ZSTD_CONTENTSIZE_UNKNOWN` and `ZSTD_CONTENTSIZE_ERROR`:** Explicitly check the return value of `ZSTD_getFrameContentSize` and implement robust error handling for these cases.
    *   **Impose a Strict Upper Bound:** Even if `ZSTD_getFrameContentSize` returns a seemingly valid size, *always* enforce a reasonable and predetermined upper bound on the allocated buffer size. Never blindly trust the returned value.
    *   **Prefer Streaming Decompression:** The most effective mitigation is to use `ZSTD_decompressStream` with smaller, fixed-size output buffers. This avoids the need to pre-allocate a large buffer based on any estimate, completely sidestepping the vulnerability.
    * **Keep zstd Updated:** Newer versions of zstd may have improved the accuracy and robustness of `ZSTD_getFrameContentSize`.

