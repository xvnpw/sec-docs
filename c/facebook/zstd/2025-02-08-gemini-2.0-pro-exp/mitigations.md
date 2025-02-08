# Mitigation Strategies Analysis for facebook/zstd

## Mitigation Strategy: [Strict Output Size Limits (Zstd API)](./mitigation_strategies/strict_output_size_limits__zstd_api_.md)

**Description:**
1.  **Determine Maximum Expected Size:** Before deployment, analyze the application's data flow to determine the absolute maximum expected size of decompressed data for *any* valid input.  Consider all possible use cases.  Add a reasonable buffer (e.g., 10-20%) to this maximum expected size.
2.  **Implement Pre-Decompression Check (If Possible, and Trustworthy):** If the compressed data format allows for it (e.g., a header indicating uncompressed size), *and* this header is considered trustworthy (e.g., cryptographically signed), perform a preliminary check using `ZSTD_getFrameContentSize()`. If the indicated size exceeds the limit, reject the input *before* starting decompression. *Crucially*, this is only a preliminary check; the main limit must still be enforced during decompression.
3.  **Enforce Limit During Decompression:** Use Zstd's streaming API (`ZSTD_decompressStream()`).  In the decompression loop:
    *   Initialize a `ZSTD_DCtx*` context using `ZSTD_createDCtx()`.    
    *   Initialize a counter for the total decompressed size.
    *   Initialize `ZSTD_inBuffer` and `ZSTD_outBuffer` structures.
    *   In a loop, read input data into `ZSTD_inBuffer`.
    *   Call `ZSTD_decompressStream()` with the input and output buffers.
    *   After each call to `ZSTD_decompressStream()`, add `output.pos` (the number of bytes written to the output buffer) to the total decompressed size counter.
    *   *Before* processing the decompressed chunk in `ZSTD_outBuffer`, compare the counter to the pre-determined maximum size limit.
    *   If the counter exceeds the limit, immediately:
        *   Stop the decompression process (break the loop).
        *   Free the decompression context using `ZSTD_freeDCtx()`.
        *   Free any other allocated resources.
        *   Log the error (without revealing sensitive data).
        *   Return an appropriate error.
4.  **Regular Review:** Periodically review the maximum size limit.

**Threats Mitigated:**
*   **Decompression Bomb (Amplification Attack):** (Severity: Critical) - Prevents attackers from crafting compressed data that expands to an extremely large size.
*   **Resource Exhaustion:** (Severity: High) - Limits memory consumed by decompression.

**Impact:**
*   **Decompression Bomb:** Risk reduced from Critical to Low.
*   **Resource Exhaustion:** Risk reduced from High to Low.

**Currently Implemented:** Partially. Streaming API is used (`data_processor.c`), but the size limit check is done *after* decompression, not per-chunk.

**Missing Implementation:** Per-chunk size check within the `ZSTD_decompressStream()` loop in `data_processor.c` is missing.  The check should be *before* processing each chunk. A configuration parameter for the maximum decompressed size is needed. `ZSTD_getFrameContentSize()` should be used for a preliminary check if applicable and trustworthy.

## Mitigation Strategy: [Secure Dictionary Handling (Zstd API)](./mitigation_strategies/secure_dictionary_handling__zstd_api_.md)

**Description:**
1.  **Integrity Checks (Hashing):**
    *   Generate a SHA-256 hash of the dictionary file.
    *   Store this hash securely, separate from the dictionary file.
    *   Before loading the dictionary, calculate its hash.
    *   Compare the calculated hash with the stored hash.  If they don't match, *do not load*.
2.  **Access Control (Permissions):** Use OS file permissions to restrict access. Only the application process needing the dictionary should have read access. Prevent write access.
3.  **Secure Distribution (If Applicable):** Use a secure mechanism (e.g., code signing) for dictionary updates. Verify integrity before replacing.
4.  **Avoid External Dictionaries (If Possible):** Embed the dictionary in the application binary if size permits.
5. **Load Dictionary Securely:**
    * Use `ZSTD_createDDict()` to create a decompression dictionary from the dictionary data. Store the `ZSTD_DDict*` pointer.
    * When initializing the decompression context, use `ZSTD_DCtx_refDDict()` to associate the dictionary with the context.
    * When finished, *always* free the dictionary using `ZSTD_freeDDict()`.
    * If using a custom dictionary for *compression*, use `ZSTD_createCDict()` and `ZSTD_CCtx_refCDict()`, and free with `ZSTD_freeCDict()`.

**Threats Mitigated:**
*   **Malicious Dictionary Replacement:** (Severity: High)
*   **Dictionary Tampering:** (Severity: High)

**Impact:**
*   **Malicious Dictionary Replacement/Tampering:** Risk reduced from High to Low.

**Currently Implemented:** Partially. Dictionary loaded from `/opt/myapp/dict.zstd`. Permissions are `644`.

**Missing Implementation:** Integrity checks (hashing) are missing. The application loads the dictionary without verification. Permissions should be `444`. A secure update mechanism is absent. `ZSTD_createDDict()`, `ZSTD_DCtx_refDDict()`, and `ZSTD_freeDDict()` (or the compression equivalents) should be used explicitly for proper dictionary lifecycle management.

## Mitigation Strategy: [Zstd-Specific Fuzzing](./mitigation_strategies/zstd-specific_fuzzing.md)

**Description:**
1.  **Choose a Fuzzer:** libFuzzer, AFL, or OSS-Fuzz.
2.  **Write a Fuzz Target:** Create a C/C++ function that takes a byte array as input and uses it with the Zstd API (both streaming and simple). The target should:
    *   Call `ZSTD_decompressStream()` or `ZSTD_decompress()` with the fuzzed input.
    *   Use `ZSTD_createDCtx()` and `ZSTD_freeDCtx()`.
    *   If using dictionaries, use `ZSTD_createDDict()`, `ZSTD_DCtx_refDDict()`, and `ZSTD_freeDDict()` (and the compression equivalents).
    *   Handle errors from Zstd functions gracefully (no crashes).
    *   Check for memory leaks/undefined behavior (ASan).
3.  **Compile with Fuzzing Instrumentation:** Compile with flags for the fuzzer (e.g., `-fsanitize=fuzzer` for libFuzzer).
4.  **Run the Fuzzer:** Run with a corpus of valid compressed data.
5.  **Analyze Results:** Analyze crashes to find the root cause.
6.  **Repeat:** Fix, recompile, and repeat.

**Threats Mitigated:**
*   **Unknown Vulnerabilities in Zstd Decompression:** (Severity: Variable)

**Impact:**
*   **Unknown Vulnerabilities:** Risk reduced from Unknown to Low (over time).

**Currently Implemented:** No.

**Missing Implementation:** A fuzz target needs to be written and integrated with a fuzzer.

## Mitigation Strategy: [Proper Memory Management with Zstd API](./mitigation_strategies/proper_memory_management_with_zstd_api.md)

**Description:**
1.  **Streaming API:** Use `ZSTD_decompressStream()`.
2.  **Input Buffer Management:**
    *   Allocate a reasonably sized input buffer.
    *   Read compressed data in chunks.
    *   Pass to `ZSTD_decompressStream()`.
    *   Track consumed data.
3.  **Output Buffer Management:**
    *   Allocate a reasonably sized output buffer.
    *   Pass to `ZSTD_decompressStream()`.
    *   Track produced data.
    *   Process decompressed data.
    *   If full, process, reset, and continue.
4.  **Context Management:**
    *   Create context: `ZSTD_createDCtx()`.
    *   Reuse context (if possible).
    *   Free context: `ZSTD_freeDCtx()`.
5.  **Dictionary Management (If Applicable):**
    *   Create: `ZSTD_createCDict()` or `ZSTD_createDDict()`.
    *   Free: `ZSTD_freeCDict()` or `ZSTD_freeDDict()`.
6.  **Error Handling:** Check the return value of *every* Zstd function. Handle errors gracefully.
7. **Memory Sanitizers:** Compile and run with AddressSanitizer and LeakSanitizer.

**Threats Mitigated:**
*   **Buffer Overflows/Underflows:** (Severity: Critical)
*   **Memory Leaks:** (Severity: High)
*   **Use-After-Free:** (Severity: Critical)

**Impact:**
*   **Buffer Overflows/Underflows/Use-After-Free:** Risk reduced from Critical to Low.
*   **Memory Leaks:** Risk reduced from High to Low.

**Currently Implemented:** Partially. Streaming API is used, but buffer sizes are not dynamically adjusted, and error handling is inconsistent.

**Missing Implementation:** Robust error handling for *all* Zstd calls. Careful buffer management. Memory sanitizers during development. Context and dictionary freeing should be double-checked.

