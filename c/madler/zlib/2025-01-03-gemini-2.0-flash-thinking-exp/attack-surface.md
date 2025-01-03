# Attack Surface Analysis for madler/zlib

## Attack Surface: [Compression Bombs (Zip Bombs/Decompression Bombs)](./attack_surfaces/compression_bombs_(zip_bombsdecompression_bombs).md)

**Description:**  Maliciously crafted compressed data that expands to an extremely large size when decompressed.

**How zlib Contributes:** zlib's core functionality is decompression. It faithfully decompresses the provided data according to the compression algorithm, regardless of the resulting size.

**Example:** A small .zip file containing nested compressed data that expands to gigabytes or terabytes upon full decompression.

**Impact:** Denial of Service (DoS) due to resource exhaustion (memory, disk space, CPU), potentially crashing the application or the entire system.

**Risk Severity:** High

**Mitigation Strategies:**
* **Developers:** Implement limits on the maximum size of decompressed data. Set timeouts for decompression operations. Monitor resource usage during decompression. Consider using decompression libraries with built-in safeguards or resource limits if available.
* **Users:** Be cautious when decompressing files from untrusted sources.

## Attack Surface: [Buffer Overflows During Decompression](./attack_surfaces/buffer_overflows_during_decompression.md)

**Description:**  Providing compressed data that, when decompressed, exceeds the allocated buffer size for the decompressed output.

**How zlib Contributes:** If the application provides an insufficiently sized buffer to zlib's decompression functions (`uncompress`, `inflate`, etc.), zlib will write beyond the buffer boundary.

**Example:** Decompressing a file where the actual decompressed size is larger than the buffer allocated by the application.

**Impact:** Memory corruption, potentially leading to crashes, arbitrary code execution, or information disclosure.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Developers:**  Always allocate a buffer large enough to accommodate the *maximum possible* decompressed size (if known) or dynamically allocate the buffer based on information within the compressed data (with size limits). Carefully manage buffer sizes and boundaries. Use safer alternatives if available and appropriate.
* **Users:**  This is primarily a developer concern.

## Attack Surface: [Integer Overflows/Underflows in Size Handling](./attack_surfaces/integer_overflowsunderflows_in_size_handling.md)

**Description:**  Manipulating input sizes (compressed or uncompressed) to cause integer overflows or underflows within zlib's internal calculations.

**How zlib Contributes:** zlib performs calculations based on the provided input and output sizes. If these sizes are not properly validated by the application, attackers might be able to trigger integer overflows or underflows within zlib's code.

**Example:** Providing a very large value for the expected uncompressed size that wraps around, leading to incorrect memory allocation or buffer handling.

**Impact:** Memory corruption, leading to crashes or potentially exploitable vulnerabilities.

**Risk Severity:** High

**Mitigation Strategies:**
* **Developers:**  Thoroughly validate input sizes before passing them to zlib functions. Use appropriate data types to prevent overflows. Be aware of potential integer wrapping issues.
* **Users:** This is primarily a developer concern.

