# Attack Surface Analysis for zetbaitsu/compressor

## Attack Surface: [Maliciously Crafted Compressed Data (Exploiting Decompression)](./attack_surfaces/maliciously_crafted_compressed_data__exploiting_decompression_.md)

  *   **Description:** An attacker provides a specially crafted compressed input that exploits vulnerabilities *within the underlying decompression algorithm* itself (e.g., a bug in `zlib`, `brotli`, etc.). This differs from the previous "General" case, which included application-level handling *after* decompression. This focuses solely on the decompression process.
    *   **How Compressor Contributes:** The library is the *direct* interface to the vulnerable decompression algorithm. It receives the malicious input and passes it to the underlying library. The library's choice of underlying libraries and its handling of their output are crucial.
    *   **Example:** An attacker exploits a known buffer overflow vulnerability in a specific version of the `zlib` library used by `compressor`. The `compressor` library, by using that vulnerable `zlib` version, enables the attack.
    *   **Impact:** Remote Code Execution (RCE), Denial of Service (DoS).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Up-to-Date Dependencies:** This is paramount. The `compressor` library *must* keep its underlying compression libraries (e.g., `zlib`, `brotli`, `gzip`) updated to the latest, patched versions. The library should provide a clear and easy way to manage and update these dependencies.
        *   **Dependency Pinning (with Caution):** While pinning dependencies to specific versions can improve stability, it *must not* prevent security updates. The library should either allow flexible version ranges for security patches or provide a mechanism for users to easily override pinned versions for security reasons.
        *   **Library-Level Input Sanitization (Limited):** While comprehensive validation is the application's responsibility *after* decompression, the `compressor` library could perform *basic* sanity checks on the compressed data *before* passing it to the underlying library. This is difficult to do generically, but checks for obviously invalid headers or structures could provide an early line of defense. This is a *supplementary* measure, not a replacement for application-level validation.
        * **Vulnerability Scanning of Dependencies:** The library maintainers should regularly scan their dependencies for known vulnerabilities using tools like Dependabot, Snyk, or similar.

## Attack Surface: [Decompression Bomb / Zip Bomb](./attack_surfaces/decompression_bomb__zip_bomb.md)

    *   **Description:** A small compressed file expands to a vastly larger size, consuming excessive memory or disk space, leading to a Denial of Service (DoS).
    *   **How Compressor Contributes:** The library is the *engine* performing the decompression. Its handling of resource limits during decompression is critical.
    *   **Example:** A 1KB compressed file that expands to 10GB upon decompression. The `compressor` library, if it doesn't have limits, will attempt to allocate the 10GB, causing a DoS.
    *   **Impact:** Denial of Service (DoS) – the application becomes unresponsive or crashes.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Library-Provided Limits (Ideal):** The `compressor` library *should* provide configuration options to limit the maximum allowed size of the decompressed data. This is the most direct and effective mitigation. This should be a *configurable* limit, not a hardcoded one.
        *   **Expansion Ratio Limits (Helpful):** The library could offer an option to limit the maximum expansion ratio (compressed size vs. decompressed size). This is a good supplementary defense.
        *   **Documentation:** The library *must* clearly document the risks of decompression bombs and strongly recommend (or require) the use of size limits.

## Attack Surface: [Path Traversal (If Archive Extraction is Used)](./attack_surfaces/path_traversal__if_archive_extraction_is_used_.md)

    *   **Description:** If the library handles archive extraction (e.g., `.zip` files), an attacker could include filenames with `../` sequences to write files outside the intended extraction directory.
    *   **How Compressor Contributes:** The library is *directly responsible* for handling filenames during archive extraction. If it doesn't sanitize them, it enables the attack.
    *   **Example:** A compressed archive contains a file named `../../../../etc/passwd`. The `compressor` library, if it doesn't sanitize, will attempt to write to that location.
    *   **Impact:** Arbitrary File Write, Potential for Privilege Escalation, System Compromise.
    *   **Risk Severity:** High (if archive extraction is supported; otherwise, Not Applicable)
    *   **Mitigation Strategies:**
        *   **Mandatory Filename Sanitization:** The library *must* rigorously sanitize filenames to prevent path traversal. This is a non-negotiable security requirement if archive extraction is supported. It should reject or modify any filename containing `../`, absolute paths, or other potentially dangerous characters. There should be *no way* to disable this sanitization.
        *   **Clear Documentation:** The library's documentation must clearly state its policy on filename sanitization and warn users about the risks of path traversal.

