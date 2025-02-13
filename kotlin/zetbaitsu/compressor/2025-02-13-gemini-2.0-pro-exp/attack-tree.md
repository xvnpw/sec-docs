# Attack Tree Analysis for zetbaitsu/compressor

Objective: Execute arbitrary code, leak data, or cause DoS via `zetbaitsu/compressor`

## Attack Tree Visualization

```
Attacker Goal: Execute arbitrary code, leak data, or cause DoS via zetbaitsu/compressor

├── 1. Denial of Service (DoS) [HIGH RISK]
│   ├── 1.1. Compression Bomb (Zip Bomb, Brotli Bomb, etc.) [HIGH RISK]
│   │   ├── 1.1.1.  Craft a highly compressed archive that expands to an enormous size. [CRITICAL]
│   │   │   ├── 1.1.1.1.  Submit the bomb via a form or API endpoint that uses compressor. [HIGH RISK]
│   │   │   │   └── Action:  Application attempts to decompress, consuming excessive memory/CPU.
│   │   │   └── 1.1.1.2.  Exploit lack of size limits *before* decompression. [HIGH RISK] [CRITICAL]
│   │   │       └── Action:  Bypass any initial size checks, then trigger decompression.
```

## Attack Tree Path: [1. Denial of Service (DoS) [HIGH RISK]](./attack_tree_paths/1__denial_of_service__dos___high_risk_.md)

*   **Description:** This category encompasses attacks aimed at making the application or server unavailable to legitimate users. The high risk stems from the relative ease of exploiting compression-related vulnerabilities to achieve DoS.

## Attack Tree Path: [1.1. Compression Bomb (Zip Bomb, Brotli Bomb, etc.) [HIGH RISK]](./attack_tree_paths/1_1__compression_bomb__zip_bomb__brotli_bomb__etc____high_risk_.md)

*   **Description:** This is a specific type of DoS attack where a maliciously crafted compressed file is used.  These files are small when compressed but expand to an extremely large size when decompressed, overwhelming the server's resources.

## Attack Tree Path: [1.1.1. Craft a highly compressed archive that expands to an enormous size. [CRITICAL]](./attack_tree_paths/1_1_1__craft_a_highly_compressed_archive_that_expands_to_an_enormous_size___critical_.md)

*   **Description:** This is the core action of preparing the attack.  The attacker creates a file (or multiple nested files) that utilizes the compression algorithm's features to achieve a very high compression ratio.  For example, a file filled with repeating bytes (like all zeros) can be compressed extremely efficiently.
*   **Techniques:**
    *   **Nested Archives:** Creating archives within archives (e.g., a zip file containing another zip file, and so on) can exponentially increase the expansion size.
    *   **Highly Redundant Data:** Using data with a high degree of repetition maximizes the compression ratio.
    *   **Algorithm-Specific Techniques:** Exploiting specific features of compression algorithms (like Brotli's dictionary) to maximize compression.
*   **Tools:**  Pre-made compression bomb generators are readily available online.  Attackers can also craft them manually using standard compression utilities.

## Attack Tree Path: [1.1.1.1. Submit the bomb via a form or API endpoint that uses compressor. [HIGH RISK]](./attack_tree_paths/1_1_1_1__submit_the_bomb_via_a_form_or_api_endpoint_that_uses_compressor___high_risk_.md)

*   **Description:** The attacker delivers the crafted compressed file to the application. This is typically done through any input vector that the application uses `compressor` on.
*   **Examples:**
    *   **File Upload:** If the application allows users to upload files and uses `compressor` to decompress them, this is a direct attack vector.
    *   **API Endpoint:** If an API endpoint accepts compressed data (e.g., in a request body), the attacker can send the bomb there.
    *   **Form Data:**  Even if a form doesn't explicitly handle file uploads, if it accepts text input that is later compressed, a very long, highly compressible string could be used.
*   **Likelihood:** High (if no size limits are in place).
*   **Impact:** High (system crash, service unavailable).
*   **Effort:** Low.
*   **Skill Level:** Novice.
*   **Detection Difficulty:** Medium.

## Attack Tree Path: [1.1.1.2. Exploit lack of size limits *before* decompression. [HIGH RISK] [CRITICAL]](./attack_tree_paths/1_1_1_2__exploit_lack_of_size_limits_before_decompression___high_risk___critical_.md)

*   **Description:** This highlights the *root cause* vulnerability that makes compression bombs effective.  If the application doesn't check the size of the *compressed* data *before* attempting to decompress it, the attack will likely succeed.
*   **Why it's Critical:**  Even if the application has limits on the *decompressed* size, those limits are useless if the attacker can submit a tiny compressed file that expands beyond those limits.  The check *must* happen before decompression.
*   **Vulnerable Code Example (Illustrative):**
    ```go
    // VULNERABLE: No size check before decompression
    func handleCompressedData(compressedData []byte) {
        decompressedData, err := compressor.Decompress(compressedData) // Decompression happens *before* any size check
        if err != nil {
            // Handle error
        }
        // ... process decompressedData ...
    }
    ```
*   **Secure Code Example (Illustrative):**
    ```go
    const MaxCompressedSize = 1024 * 1024 // 1MB limit on *compressed* size

    func handleCompressedData(compressedData []byte) {
        if len(compressedData) > MaxCompressedSize {
            // Reject the data: Too large *before* decompression
            return errors.New("compressed data exceeds size limit")
        }

        decompressedData, err := compressor.Decompress(compressedData)
        if err != nil {
            // Handle error
        }
        // ... process decompressedData ...
    }
    ```
*   **Likelihood:** High (if size limits are poorly implemented or absent).
*   **Impact:** High (system crash, service unavailable).
*   **Effort:** Low.
*   **Skill Level:** Novice.
*   **Detection Difficulty:** Medium.

