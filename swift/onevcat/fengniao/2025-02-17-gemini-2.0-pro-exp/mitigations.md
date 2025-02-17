# Mitigation Strategies Analysis for onevcat/fengniao

## Mitigation Strategy: [Leverage Fengniao's Exclusion Options](./mitigation_strategies/leverage_fengniao's_exclusion_options.md)

*   **Description:**
    1.  **Identify Critical Resources:** Create a list of files, directories, or file types that are *known* to be used, even if `fengniao` might not detect them. This includes:
        *   Resources loaded dynamically.
        *   Resources used by third-party libraries.
        *   Resources used only in specific build configurations.
    2.  **Use `-x` or `--exclude`:**  When running `fengniao`, use the `-x` or `--exclude` option (or the appropriate option for your `fengniao` version) to specify these exclusions.  For example:
        ```bash
        fengniao -x Resources/DynamicImages -x Libraries/ThirdPartyLib/Resources
        ```
    3.  **Maintain an Exclusion List:** Create a text file (e.g., `fengniao_exclusions.txt`) to store your exclusion rules.  This makes it easier to manage and reuse them. You could then use a script to read this file and pass the exclusions to `fengniao`.
    4.  **Regularly Review:** Periodically review and update your exclusion list as your project evolves.

*   **List of Threats Mitigated:**
    *   **Accidental Deletion of Necessary Resources:** (Severity: High) - Directly prevents the deletion of known critical resources.
    *   **Dependency Issues:** (Severity: Medium) - Protects resources used by third-party libraries.

*   **Impact:**
    *   **Accidental Deletion of Necessary Resources:** Risk significantly reduced (proactive prevention).
    *   **Dependency Issues:** Risk significantly reduced (proactive prevention).

*   **Currently Implemented:**
    *   Developers are aware of the `-x` option.

*   **Missing Implementation:**
    *   Centralized, maintained exclusion list (`fengniao_exclusions.txt`).
    *   Automated script to incorporate the exclusion list into `fengniao` execution.
    *   Regular, scheduled reviews of the exclusion list.

## Mitigation Strategy: [Verify Fengniao's Integrity](./mitigation_strategies/verify_fengniao's_integrity.md)

*   **Description:**
    1.  **Official Source:** Download `fengniao` *only* from the official GitHub repository: [https://github.com/onevcat/fengniao](https://github.com/onevcat/fengniao).
    2.  **Checksum Verification (If Available):** If the `fengniao` release provides checksums (e.g., SHA-256), download the checksum file and use a tool (like `shasum` on macOS/Linux) to verify the downloaded `fengniao` executable matches the expected checksum.
    3.  **Trusted Package Manager:** If using a package manager (e.g., Homebrew), ensure it's configured to use trusted repositories.
    4.  **Regular Updates:** Keep `fengniao` updated to the latest version to benefit from bug fixes and potential security improvements.

*   **List of Threats Mitigated:**
    *   **Tampering with Fengniao:** (Severity: Low, but potentially very high impact) - Ensures you're using a legitimate, unmodified version of the tool.

*   **Impact:**
    *   **Tampering with Fengniao:** Risk significantly reduced.

*   **Currently Implemented:**
    *   `fengniao` was initially downloaded from the official GitHub repository.

*   **Missing Implementation:**
    *   Checksum verification (if checksums are provided by the developers).
    *   Automated update checks for `fengniao`.

## Mitigation Strategy: [Pre-Deletion Review within Fengniao](./mitigation_strategies/pre-deletion_review_within_fengniao.md)

*   **Description:**
   1. **Run Fengniao in Preview/Dry-Run Mode (If Supported):** If `fengniao` has a preview or dry-run mode (often indicated by a flag like `-n` or `--dry-run`), *always* use it first. This will show you the files it *would* delete without actually deleting them.
   2. **Examine the Output Carefully:** Scrutinize the list of files `fengniao` proposes to delete. Look for:
        * Files you recognize as being actively used.
        * Files belonging to third-party libraries.
        * Files with names suggesting dynamic loading.
        * Any file you are uncertain about.
   3. **Adjust Exclusions if Necessary:** If you find files in the preview that should *not* be deleted, add them to your exclusion list (see Mitigation Strategy #1) *before* running `fengniao` for real.
   4. **Run Fengniao for Real (Without Preview):** Only after you are completely satisfied with the preview and have adjusted your exclusions, run `fengniao` without the preview/dry-run flag to perform the actual deletion.

*   **List of Threats Mitigated:**
    *   **Accidental Deletion of Necessary Resources:** (Severity: High) - Provides a direct opportunity to prevent incorrect deletions *before* they happen.
    *   **Dependency Issues:** (Severity: Medium) - Allows you to identify and protect resources used by dependencies.

*   **Impact:**
    *   **Accidental Deletion of Necessary Resources:** Risk significantly reduced (proactive prevention).
    *   **Dependency Issues:** Risk significantly reduced (proactive prevention).

*   **Currently Implemented:**
    *   Developers are instructed to manually review the output before confirming deletion.

*   **Missing Implementation:**
    *   Formalized checklist for the pre-deletion review process.
    *   Enforcement of using a dry-run mode (if available) before actual deletion.
    *   Integration of this review step into the automated `fengniao` execution script (if one is created).

