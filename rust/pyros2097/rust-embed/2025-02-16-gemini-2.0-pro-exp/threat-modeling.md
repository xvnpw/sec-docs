# Threat Model Analysis for pyros2097/rust-embed

## Threat: [Pre-Compilation Asset Injection](./threats/pre-compilation_asset_injection.md)

*   **Description:** An attacker gains write access to the directory containing the static assets *before* compilation. They modify existing files (e.g., JavaScript, HTML, CSS) or add new malicious files. `rust-embed` then includes these compromised assets in the final binary. This is a supply-chain attack targeting the build process, directly impacting how `rust-embed` functions.
*   **Impact:**
    *   Execution of arbitrary JavaScript (XSS) in the user's browser.
    *   Data exfiltration (stealing cookies, user input, etc.).
    *   Website defacement or phishing.
    *   Client-side denial-of-service.
*   **Affected Component:** The `RustEmbed` derive macro and the entire asset embedding process. Specifically, the `folder` attribute and the code that reads files from that folder are directly involved. `rust-embed` is the mechanism by which the attack is realized.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Access Control:** Limit write access to the asset directory to authorized personnel and build systems only.
    *   **Code Reviews:** Thoroughly review all changes to static assets, looking for unexpected modifications.
    *   **Secure Build Environment:** Use a clean, isolated, and trusted build environment.
    *   **Pre-Embed Checksum Verification:** Calculate and store cryptographic hashes (e.g., SHA-256) of all assets. Before `rust-embed` processes them, verify that the asset hashes match the stored values.
    *   **Immutable Build Artifacts:** Utilize build systems that generate immutable artifacts to prevent post-staging tampering.

## Threat: [Post-Compilation Binary Modification](./threats/post-compilation_binary_modification.md)

*   **Description:** An attacker gains access to the compiled binary and attempts to modify the embedded assets by reverse-engineering and patching the binary.  This attack targets the data embedded *by* `rust-embed`. The success of this attack depends on how `rust-embed` stores the data within the binary.
*   **Impact:**
    *   Similar to pre-compilation injection: XSS, data exfiltration, defacement, client-side DoS.
*   **Affected Component:** The compiled binary itself, specifically the sections containing the embedded asset data *placed there by `rust-embed`*. The `RustEmbed` implementation details (how it stores the data) are directly relevant to the feasibility of this attack.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Code Signing:** Digitally sign the binary to allow verification of its integrity.
    *   **Binary Hardening:** Employ code obfuscation and anti-tampering techniques (though these are not foolproof).  These techniques make it harder to modify the data that `rust-embed` has included.

## Threat: [Incorrect `RustEmbed` Configuration](./threats/incorrect__rustembed__configuration.md)

*   **Description:** The `#[derive(RustEmbed)]` macro is misconfigured, causing unintended files to be embedded. This could include source code, configuration files, or other sensitive data. This is a direct misuse of the `rust-embed` API.
*   **Impact:**
    *   **Information Disclosure:** Exposure of sensitive data embedded in the binary.
    *   **Increased Attack Surface:** Unnecessary files might introduce new vulnerabilities.
*   **Affected Component:** The `#[derive(RustEmbed)]` macro and its configuration, specifically the `folder` attribute. This is a direct threat related to the usage of the `rust-embed` library.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Careful Configuration:** Double-check the `folder` attribute to ensure it points to the correct directory and includes *only* the intended assets.
    *   **Code Review:** Review the `RustEmbed` configuration during code reviews.
    *   **Testing:** Test the application to verify that only expected assets are accessible and no sensitive files are exposed.
    * **Use `.gitignore`:** Exclude sensitive files from version control to prevent accidental inclusion in the build environment.

