# Threat Model Analysis for android/nowinandroid

## Threat: [Malicious Build Variant Substitution](./threats/malicious_build_variant_substitution.md)

*   **Threat:** Malicious Build Variant Substitution

    *   **Description:** An attacker creates a modified version of the app, mimicking a legitimate build variant (e.g., a "debug" build with added malicious code, but more critically, a *release* build). They distribute this fake app through unofficial channels (sideloading, phishing). The attacker's goal is to distribute a seemingly legitimate app that steals data, performs malicious actions, or compromises the device. This exploits NiA's use of build variants for different configurations.
    *   **Impact:** User data compromise, device compromise, reputational damage, financial loss.
    *   **Affected Component:** Gradle build system, build variants (especially release builds), app signing process.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Robust code signing for *all* release builds. Use Play App Signing. Regularly monitor for unauthorized app distributions (e.g., using app distribution monitoring services). Consider code obfuscation to make reverse engineering more difficult.
        *   **User:** Only install apps from the official Google Play Store. Avoid sideloading.

## Threat: [Dependency Manipulation (Supply Chain Attack)](./threats/dependency_manipulation__supply_chain_attack_.md)

*   **Threat:** Dependency Manipulation (Supply Chain Attack)

    *   **Description:** An attacker compromises a third-party library that NiA depends on. This could be a Jetpack library, a networking library, or any other dependency. The attacker injects malicious code into the library, which is then pulled into the NiA app during the build process. This is a highly sophisticated attack targeting the software supply chain. Because NiA relies on a modern Android stack with many dependencies, this is a significant risk.
    *   **Impact:** Potentially severe and wide-ranging, from data theft to complete device compromise, depending on the compromised library and the nature of the injected code.
    *   **Affected Component:** `build.gradle.kts` files (project and module level), all modules using external libraries.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:** Use dependency verification (Gradle's built-in features). Regularly update dependencies to their *latest secure* versions (not just the newest). Use a Software Composition Analysis (SCA) tool to identify known vulnerable dependencies. Pin dependencies to specific versions (and use a lockfile – `versions.toml` in NiA) to prevent unexpected updates, *but* balance this with the need to apply security updates. Use only trusted repositories (Maven Central, Google's Maven repository). Consider using a private repository with vetted dependencies.

## Threat: [Sensitive Data Exposure in Logs](./threats/sensitive_data_exposure_in_logs.md)

*   **Threat:** Sensitive Data Exposure in Logs

    *   **Description:** The NiA app, due to its complex data flow and offline-first nature, inadvertently logs sensitive information. This could include user data, API keys (if not handled properly), internal data structures related to synchronization, or authentication tokens. An attacker gaining access to device logs (through another malicious app or physical access) could exploit this.
    *   **Impact:** Information disclosure, privacy violations, potential for credential compromise and subsequent attacks.
    *   **Affected Component:** All modules; any code that uses logging (e.g., `Log.d`, `Log.e`, or custom logging).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Carefully review *all* logging statements. Use different log levels appropriately. *Sanitize or redact* sensitive information *before* logging. Use a logging library that supports redaction/masking. Configure logging levels differently for debug and release builds (disable verbose logging in release builds). Avoid logging sensitive data structures directly.

## Threat: [Data Leakage through EncryptedSharedPreferences (Incorrect Usage)](./threats/data_leakage_through_encryptedsharedpreferences__incorrect_usage_.md)

*   **Threat:** Data Leakage through EncryptedSharedPreferences (Incorrect Usage)

    *   **Description:** While NiA uses `EncryptedSharedPreferences` for supposedly secure storage, *incorrect usage* can still lead to data leakage.  The most critical risk is improper key management: hardcoded keys, keys stored insecurely, or keys that are not rotated. An attacker gaining access to the device could potentially decrypt the data if the keys are compromised.
    *   **Impact:** Information disclosure; defeats the purpose of using `EncryptedSharedPreferences`.
    *   **Affected Component:** `core:datastore` module, specifically the `EncryptedSharedPreferences` implementation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Follow *strict* best practices for key management. *Never* hardcode encryption keys. Use the Android Keystore system to securely store and manage keys. Ensure keys are properly rotated and revoked when necessary. Understand the different key generation and storage options provided by the Android Keystore.

