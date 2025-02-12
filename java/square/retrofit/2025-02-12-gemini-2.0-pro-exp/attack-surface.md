# Attack Surface Analysis for square/retrofit

## Attack Surface: [Deserialization Attacks](./attack_surfaces/deserialization_attacks.md)

*   **Description:** Attackers craft malicious responses that exploit vulnerabilities in the deserialization process (using libraries like Gson, Jackson, Moshi) to achieve arbitrary code execution on the client.
*   **Retrofit Contribution:** Retrofit *directly* relies on external converter libraries for deserialization, making this a primary attack vector. Retrofit's design and ease of use can lead developers to overlook the inherent security risks of deserialization. The choice of converter and its configuration is a *direct* Retrofit concern.
*   **Example:** An attacker sends a JSON payload containing a specially crafted object that, when deserialized by a vulnerable version of Jackson with default typing enabled, triggers the execution of malicious code. Or, a malicious payload exploits a known "gadget chain" in a library used by the converter.
*   **Impact:** Complete compromise of the application and potentially the device. Data theft, remote control, and other severe consequences.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Keep Converters Updated:** Always use the latest patched versions of all converter libraries (Gson, Jackson, Moshi, etc.). This is a *direct* action related to Retrofit's configuration.
    *   **Secure Converter Configuration:** Avoid permissive deserialization settings. Disable features like default typing in Jackson unless absolutely necessary and with extreme caution. Thoroughly review the security documentation for your chosen converter *as part of your Retrofit setup*.
    *   **Post-Deserialization Validation:** *Always* validate the deserialized data *after* it's been converted to objects by the Retrofit converter. Check for unexpected values, data types, and ranges. This validation is crucial because of *how* Retrofit handles data.
    *   **Consider Safer Alternatives (High-Security Contexts):** For extremely sensitive applications, explore more restrictive deserialization methods or even manual parsing (if feasible) as an alternative to Retrofit's standard converters. This is a *direct* choice impacting Retrofit's usage.
    *   **Use R8/ProGuard:** Obfuscate and shrink your code to make reverse engineering of the deserialization process (facilitated by Retrofit) more difficult.

## Attack Surface: [Man-in-the-Middle (MitM) Attacks via Improper Certificate Validation](./attack_surfaces/man-in-the-middle__mitm__attacks_via_improper_certificate_validation.md)

*   **Description:** Attackers intercept network traffic, presenting a fake certificate. If the app doesn't properly validate the certificate, the attacker can decrypt and modify the communication.
*   **Retrofit Contribution:** Retrofit, by default, uses the platform's `OkHttpClient`. However, developers often *directly* configure `OkHttpClient` *within* their Retrofit setup. If they override the default certificate validation (e.g., to trust all certificates during development) and forget to remove this override, the app becomes vulnerable. This is a *direct* configuration choice made when using Retrofit.
*   **Example:** A developer uses a custom `TrustManager` that trusts all certificates to bypass HTTPS errors during testing with Retrofit. They accidentally ship this `OkHttpClient` configuration (part of their Retrofit setup) to production.
*   **Impact:** Exposure of sensitive data (credentials, API keys, user data), potential for data modification, and loss of user trust.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Never Disable Certificate Validation in Production:** This is a fundamental security requirement, and it's directly related to how `OkHttpClient` is configured *for* Retrofit.
    *   **Implement Certificate Pinning:** Pin specific certificates or public keys. This is done by configuring the `OkHttpClient` that's *directly* used by Retrofit. This makes MitM attacks much harder.
    *   **Use a Proper `HostnameVerifier`:** Ensure the `HostnameVerifier` is correctly configured (and not disabled) within the `OkHttpClient` used by Retrofit.

