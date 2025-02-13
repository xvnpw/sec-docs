# Threat Model Analysis for afnetworking/afnetworking

## Threat: [Spoofing: Man-in-the-Middle (MitM) Attack via Certificate Validation Bypass](./threats/spoofing_man-in-the-middle__mitm__attack_via_certificate_validation_bypass.md)

*   **Description:** An attacker positions themselves between the client and server. They present a fake certificate. Due to misconfiguration of `AFSecurityPolicy` (e.g., `allowInvalidCertificates = YES`, incorrect or missing `pinnedCertificates`, or `validatesDomainName = NO`) or an outdated AFNetworking version with known TLS vulnerabilities, the fake certificate is *not* rejected. The attacker intercepts and decrypts (and potentially modifies) the communication.
    *   **Impact:** Complete compromise of communication confidentiality and integrity. Sensitive data (credentials, personal information, API keys) are exposed. The attacker can inject malicious data.
    *   **Affected AFNetworking Component:** `AFSecurityPolicy`, specifically the `allowInvalidCertificates`, `validatesDomainName`, and `pinnedCertificates` properties. The underlying `NSURLSession` TLS handling is also relevant, but the misconfiguration of `AFSecurityPolicy` is the direct cause.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Certificate Pinning:** Use `AFSecurityPolicy` to pin to the specific server certificate (or its public key).  Set `allowInvalidCertificates = NO` and `validatesDomainName = YES`. Pin to the leaf certificate or a tightly controlled intermediate CA, *not* a widely trusted root CA.
        *   **Regular Updates:** Keep AFNetworking updated to the latest version to benefit from security patches and improvements in certificate validation.
        *   **Certificate Expiration Monitoring:** Implement a system to monitor pinned certificate expiration and update them proactively.
        *   **Public Key Pinning (Advanced):** Consider pinning to the public key instead of the certificate, but be aware of key rotation complexities.

## Threat: [Tampering: Insecure Deserialization leading to Remote Code Execution (RCE)](./threats/tampering_insecure_deserialization_leading_to_remote_code_execution__rce_.md)

*   **Description:** An attacker crafts a malicious server response.  If the application uses an older, vulnerable version of AFNetworking, *or* if it uses a custom `AFHTTPResponseSerializer` that insecurely deserializes data (especially using `NSKeyedUnarchiver` without `NSSecureCoding` and proper class allow-listing), the attacker can execute arbitrary code on the client device.
    *   **Impact:** Complete control over the application and potentially the device. Data theft, malware installation, and other malicious actions are possible.
    *   **Affected AFNetworking Component:** `AFHTTPResponseSerializer` and its subclasses (especially custom implementations). Potentially `AFPropertyListResponseSerializer` if misused. The underlying `NSKeyedUnarchiver` is the primary vulnerability point if used incorrectly.
    *   **Risk Severity:** Critical (if exploitable)
    *   **Mitigation Strategies:**
        *   **Use Latest AFNetworking:** Update to the latest version. Newer versions have improved security around serialization.
        *   **Avoid `NSKeyedUnarchiver` with Untrusted Data:** Do *not* use `NSKeyedUnarchiver` directly with data from the server unless absolutely necessary.
        *   **Secure Coding with `NSKeyedUnarchiver` (if unavoidable):** If you *must* use it, use `NSSecureCoding` and explicitly specify allowed classes via `setAllowedClasses:`. Use a strict allow list.
        *   **Prefer Safer Serializers:** Use `AFJSONResponseSerializer` (for JSON) or other safer serializers whenever possible.
        *   **Input Validation:** *Always* validate data from the server *before* deserialization, regardless of the serializer.

## Threat: [Information Disclosure: Exposure of Sensitive Data in URLs or Headers (due to incorrect AFNetworking usage)](./threats/information_disclosure_exposure_of_sensitive_data_in_urls_or_headers__due_to_incorrect_afnetworking__eb5d38b9.md)

* **Description:** The application code incorrectly includes sensitive data (API keys, tokens) in URL query parameters or in HTTP headers *when configuring requests through AFNetworking*. This is a developer error in *how* AFNetworking is used, but AFNetworking is the mechanism by which the data is exposed.
    * **Impact:** Leakage of sensitive data, leading to potential account compromise or unauthorized access.
    * **Affected AFNetworking Component:** All components used to construct and send requests (`AFHTTPSessionManager`, `AFURLSessionManager`). The vulnerability is in the application's *use* of these, not the components themselves, but they are the direct conduit.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   **Never in URLs:** *Never* include sensitive data in URL query parameters.
        *   **`Authorization` Header:** Use the HTTP `Authorization` header for authentication tokens (e.g., `Authorization: Bearer <token>`).
        *   **POST for Sensitive Data:** Use HTTP POST requests with sensitive data in the request body.
        *   **Code Review:** Thoroughly review all code interacting with AFNetworking.

