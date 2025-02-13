# Attack Surface Analysis for coil-kt/coil

## Attack Surface: [Arbitrary File Access via `file://` Scheme](./attack_surfaces/arbitrary_file_access_via__file__scheme.md)

*   **Description:** Attackers attempt to read local files using the `file://` URL scheme.
    *   **Coil Contribution:** Coil fetches images based on URLs.  If it doesn't *strictly* enforce allowed URL schemes, it *directly* enables this attack.  This is a core responsibility of an image loading library.
    *   **Example:** An attacker provides a URL like `file:///etc/passwd` (or a sensitive app-specific file path) to Coil.
    *   **Impact:** Disclosure of sensitive local files, potentially including credentials, configuration data, or private user information. Could lead to complete device compromise.
    *   **Risk Severity:** *Critical*
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   **Strict URL Validation:** *Never* allow user-provided input to directly construct the URL scheme.  Use a whitelist of allowed schemes (`http://`, `https://`, and *only* if absolutely necessary and carefully validated, `content://`).
            *   **Input Sanitization:** Even with a whitelist, sanitize the rest of the URL to remove malicious characters (e.g., `../`).
            *   **Explicit Scheme Configuration:** If Coil allows configuring allowed schemes, explicitly set it to only the necessary ones.  *Do not* rely on potentially insecure defaults.
            *   **Use `ImageRequest.Builder`:** Prefer Coil's `ImageRequest.Builder` and its methods for constructing requests, rather than manually building URL strings.

## Attack Surface: [Server-Side Request Forgery (SSRF) via Redirection](./attack_surfaces/server-side_request_forgery__ssrf__via_redirection.md)

*   **Description:** Attackers use Coil to make requests to internal or sensitive servers.
    *   **Coil Contribution:** Coil follows HTTP redirects.  If it doesn't validate the target of the redirect *after* following them, it *directly* enables this attack.  Redirect handling is a core part of Coil's functionality.
    *   **Example:** An attacker provides `http://attacker.com/redirect.php` which redirects to `http://localhost:8080/admin` or `http://169.254.169.254/`.
    *   **Impact:** Access to internal services, data breaches, denial of service, or potentially remote code execution on internal systems.
    *   **Risk Severity:** *High* to *Critical*
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   **Limit Redirects:** Configure Coil to limit the number of redirects (e.g., to 2 or 3).
            *   **Validate Redirect Targets:** *Crucially*, validate the final URL *after* all redirects.  Use a whitelist of allowed domains/IPs if possible.  If not, reject loopback addresses, private IPs, and known sensitive URLs.
            *   **Disable Redirects (If Possible):** If redirects are not essential, disable them in Coil's configuration.
            *   **Network Security Configuration (Android):** Use Android's Network Security Configuration to help mitigate some SSRF attacks.

## Attack Surface: [Exploiting Image Decoder Vulnerabilities](./attack_surfaces/exploiting_image_decoder_vulnerabilities.md)

*   **Description:** Attackers craft malformed images to exploit vulnerabilities in image decoders.
    *   **Coil Contribution:** While Coil doesn't *implement* the decoders, it is the *direct conduit* through which malicious image data is passed to these vulnerable components.  The choice of supported image formats and the handling of image data before decoding are relevant.
    *   **Example:** A crafted JPEG image triggers a buffer overflow in the system's JPEG decoder.
    *   **Impact:** Arbitrary code execution, potentially leading to complete device compromise.
    *   **Risk Severity:** *Critical*
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   **System Updates (Indirect):** Encourage users to keep their devices updated (Coil can't directly enforce this).
            *   **Prefer Safer Formats:** Prioritize modern, more secure image formats like WebP over older formats like JPEG, *where feasible*. This is a choice Coil users can make.
            *   **Avoid Custom Decoders:** Unless absolutely necessary and thoroughly security-reviewed, avoid using custom image decoders with Coil.
            * **Sanitize Image Metadata:** If you need to process image metadata (e.g., EXIF data), be *extremely* careful. Use a well-vetted library for parsing metadata and sanitize any data extracted from it before using it.

## Attack Surface: [Content Provider Injection](./attack_surfaces/content_provider_injection.md)

* **Description:** Attackers use specially crafted `content://` URI to access unintended content providers.
    * **Coil Contribution:** Coil can load images from `content://` URIs.
    * **Example:** Attacker provides `content://com.vulnerable.app.provider/data?param=malicious_value`
    * **Impact:** Access to sensitive data, potentially code execution.
    * **Risk Severity:** *High*
    * **Mitigation Strategies:**
        *   **Developer:**
            *   **Strict URI Validation:** Validate and sanitize `content://` URIs.
            *   **Whitelist:** Use whitelist of allowed content providers.
            *   **Avoid User Input:** Avoid using user input to construct `content://` URIs.

