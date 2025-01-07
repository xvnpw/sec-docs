# Threat Model Analysis for coil-kt/coil

## Threat: [Loading Malicious Images from Untrusted Sources](./threats/loading_malicious_images_from_untrusted_sources.md)

**Description:** An attacker could influence the application to load images from URLs pointing to malicious image files. This could be achieved by compromising a backend service providing image URLs, manipulating user input, or through other means of injecting malicious URLs. Coil's `ImageLoader` or request builders would then fetch and attempt to process these images.

**Impact:** Display of offensive or misleading content, exploitation of vulnerabilities in image decoding libraries leading to application crashes, denial of service, or potentially even remote code execution if the underlying platform has such vulnerabilities.

**Affected Coil Component:** `ImageLoader`, `RequestBuilders`, `NetworkFetcher`

**Risk Severity:** High

**Mitigation Strategies:**
*   Strictly validate and sanitize all image URLs before passing them to Coil.
*   Implement Content Security Policy (CSP) on backend services providing image URLs (if applicable).
*   Prefer loading images from trusted and controlled sources.
*   Consider using Coil's transformations to sanitize or validate image content (though this is limited).

## Threat: [Man-in-the-Middle (MITM) Attacks on Image Downloads](./threats/man-in-the-middle__mitm__attacks_on_image_downloads.md)

**Description:** An attacker positioned between the application and the image server could intercept network traffic and replace legitimate image data with malicious content. Coil's `NetworkFetcher` is responsible for downloading image data.

**Impact:** Display of altered or malicious images, potential exploitation of image decoding vulnerabilities if the attacker injects specially crafted images.

**Affected Coil Component:** `NetworkFetcher`

**Risk Severity:** High

**Mitigation Strategies:**
*   **Enforce HTTPS for all image requests.** Ensure the application only loads images from `https://` URLs.
*   Implement certificate pinning for the image server to prevent MITM attacks even with compromised Certificate Authorities (advanced).

