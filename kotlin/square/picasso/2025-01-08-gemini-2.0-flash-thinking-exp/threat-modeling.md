# Threat Model Analysis for square/picasso

## Threat: [Man-in-the-Middle (MitM) Attacks on Image Downloads](./threats/man-in-the-middle__mitm__attacks_on_image_downloads.md)

**Description:** An attacker intercepts network traffic between the application and the image server. They can then replace the legitimate image with a malicious one before it reaches the application. This is possible if the application uses insecure HTTP connections for image loading *through Picasso* or if *Picasso's* certificate validation is not properly implemented or bypassed.

**Impact:** Displaying misleading, offensive, or malicious content to the user. If the application relies on the integrity of the image for functionality (e.g., QR codes, product images with specific details), this could lead to further exploitation or incorrect actions by the user.

**Affected Picasso Component:** `Downloader` interface (specifically implementations like `OkHttp3Downloader` or `URLConnectionDownloader` *used by Picasso*).

**Risk Severity:** High

**Mitigation Strategies:**
*   **Enforce HTTPS:** Always use HTTPS for image URLs loaded *through Picasso* to encrypt network traffic.
*   **Implement Certificate Pinning:** Validate the server's SSL certificate against a known good certificate *within the Picasso configuration or the underlying Downloader*.
*   **Ensure Underlying Libraries are Up-to-Date:** Keep the underlying HTTP client library (e.g., OkHttp *used by Picasso*) updated to patch any known vulnerabilities related to secure connections.

## Threat: [Cache Poisoning](./threats/cache_poisoning.md)

**Description:** An attacker manipulates *Picasso's* local image cache (disk or memory) to replace legitimate cached images with malicious ones. This could happen if the cache directory has insecure permissions allowing other applications or processes to write to it, or if other vulnerabilities in the application allow file manipulation *of Picasso's cache*.

**Impact:** Displaying misleading, offensive, or malicious content to the user, even when the device is offline or the original image source is unavailable. If the application relies on the integrity of cached images *managed by Picasso* for security-sensitive features, this could lead to further exploitation.

**Affected Picasso Component:** `Cache` interface (both DiskLruCache and LruCache implementations *within Picasso*).

**Risk Severity:** High

**Mitigation Strategies:**
*   **Secure Cache Directory Permissions:** Ensure *Picasso's* cache directory has appropriate permissions, restricting access only to the application's user.
*   **Implement Integrity Checks:** Consider implementing integrity checks for cached images *managed by Picasso*, such as storing and verifying checksums or cryptographic signatures.
*   **Avoid Relying on Cached Image Integrity for Critical Security Decisions:** Do not base security-sensitive logic solely on the content of cached images *retrieved from Picasso's cache* without re-validation when necessary.

