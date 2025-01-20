# Threat Model Analysis for jverkoey/nimbus

## Threat: [Insecure Storage of Cached Images on Disk](./threats/insecure_storage_of_cached_images_on_disk.md)

*   **Description:** If the application relies on Nimbus's default disk caching without implementing additional security measures, an attacker with local access to the device could potentially access sensitive or inappropriate images stored in the cache. This access could be gained through malware, physical access, or other device compromises.
    *   **Impact:** Exposure of potentially sensitive information contained within cached images, privacy violations, potential misuse of exposed content.
    *   **Nimbus Component Affected:** `NIImageDiskCache` module, responsible for storing and retrieving images from the disk cache.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use Secure Cache Location:** Ensure the Nimbus disk cache is stored in a secure location on the device with appropriate file permissions, restricting access to authorized users and applications. Consult platform-specific security guidelines for recommended secure storage locations.
        *   **Encrypt the Cache:** Implement encryption for the Nimbus disk cache, especially if it might contain sensitive information. This adds a layer of protection even if an attacker gains access to the cache files. Utilize platform-provided encryption mechanisms.

## Threat: [Denial of Service (DoS) via Cache Exhaustion](./threats/denial_of_service__dos__via_cache_exhaustion.md)

*   **Description:** An attacker could intentionally trigger the application to request and cache a large number of unique, large images. This could rapidly consume available storage space on the device, potentially leading to application slowdowns, crashes, or even impacting other applications on the device due to lack of storage. This attack directly exploits Nimbus's caching mechanism.
    *   **Impact:** Application slowdown, potential crashes due to disk space exhaustion, degraded user experience, potential impact on other device functionalities due to storage issues.
    *   **Nimbus Component Affected:** `NIImageCache` (both `NIImageMemoryCache` and `NIImageDiskCache`), as the attack targets the caching mechanisms.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Implement Cache Size Limits:** Configure Nimbus with reasonable limits on the maximum size of the cache (both in memory and on disk). Carefully consider the trade-off between performance and storage usage.
        *   **Implement Cache Eviction Strategies:** Utilize Nimbus's cache eviction policies (e.g., LRU - Least Recently Used) to automatically remove less frequently accessed images and prevent the cache from growing indefinitely. Configure appropriate eviction thresholds.
        *   **Rate Limiting on Image Requests (application-level):** Implement rate limiting on the application's image loading requests to prevent an attacker from overwhelming the cache with rapid requests. This is a defense in depth measure.

