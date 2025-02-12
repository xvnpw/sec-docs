# Attack Surface Analysis for google/guava

## Attack Surface: [Cache Poisoning/Pollution](./attack_surfaces/cache_poisoningpollution.md)

*   **Description:** An attacker manipulates input used to generate cache keys, causing the cache to store incorrect or malicious data.
*   **Guava Contribution:** Guava's `com.google.common.cache` provides caching functionality.  Improper key generation using user input is the core issue.
*   **Example:**  A user-provided ID is used directly as a cache key.  An attacker provides a crafted ID (e.g., `../../../sensitive_data`) to potentially retrieve or overwrite data outside the intended scope.  Or, an attacker provides a very long string as an ID, causing the cache key to be excessively large, contributing to DoS.
*   **Impact:** Data corruption, information disclosure, denial of service, potential code execution (if cached data is deserialized unsafely).
*   **Risk Severity:** High (Potentially Critical if sensitive data is cached or if it leads to code execution).
*   **Mitigation Strategies:**
    *   **Sanitize and Validate Input:**  Thoroughly validate and sanitize any user-supplied input *before* using it to generate cache keys.  Use a whitelist approach where possible.
    *   **Use Trusted Key Sources:**  Prefer generating cache keys from trusted internal data rather than directly from user input.
    *   **Hash Input:**  Consider using a cryptographic hash (e.g., SHA-256) of the user input as the cache key, ensuring a fixed-size and predictable key.
    *   **Implement Cache Limits:**  Configure `maximumSize`, `expireAfterWrite`, and `expireAfterAccess` to prevent cache exhaustion.
    *   **Monitor Cache Behavior:**  Monitor cache hit rates, miss rates, and size in production to detect anomalies.

## Attack Surface: [Denial of Service (DoS) via Cache Exhaustion](./attack_surfaces/denial_of_service__dos__via_cache_exhaustion.md)

*   **Description:** An attacker floods the cache with entries, consuming excessive memory and causing the application to crash or become unresponsive.
*   **Guava Contribution:** Guava's `com.google.common.cache` is the target.  Lack of proper size limits and eviction policies enables the attack.
*   **Example:** An attacker repeatedly requests data with unique, non-existent keys, forcing the cache to grow unbounded.
*   **Impact:** Application unavailability, resource exhaustion.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Configure Cache Limits:**  *Always* set `maximumSize` to a reasonable value based on available memory and expected usage.
    *   **Implement Eviction Policies:**  Use `expireAfterWrite` and/or `expireAfterAccess` to automatically remove stale entries.
    *   **Rate Limiting:**  Implement rate limiting on requests that populate the cache to prevent rapid filling.
    *   **Monitor Cache Size:**  Monitor the cache size and eviction counts in production.

## Attack Surface: [Weak Hash Function Usage](./attack_surfaces/weak_hash_function_usage.md)

*   **Description:** Using cryptographically weak hash functions (e.g., MD5, SHA-1) for security-sensitive operations.
*   **Guava Contribution:** Guava's `com.google.common.hash` provides these hash functions.  The vulnerability is in choosing the wrong function.
*   **Example:**  Using `Hashing.md5()` to hash passwords.
*   **Impact:**  Compromised security (e.g., easier password cracking).
*   **Risk Severity:** High (if used for passwords or other critical security functions)
*   **Mitigation Strategies:**
    *   **Use Strong Hash Functions:**  Use strong, modern hash functions like SHA-256 (`Hashing.sha256()`) or SHA-3.
    *   **Use Dedicated Password Hashing Libraries:**  For password hashing, use a dedicated library like bcrypt, scrypt, or Argon2, which are designed to be resistant to brute-force attacks.  *Never* use a simple hash function for passwords.

