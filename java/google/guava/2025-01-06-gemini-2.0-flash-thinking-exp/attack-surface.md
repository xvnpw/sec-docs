# Attack Surface Analysis for google/guava

## Attack Surface: [Denial of Service (DoS) via Hash Collisions in Collections](./attack_surfaces/denial_of_service__dos__via_hash_collisions_in_collections.md)

* **Description:** An attacker crafts input data that causes a large number of hash collisions in Guava's hash-based collections (like `HashMultimap`, `HashSet` when using custom objects without proper `hashCode()` implementation, or when using `ImmutableSet.copyOf()` with malicious objects). This leads to excessive CPU usage as the collection struggles to manage the collisions, effectively causing a denial of service.
    * **How Guava Contributes to the Attack Surface:** Guava provides various hash-based collection implementations. While Guava's own hashing algorithms are generally robust, the underlying Java `HashMap` implementation (used by many Guava collections) can be susceptible to collision attacks if the keys have predictable or manipulatable hash codes. Using Guava's immutable collections by copying from potentially malicious iterables can also inherit this risk.
    * **Example:** An application uses `HashMultimap` to store user attributes. An attacker sends a request with multiple attributes designed to have the same hash code, causing performance degradation and potentially crashing the application due to CPU exhaustion.
    * **Impact:** Application becomes slow or unresponsive, potentially leading to service outages.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Use Randomization in Key Generation:** If possible, introduce randomness into the key generation process to make hash collisions less predictable.
        * **Limit Input Sizes:** Restrict the number of elements that can be added to Guava's hash-based collections from untrusted sources.
        * **Monitor CPU Usage:** Implement monitoring to detect unusually high CPU usage, which could indicate a hash collision attack.
        * **Consider Alternative Data Structures:** For security-critical applications, consider using data structures less susceptible to hash collision attacks, although this might involve trade-offs in performance or functionality.
        * **Review Custom `hashCode()` Implementations:** Ensure that custom objects used as keys in Guava's hash-based collections have well-distributed and collision-resistant `hashCode()` implementations.

## Attack Surface: [Regular Expression Denial of Service (ReDoS) via `Splitter` or `CharMatcher`](./attack_surfaces/regular_expression_denial_of_service__redos__via__splitter__or__charmatcher_.md)

* **Description:** An attacker provides a carefully crafted input string that causes the regular expression engine used by Guava's `Splitter` or `CharMatcher` to backtrack excessively, leading to high CPU usage and a denial of service.
    * **How Guava Contributes to the Attack Surface:** Guava's `Splitter` and `CharMatcher` classes often utilize regular expressions for string manipulation. If these regular expressions are complex or not carefully designed, they can be vulnerable to ReDoS attacks when processing malicious input.
    * **Example:** An application uses `Splitter.on(Pattern.compile("a+b+c+")).split(userProvidedString)` to parse a string. An attacker provides a string like "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" which causes the regex engine to backtrack extensively, consuming significant CPU resources.
    * **Impact:** Application becomes slow or unresponsive, potentially leading to service outages.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Use Simple and Efficient Regular Expressions:** Avoid overly complex or nested regular expressions when using Guava's `Splitter` or `CharMatcher`.
        * **Set Timeouts for Regex Operations:** Implement timeouts for regex matching operations within the context of `Splitter` or `CharMatcher` usage to prevent them from running indefinitely.
        * **Input Validation and Sanitization:** Validate and sanitize user-provided input before using it with Guava's `Splitter` or `CharMatcher`. Consider limiting the length of the input string.
        * **Consider Alternative String Processing Methods:** If possible, explore alternative string processing methods that do not rely on potentially vulnerable regular expressions when using Guava.

## Attack Surface: [Resource Exhaustion via Unbounded Caches](./attack_surfaces/resource_exhaustion_via_unbounded_caches.md)

* **Description:** An attacker can cause the application to consume excessive memory by inserting a large number of unique entries into a Guava cache that lacks proper eviction policies or size limits.
    * **How Guava Contributes to the Attack Surface:** Guava provides powerful caching mechanisms (`LoadingCache`, `CacheBuilder`). If these caches are not configured with appropriate size limits (e.g., `maximumSize`, `maximumWeight`) or time-based eviction policies (e.g., `expireAfterAccess`, `expireAfterWrite`), they can grow indefinitely, leading to memory exhaustion.
    * **Example:** An application uses a `LoadingCache` to store user-specific data. An attacker can repeatedly trigger requests for unique user IDs, causing the cache to grow without bound, eventually leading to an `OutOfMemoryError`.
    * **Impact:** Application crashes due to memory exhaustion, leading to service outages.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Set Maximum Size Limits:** Configure Guava caches with `CacheBuilder.maximumSize(long)` or `CacheBuilder.maximumWeight(long, Weigher)` to limit the number of entries.
        * **Implement Time-Based Eviction:** Use `CacheBuilder.expireAfterAccess(Duration)` or `CacheBuilder.expireAfterWrite(Duration)` when configuring Guava caches to evict entries after a certain period of inactivity or creation.
        * **Monitor Cache Size:** Implement monitoring to track the size of Guava caches and receive alerts when they approach predefined limits.

## Attack Surface: [Cache Poisoning via Untrusted Data in Cache Loading](./attack_surfaces/cache_poisoning_via_untrusted_data_in_cache_loading.md)

* **Description:** If the loading function of a Guava `LoadingCache` relies on external, untrusted data sources without proper validation, an attacker can manipulate this data to insert malicious or incorrect entries into the cache. Subsequent requests will then retrieve this poisoned data.
    * **How Guava Contributes to the Attack Surface:** Guava's `LoadingCache` simplifies the process of automatically loading values into the cache when they are requested but not present. If the `CacheLoader` used with Guava's `LoadingCache` retrieves data from untrusted sources, it becomes a potential attack vector.
    * **Example:** A `LoadingCache` retrieves user roles from a database based on a user ID. If an attacker can manipulate the database or intercept the communication, they could inject incorrect roles for a user, leading to unauthorized access or privilege escalation.
    * **Impact:** Application logic is based on incorrect or malicious data, potentially leading to security breaches, data corruption, or incorrect functionality.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Validate Data from External Sources:** Thoroughly validate and sanitize any data retrieved from external sources before loading it into the Guava cache.
        * **Secure Communication Channels:** Ensure secure communication channels (e.g., HTTPS, TLS) when retrieving data for the Guava cache loader.
        * **Implement Integrity Checks:** Implement mechanisms to verify the integrity of the data being loaded into the Guava cache.
        * **Principle of Least Privilege:** Ensure the credentials used by the Guava cache loader have the minimum necessary permissions to access the data source.

