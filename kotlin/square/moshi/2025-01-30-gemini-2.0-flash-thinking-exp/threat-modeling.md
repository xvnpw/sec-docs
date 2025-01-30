# Threat Model Analysis for square/moshi

## Threat: [Malicious Payload Deserialization](./threats/malicious_payload_deserialization.md)

*   **Description:** An attacker sends a crafted JSON payload to the application. This payload is specifically designed to exploit vulnerabilities in custom Moshi `JsonAdapter` implementations or unexpected parsing behavior within Moshi itself. The attacker's goal is to cause severe application instability, resource exhaustion leading to denial of service, or in extremely rare and unlikely scenarios, attempt to execute arbitrary code if a highly vulnerable custom adapter exists.
*   **Impact:** Application crash (Critical DoS), resource exhaustion (High DoS), potential data corruption, in extremely unlikely scenarios, potential for remote code execution if custom adapters are severely flawed.
*   **Moshi Component Affected:** `Moshi` instance, `JsonAdapter` (especially custom adapters), `JsonReader`.
*   **Risk Severity:** High to Critical (depending on application context and custom adapter complexity).
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Implement robust schema validation against a well-defined schema *before* any deserialization occurs. Reject payloads that do not conform to the expected structure.
    *   **Secure Custom Adapter Development:**  Treat custom `JsonAdapter` development with extreme caution. Conduct rigorous security reviews and penetration testing specifically targeting custom adapters, especially those handling complex or sensitive data types. Employ secure coding practices and avoid using reflection or dynamic code execution within adapters if possible.
    *   **Deserialization Sandboxing (Advanced):** In highly sensitive applications, consider isolating deserialization processes within sandboxed environments to limit the impact of potential vulnerabilities.
    *   **Regular and Timely Moshi Updates:**  Prioritize keeping the Moshi library updated to the latest version to benefit from critical bug fixes and security patches. Monitor Moshi's release notes and security advisories closely.

## Threat: [Denial of Service via Large Payload](./threats/denial_of_service_via_large_payload.md)

*   **Description:** An attacker floods the application with extremely large and/or deeply nested JSON payloads. The intent is to overwhelm the application's JSON parsing capabilities within Moshi, leading to excessive consumption of server resources (CPU, memory, network bandwidth). This results in application slowdowns, instability, and ultimately, denial of service for legitimate users.
*   **Impact:** Application slowdown, complete denial of service (Critical DoS), system instability, resource exhaustion, significant impact on application availability and user experience.
*   **Moshi Component Affected:** `Moshi` instance, `JsonReader`, JSON parsing process, potentially `BufferedSource` if used directly.
*   **Risk Severity:** High to Critical (depending on application resource limits, exposure to public networks, and resilience to DoS attacks).
*   **Mitigation Strategies:**
    *   **Aggressive Payload Size Limits:** Implement strict and enforced limits on the maximum size of incoming JSON payloads at the application gateway or load balancer level, *before* they reach Moshi for parsing.
    *   **Rate Limiting and Throttling:** Implement robust rate limiting and request throttling mechanisms to restrict the number of JSON requests from a single source within a given timeframe. This helps mitigate volumetric DoS attacks.
    *   **Resource Monitoring and Alerting:** Implement comprehensive real-time monitoring of application resource usage (CPU, memory, network). Set up alerts to trigger when resource consumption exceeds predefined thresholds, indicating a potential DoS attack.
    *   **Asynchronous and Non-Blocking Processing:**  Process JSON payloads asynchronously and in a non-blocking manner to prevent blocking the main application thread and maintain responsiveness under heavy load. Utilize techniques like reactive programming or asynchronous task queues.
    *   **Load Balancing and Scalability:** Employ load balancing and horizontal scaling to distribute incoming JSON processing load across multiple application instances, increasing resilience to DoS attacks.

