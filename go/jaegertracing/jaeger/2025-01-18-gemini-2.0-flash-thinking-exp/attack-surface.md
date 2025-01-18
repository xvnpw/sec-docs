# Attack Surface Analysis for jaegertracing/jaeger

## Attack Surface: [Unauthenticated Span Submission to Jaeger Agent](./attack_surfaces/unauthenticated_span_submission_to_jaeger_agent.md)

*   **Description:** The Jaeger Agent, by default, listens on UDP and potentially gRPC for incoming spans without requiring authentication.
    *   **How Jaeger Contributes:** Jaeger's design relies on Agents deployed alongside applications to efficiently collect and batch spans. This local deployment often prioritizes ease of use over immediate authentication requirements.
    *   **Example:** An attacker on the same network segment as the application instances could craft and send a large volume of arbitrary spans to the Agent's UDP/gRPC port.
    *   **Impact:**
        *   Resource exhaustion on the Agent, potentially impacting its ability to process legitimate spans.
        *   Data poisoning in the tracing system, leading to misleading performance analysis and debugging.
        *   Potential for injecting malicious data that could exploit vulnerabilities in downstream components (Collector, storage).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Network Segmentation:** Isolate the network segment where application instances and Jaeger Agents reside, limiting access from untrusted networks.
        *   **Agent Authentication (gRPC):** If using gRPC for Agent communication, enable authentication mechanisms provided by gRPC.
        *   **Rate Limiting:** Implement rate limiting on the Agent to prevent it from being overwhelmed by excessive span submissions.
        *   **Consider Alternatives:** Explore alternative span submission methods that offer built-in authentication if the default Agent configuration is deemed too risky.

## Attack Surface: [Unauthenticated Access to Jaeger Query UI and API](./attack_surfaces/unauthenticated_access_to_jaeger_query_ui_and_api.md)

*   **Description:** The Jaeger Query service provides a web UI and API for viewing and analyzing traces. If not properly secured, these interfaces can be accessed without authentication.
    *   **How Jaeger Contributes:** Jaeger's primary function is to provide observability through its Query interface. Leaving this interface open exposes sensitive operational data.
    *   **Example:** An attacker gains access to the Jaeger Query UI and can view detailed traces, including request parameters, timestamps, and service interactions, potentially revealing sensitive business logic or security vulnerabilities.
    *   **Impact:**
        *   Exposure of sensitive application performance and operational data.
        *   Information leakage about internal system architecture and potential vulnerabilities.
        *   Potential for reconnaissance and planning of further attacks.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Authentication and Authorization:** Implement robust authentication (e.g., OAuth 2.0, OpenID Connect) and authorization mechanisms for the Jaeger Query service.
        *   **Network Restrictions:** Restrict access to the Jaeger Query service to authorized networks or IP addresses.
        *   **HTTPS Enforcement:** Ensure all communication with the Jaeger Query service is encrypted using HTTPS.
        *   **Regular Security Audits:** Conduct regular security audits of the Jaeger Query deployment and configuration.

## Attack Surface: [Unauthenticated Span Submission to Jaeger Collector (if directly exposed)](./attack_surfaces/unauthenticated_span_submission_to_jaeger_collector__if_directly_exposed_.md)

*   **Description:** If the Jaeger Collector's HTTP or gRPC endpoints for receiving spans are directly exposed to the network without authentication, it becomes a target for malicious span injection.
    *   **How Jaeger Contributes:** While typically the Agent is the primary entry point, misconfigurations or specific deployment scenarios might expose the Collector directly.
    *   **Example:** An attacker bypasses the Agent and directly sends a large number of crafted spans to the Collector's ingestion endpoint, potentially overloading it or injecting malicious data.
    *   **Impact:**
        *   Resource exhaustion on the Collector, potentially leading to dropped spans and incomplete tracing data.
        *   Data poisoning in the tracing system.
        *   Potential exploitation of vulnerabilities in the Collector's span processing logic.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid Direct Exposure:**  Ensure the Jaeger Collector is not directly exposed to untrusted networks. The Agent should be the primary point of entry for span submission.
        *   **Collector Authentication (gRPC):** If using gRPC for Collector communication, enable authentication.
        *   **Network Segmentation:**  Isolate the Collector within a secure network segment.
        *   **Rate Limiting:** Implement rate limiting on the Collector's ingestion endpoints.

