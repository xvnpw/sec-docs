# Attack Surface Analysis for jaegertracing/jaeger

## Attack Surface: [Unsecured Jaeger Agent UDP Endpoint](./attack_surfaces/unsecured_jaeger_agent_udp_endpoint.md)

*   **Description:** The Jaeger Agent, by default, listens on UDP ports (6831/UDP for Thrift, 6832/UDP for gRPC) to receive spans. If these ports are exposed to untrusted networks without proper security measures, they become an entry point for malicious actors.
*   **How Jaeger Contributes:** Jaeger's architecture relies on agents to collect and forward tracing data, necessitating these open ports for communication.
*   **Example:** An attacker on the same network or a network with open UDP ports could flood the agent with a large number of fabricated spans, consuming its resources and potentially impacting the host system's performance.
*   **Impact:** Denial of Service (DoS) on the agent host, potential resource exhaustion, and injection of misleading or malicious tracing data.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement network segmentation to restrict access to the agent's UDP ports to only trusted sources (e.g., application instances).
    *   Use firewalls to block access to these ports from untrusted networks.
    *   Consider using authentication mechanisms if available for agent communication (though typically not a standard feature for UDP).

## Attack Surface: [Exposed Jaeger Collector HTTP/gRPC Endpoint](./attack_surfaces/exposed_jaeger_collector_httpgrpc_endpoint.md)

*   **Description:** The Jaeger Collector exposes HTTP and gRPC endpoints to receive spans from agents. If these endpoints are accessible without proper authentication and authorization, attackers can send arbitrary spans.
*   **How Jaeger Contributes:** The collector is a central component for receiving and processing tracing data in Jaeger's architecture.
*   **Example:** An attacker could send a massive number of spans to the collector, overwhelming its resources and potentially the storage backend, leading to a DoS. They could also send spans with malicious content intended to exploit vulnerabilities in the collector's processing logic or the storage backend.
*   **Impact:** Denial of Service (DoS) on the collector and potentially the storage backend, resource exhaustion, injection of malicious data into the tracing system, and potential exploitation of vulnerabilities in span processing.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Implement strong authentication and authorization mechanisms for the collector's HTTP/gRPC endpoints.
    *   Restrict access to the collector endpoints to only authorized agents or internal networks using firewalls or network policies.
    *   Implement rate limiting on the collector endpoints to prevent abuse.
    *   Ensure proper input validation and sanitization of received span data to prevent injection attacks.

## Attack Surface: [Unsecured Jaeger Query Service API](./attack_surfaces/unsecured_jaeger_query_service_api.md)

*   **Description:** The Jaeger Query service provides an HTTP API for retrieving and viewing traces. If this API is exposed without proper authentication and authorization, sensitive tracing data can be accessed by unauthorized parties.
*   **How Jaeger Contributes:** The query service is the primary interface for accessing and analyzing collected trace data.
*   **Example:** An attacker could access the query service API and retrieve sensitive information about the application's internal workings, performance characteristics, and potentially even business logic revealed through tracing data.

