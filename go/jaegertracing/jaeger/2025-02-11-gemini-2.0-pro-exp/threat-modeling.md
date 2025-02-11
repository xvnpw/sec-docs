# Threat Model Analysis for jaegertracing/jaeger

## Threat: [Sensitive Data Exposure in Spans](./threats/sensitive_data_exposure_in_spans.md)

*   **Description:** Developers inadvertently include sensitive data (PII, credentials, API keys, internal IP addresses, etc.) within span tags, logs, or operation names. An attacker with access to the Jaeger UI or backend storage could view this data. This occurs due to improper instrumentation or lack of data sanitization within the application code sending data *to* Jaeger.
*   **Impact:** Data breach, privacy violation, potential for further attacks using exposed credentials, regulatory non-compliance (e.g., GDPR, HIPAA).
*   **Affected Jaeger Component:** Primarily affects the *Jaeger Agent* (where spans are initially created) and the *Jaeger Backend Storage* (where spans are persisted). The *Jaeger Query* service and UI are also affected as they display this data.
*   **Risk Severity:** High to Critical (depending on the sensitivity of the exposed data).
*   **Mitigation Strategies:**
    *   **Code Reviews:** Enforce strict code reviews to prevent sensitive data inclusion.
    *   **Developer Training:** Educate developers on secure instrumentation and data sanitization.
    *   **Data Masking/Redaction:** Implement masking/redaction *before* data reaches the Jaeger agent (OpenTelemetry processors or custom agent extensions).
    *   **Deny-List:** Maintain a "deny-list" of sensitive data fields.
    *   **Automated Scanning:** Use tools to scan code and trace data for leaks.
    *   **Access Control:** Implement strong RBAC on the Jaeger UI and backend storage.

## Threat: [Denial of Service (DoS) - Agent Overload](./threats/denial_of_service__dos__-_agent_overload.md)

*   **Description:** An application generates an extremely high volume of spans, overwhelming the Jaeger agent. This could be due to a bug, misconfiguration, or a malicious attack. The agent might drop spans, become unresponsive, or even crash the application process.
*   **Impact:** Loss of tracing data, potential application instability or crash, degraded application performance.
*   **Affected Jaeger Component:** *Jaeger Agent* (span processing and reporting pipeline).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Adaptive Sampling:** Use adaptive sampling to dynamically adjust the sampling rate.
    *   **Rate Limiting (Application-Side):** Implement rate limiting within the application.
    *   **Circuit Breakers:** Use circuit breakers to temporarily disable tracing if overloaded.
    *   **Resource Limits:** Set appropriate resource limits (CPU, memory) for the agent.
    *   **Queueing:** Use a robust queueing mechanism (especially for out-of-process agents).

## Threat: [Denial of Service (DoS) - Collector Overload](./threats/denial_of_service__dos__-_collector_overload.md)

*   **Description:** A large number of Jaeger agents send spans simultaneously, overwhelming the Jaeger collector. This could be due to a traffic spike, misconfiguration, or a DDoS attack. The collector might drop spans, have increased latency, or become unstable.
*   **Impact:** Loss of tracing data, increased trace latency, potential collector instability, degraded tracing system performance.
*   **Affected Jaeger Component:** *Jaeger Collector* (span receiving and processing pipeline).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Horizontal Scaling:** Scale the Jaeger collector horizontally (add more instances).
    *   **Load Balancing:** Use a load balancer in front of the collectors.
    *   **Resource Limits:** Configure appropriate resource limits (CPU, memory) for collectors.
    *   **Monitoring:** Monitor collector performance metrics (queue size, processing time, errors).
    *   **Backpressure:** Implement backpressure to signal agents to reduce sampling.

## Threat: [Denial of Service (DoS) - Backend Storage Overload](./threats/denial_of_service__dos__-_backend_storage_overload.md)

*   **Description:** High span ingestion rates saturate the backend storage (Cassandra, Elasticsearch, etc.). This could be due to high traffic, misconfiguration, or lack of capacity. The storage system might become slow, unresponsive, or experience data loss.
*   **Impact:** Slow query performance, data loss, potential storage cluster instability, inability to retrieve trace data.
*   **Affected Jaeger Component:** *Jaeger Backend Storage* (Cassandra, Elasticsearch, or other storage).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Storage Scaling:** Scale the backend storage appropriately (add nodes, increase capacity).
    *   **Schema Optimization:** Optimize the storage schema and indexing.
    *   **Data Retention Policies:** Implement data retention policies to limit stored data.
    *   **Monitoring:** Monitor storage performance metrics (disk I/O, query latency, errors).
    *   **Jaeger Ingester:** Consider using a dedicated Jaeger ingester to buffer writes.

## Threat: [Agent Compromise](./threats/agent_compromise.md)

*   **Description:** An attacker gains control of the Jaeger agent. This could be through a vulnerability in the agent code, a compromised host, or a supply chain attack. The attacker could inject malicious spans, manipulate data, or use the agent as a pivot point.
*   **Impact:** Data manipulation, injection of false data, potential for lateral movement, compromise of the application host.
*   **Affected Jaeger Component:** *Jaeger Agent* (all aspects).
*   **Risk Severity:** High to Critical
*   **Mitigation Strategies:**
    *   **Regular Updates:** Keep the agent up to date with security patches.
    *   **Least Privilege:** Run the agent with the least necessary privileges.
    *   **Secure Containerization:** Use secure container runtime and image scanning.
    *   **Anomaly Detection:** Monitor the agent's behavior for anomalies.
    *   **Code Signing:** Verify the integrity of the agent code.

## Threat: [Collector/Backend Component Compromise](./threats/collectorbackend_component_compromise.md)

*   **Description:** An attacker gains control of a Jaeger collector, ingester, or other backend component. This could be through a vulnerability, misconfiguration, or compromised host. The attacker could manipulate data, disrupt the system, or access sensitive information.
*   **Impact:** Data manipulation, data loss, tracing system disruption, potential lateral movement, compromise of sensitive data.
*   **Affected Jaeger Component:** *Jaeger Collector*, *Jaeger Ingester*, *Jaeger Query*, *Jaeger Backend Storage*.
*   **Risk Severity:** High to Critical
*   **Mitigation Strategies:**
    *   **Regular Updates:** Keep all components up to date with security patches.
    *   **Least Privilege:** Run components with least necessary privileges.
    *   **Secure Containerization:** Use secure container runtimes and image scanning.
    *   **Network Segmentation:** Isolate Jaeger components from other infrastructure.
    *   **Anomaly Detection:** Monitor component behavior for anomalies.
    *   **Authentication & Authorization:** Implement strong authentication and authorization.

## Threat: [Malformed Trace Data Injection](./threats/malformed_trace_data_injection.md)

*   **Description:** An attacker sends crafted trace data to the Jaeger collector, exploiting vulnerabilities in its parsing or processing logic (e.g., buffer overflows). This could lead to code execution or denial of service.
*   **Impact:** Remote code execution on the collector, denial of service, potential compromise of the tracing system.
*   **Affected Jaeger Component:** *Jaeger Collector* (span receiving and processing pipeline, data validation).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Input Validation:** Implement robust input validation and sanitization.
    *   **Fuzz Testing:** Perform fuzz testing on the collector.
    *   **Secure Coding Practices:** Follow secure coding practices.
    *   **Regular Updates:** Keep the collector up to date with security patches.
    *   **WAF/API Gateway:** Consider using a WAF/API gateway to filter traffic.

## Threat: [Weak or Default Credentials](./threats/weak_or_default_credentials.md)

*   **Description:** The Jaeger deployment uses default or weak passwords for accessing the UI, backend storage, or other components. An attacker could easily gain unauthorized access.
*   **Impact:** Unauthorized access to trace data, data manipulation, tracing system disruption, backend storage compromise.
*   **Affected Jaeger Component:** *Jaeger Query* (UI), *Jaeger Backend Storage*, any component with authentication.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Change Default Credentials:** Change all default credentials immediately.
    *   **Strong Passwords:** Use strong, unique passwords.
    *   **Password Management:** Implement a password management system.
    *   **Multi-Factor Authentication (MFA):** Consider using MFA.
    *   **Regular Password Rotation:** Enforce regular password changes.

## Threat: [Unauthorized Access to Jaeger UI](./threats/unauthorized_access_to_jaeger_ui.md)

*   **Description:** The Jaeger UI is not properly secured with authentication and authorization. An attacker can access the UI without credentials or with easily obtained credentials.
*   **Impact:** Unauthorized access to trace data, potential data exfiltration, privacy violations.
*   **Affected Jaeger Component:** *Jaeger Query* (specifically, the web UI).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Authentication:** Implement strong authentication for the Jaeger UI (OAuth 2.0, OIDC, reverse proxy with authentication).
    *   **Authorization (RBAC):** Implement RBAC to restrict access based on user roles.
    *   **Network Segmentation:** Restrict network access to the Jaeger UI.

