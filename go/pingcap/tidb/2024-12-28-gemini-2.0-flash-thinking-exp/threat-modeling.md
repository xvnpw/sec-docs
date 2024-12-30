### High and Critical TiDB Threats

This list details high and critical security threats that directly involve TiDB components.

#### Threat 1: TiDB-Specific SQL Injection

*   **Description:** An attacker exploits vulnerabilities in application code that constructs SQL queries using user-supplied input without proper sanitization, specifically targeting TiDB-specific syntax or features (e.g., features related to distributed transactions or table partitioning). The attacker might inject malicious SQL code to read, modify, or delete data beyond their authorized scope by directly interacting with the **TiDB Server**.
*   **Impact:** Data breach, data modification, data deletion, potential denial of service by executing resource-intensive queries on the **TiDB Server**.
*   **Affected Component:** TiDB Server (SQL parsing and execution engine).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use parameterized queries or prepared statements for all database interactions.
    *   Implement strict input validation and sanitization on all user-supplied data before incorporating it into SQL queries.
    *   Follow the principle of least privilege when granting database permissions to application users within **TiDB**.
    *   Regularly review and audit application code for potential SQL injection vulnerabilities.

#### Threat 2: PD Leader Compromise

*   **Description:** An attacker gains unauthorized access to the PD leader node, potentially through exploiting vulnerabilities in the **PD Server** itself, the underlying operating system, or through compromised credentials. Once compromised, the attacker can manipulate cluster metadata, such as data placement rules, region assignments, and scheduling, leading to data loss, corruption, or denial of service across the entire **TiDB cluster**.
*   **Impact:** Data loss, data corruption, cluster instability, denial of service.
*   **Affected Component:** PD Server (leader election and metadata management).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Secure PD server nodes with strong access controls and regular security patching.
    *   Implement mutual TLS (mTLS) for communication between **PD** members.
    *   Monitor **PD** leader election and health status for anomalies.
    *   Follow the principle of least privilege for access to **PD** server infrastructure.
    *   Consider using a dedicated network for **PD** server communication.

#### Threat 3: Direct TiKV Data Access

*   **Description:** An attacker bypasses the **TiDB Server** and attempts to directly access the underlying **TiKV** key-value store, potentially by exploiting vulnerabilities in **TiKV's** security mechanisms or through compromised credentials used for **TiKV** access. This allows the attacker to read or modify raw data without going through the **TiDB** access control layer.
*   **Impact:** Data breach, data modification, data corruption within **TiKV**.
*   **Affected Component:** TiKV Server (storage engine and access control).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Ensure strong authentication and authorization are enforced for **TiKV** access.
    *   Implement network segmentation to restrict access to **TiKV** nodes.
    *   Encrypt data at rest within **TiKV**.
    *   Regularly audit **TiKV** access logs for suspicious activity.

#### Threat 4: TiFlash Data Exfiltration

*   **Description:** An attacker gains unauthorized access to the **TiFlash** server, potentially through exploiting vulnerabilities in **TiFlash** or the underlying infrastructure. This allows the attacker to access and exfiltrate data stored in the columnar format within **TiFlash**, which is often used for analytical purposes and might contain sensitive information.
*   **Impact:** Data breach of analytical data stored in **TiFlash**.
*   **Affected Component:** TiFlash Server (columnar storage engine).
*   **Risk Severity:** Medium
*   **Mitigation Strategies:**
    *   Implement strong authentication and authorization for **TiFlash** access.
    *   Secure **TiFlash** server nodes with appropriate access controls.
    *   Encrypt data at rest within **TiFlash**.
    *   Monitor **TiFlash** access logs for suspicious activity.

#### Threat 5: Denial of Service (DoS) through Resource Exhaustion on TiDB Server

*   **Description:** An attacker sends a large number of malicious or poorly constructed SQL queries directly to the **TiDB Server**, consuming excessive resources (CPU, memory, network) and causing performance degradation or service unavailability for legitimate users of the **TiDB Server**.
*   **Impact:** Service disruption, performance degradation of the **TiDB Server**.
*   **Affected Component:** TiDB Server (query processing engine).
*   **Risk Severity:** Medium
*   **Mitigation Strategies:**
    *   Implement query timeouts and resource limits on the **TiDB Server**.
    *   Use connection pooling to manage client connections effectively.
    *   Implement rate limiting on incoming requests to the **TiDB Server**.
    *   Monitor **TiDB Server** resource utilization and set up alerts for anomalies.

#### Threat 6: Compromised TiDB Operator Credentials (if used)

*   **Description:** If TiDB is deployed using TiDB Operator on Kubernetes, an attacker gains access to the credentials used by the operator to manage the **TiDB cluster**. This allows the attacker to perform administrative actions on the cluster, potentially leading to data loss, corruption, or denial of service by manipulating the **TiDB components**.
*   **Impact:** Data loss, data corruption, denial of service affecting the entire **TiDB cluster**.
*   **Affected Component:** TiDB Operator (Kubernetes controller).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Secure Kubernetes secrets used by the **TiDB Operator**.
    *   Implement strong authentication and authorization for accessing the Kubernetes API.
    *   Follow Kubernetes security best practices.

### Threat Flow Diagram

```mermaid
graph LR
    subgraph "TiDB Cluster"
        TS["TiDB Server"]
        PD["PD Server"]
        TK["TiKV Server"]
        TF["TiFlash Server"]
    end
    subgraph "TiDB Operator (Optional)"
        TO["TiDB Operator"]
    end

    TS -- "1. Malicious SQL Injection" --> TS
    TS -- "5. DoS Attacks" --> TS
    PD -- "2. PD Leader Exploit" --> PD
    TK -- "3. Direct TiKV Access Attempt" --> TK
    TF -- "4. TiFlash Data Access" --> TF
    TO -- "6. Operator Credential Theft" --> TS & PD & TK & TF

    style TS fill:#f9f,stroke:#333,stroke-width:2px
    style PD fill:#ccf,stroke:#333,stroke-width:2px
    style TK fill:#ccf,stroke:#333,stroke-width:2px
    style TF fill:#ccf,stroke:#333,stroke-width:2px
    style TO fill:#aaf,stroke:#333,stroke-width:2px
