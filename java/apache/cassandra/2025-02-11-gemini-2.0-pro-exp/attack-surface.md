# Attack Surface Analysis for apache/cassandra

## Attack Surface: [1. Unencrypted Client-to-Node Communication](./attack_surfaces/1__unencrypted_client-to-node_communication.md)

*   **Description:** Data transmitted between clients and Cassandra nodes is sent in plain text.
*   **How Cassandra Contributes:** Cassandra's default configuration does *not* enforce encryption; it must be explicitly enabled.
*   **Example:** An attacker intercepts login credentials and sensitive data.
*   **Impact:** Data breach (confidentiality), unauthorized data modification (integrity).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers/Users:** Enable TLS/SSL in `cassandra.yaml` (`client_encryption_options`).
    *   **Developers/Users:** Configure clients to use TLS/SSL and validate certificates.
    *   **Developers/Users:** Use strong ciphers and TLS versions.
    *   **Developers:** Ensure client libraries handle certificate validation correctly.

## Attack Surface: [2. Unencrypted Node-to-Node Communication](./attack_surfaces/2__unencrypted_node-to-node_communication.md)

*   **Description:** Data replicated between Cassandra nodes is transmitted in plain text.
*   **How Cassandra Contributes:** Inter-node encryption is not enabled by default; it requires configuration.
*   **Example:** An attacker intercepts replication traffic, gaining access to all data.
*   **Impact:** Complete data breach (confidentiality).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers/Users:** Enable TLS/SSL in `cassandra.yaml` (`server_encryption_options`).
    *   **Developers/Users:** Use strong ciphers and TLS versions.
    *   **Developers/Users:** Configure node-to-node authentication (e.g., certificates).

## Attack Surface: [3. Weak or Default Authentication](./attack_surfaces/3__weak_or_default_authentication.md)

*   **Description:** Cassandra is accessed using default or weak passwords.
*   **How Cassandra Contributes:** Cassandra ships with a default superuser account that is often left enabled with default credentials.
*   **Example:** An attacker uses default credentials to gain full administrative access.
*   **Impact:** Complete cluster compromise (confidentiality, integrity, availability).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers/Users:** Change/disable the default `cassandra` user immediately.
    *   **Developers/Users:** Enforce strong password policies.
    *   **Developers/Users:** Implement Role-Based Access Control (RBAC).
    *   **Developers:** Consider external authentication providers (LDAP, Kerberos).

## Attack Surface: [4. Unauthorized JMX Access](./attack_surfaces/4__unauthorized_jmx_access.md)

*   **Description:** The JMX interface is exposed and accessible without authentication or with weak credentials.
*   **How Cassandra Contributes:** Cassandra exposes a JMX interface; remote access may be enabled by default without authentication.
*   **Example:** An attacker uses JMX to trigger expensive operations, causing a denial-of-service, or extracts sensitive information.
*   **Impact:** Denial of service, information disclosure, configuration manipulation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers/Users:** Disable remote JMX if not required.
    *   **Developers/Users:** Secure JMX with strong authentication and authorization.
    *   **Developers/Users:** Change the default JMX port.
    *   **Network Engineers:** Restrict network access to the JMX port.

## Attack Surface: [5. CQL Injection](./attack_surfaces/5__cql_injection.md)

*   **Description:** User input is used directly in CQL queries without sanitization, allowing injection of malicious CQL code.
*   **How Cassandra Contributes:** While less prone than SQL, CQL *is* susceptible if applications concatenate strings with user input.
*   **Example:** An attacker injects `' OR '1'='1` to retrieve all users.
*   **Impact:** Unauthorized data access (confidentiality), data modification/deletion (integrity).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** *Always* use parameterized queries (prepared statements).
    *   **Developers:** Implement strict input validation and sanitization.
    *   **Developers:** Avoid dynamic query construction.

## Attack Surface: [6. Unrestricted UDF/UDA Execution](./attack_surfaces/6__unrestricted_udfuda_execution.md)

*   **Description:** Untrusted users can create/execute UDFs/UDAs containing malicious code.
*   **How Cassandra Contributes:** Cassandra allows UDFs/UDAs in languages like Java/JavaScript, which run within the Cassandra process.
*   **Example:** An attacker uploads a UDF that opens a reverse shell, granting remote code execution.
*   **Impact:** Arbitrary code execution, leading to complete system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers/Users:** Restrict UDF/UDA creation/execution to trusted users.
    *   **Developers/Users:** Enable the Java Security Manager for UDFs/UDAs.
    *   **Developers/Users:** Thoroughly review UDF/UDA code before deployment.
    *   **Developers:** Prefer built-in functions over UDFs/UDAs.

## Attack Surface: [7. Unpatched Cassandra Vulnerabilities](./attack_surfaces/7__unpatched_cassandra_vulnerabilities.md)

*   **Description:** The Cassandra cluster is running an outdated version with known vulnerabilities.
*   **How Cassandra Contributes:** Cassandra, like any software, can have vulnerabilities; security updates are released to address them.
*   **Example:** An attacker exploits a known vulnerability in an older version.
*   **Impact:** Varies, but can range from denial-of-service to complete compromise.
*   **Risk Severity:** Varies (Critical to High), depending on the vulnerability.  We're only including High/Critical here.
*   **Mitigation Strategies:**
    *   **Developers/Users:** Establish a robust patch management process; update regularly.
    *   **Developers/Users:** Subscribe to Cassandra security announcements.
    *   **Developers/Users:** Test updates in a non-production environment first.

