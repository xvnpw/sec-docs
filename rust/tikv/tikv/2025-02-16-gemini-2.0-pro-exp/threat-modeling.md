# Threat Model Analysis for tikv/tikv

## Threat: [Unauthorized Data Access via Direct Storage Access](./threats/unauthorized_data_access_via_direct_storage_access.md)

*   **Threat:** Unauthorized Data Access via Direct Storage Access

    *   **Description:** An attacker gains physical or virtual machine-level access to a TiKV node. They bypass the TiKV server process and directly access the underlying RocksDB storage files. The attacker uses tools to read the raw data stored in the SST files, circumventing any access controls enforced by TiKV.
    *   **Impact:** Complete data confidentiality breach. All data stored on the compromised TiKV node is exposed.
    *   **Affected Component:** TiKV: RocksDB storage engine (SST files).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Enable TDE (Transparent Data Encryption):** Configure TiKV to encrypt data at rest using a securely managed key.
        *   **Strict Network Segmentation:** Place TiKV nodes on a highly restricted network segment, accessible only to authorized systems.
        *   **Operating System Hardening:** Implement strict file system permissions, access control lists (ACLs), and disable unnecessary services on TiKV nodes.
        *   **Physical Security:** If running on physical hardware, ensure strong physical security controls for the data center.
        *   **VM Security:** If running in a virtualized environment, ensure the hypervisor and host operating system are secure.
        *   **Intrusion Detection:** Implement intrusion detection systems (IDS) to monitor for unauthorized access attempts.

## Threat: [Man-in-the-Middle (MitM) Attack on Client-TiKV Communication](./threats/man-in-the-middle__mitm__attack_on_client-tikv_communication.md)

*   **Threat:** Man-in-the-Middle (MitM) Attack on Client-TiKV Communication

    *   **Description:** An attacker positions themselves on the network between the application client and the TiKV cluster.  If TLS is not enabled or is improperly configured (e.g., weak ciphers, invalid certificates), the attacker can intercept and modify data in transit.  They could read sensitive data, inject malicious data, or alter requests.
    *   **Impact:** Data confidentiality and integrity breach.  Data can be read, modified, or injected.
    *   **Affected Component:** TiKV: gRPC communication layer (client-server and inter-node).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Enforce TLS:** Enable and *require* TLS for all communication between the client and TiKV, and between TiKV nodes (PD, TiKV, TiFlash).
        *   **Strong Cipher Suites:** Use only strong, modern cipher suites.
        *   **Valid Certificates:** Use valid, trusted certificates signed by a reputable Certificate Authority (CA).
        *   **Certificate Pinning (Optional):** Consider certificate pinning in the client application for enhanced security.
        *   **Regular Certificate Rotation:** Rotate certificates regularly to minimize the impact of compromised certificates.

## Threat: [Denial-of-Service (DoS) Attack on PD](./threats/denial-of-service__dos__attack_on_pd.md)

*   **Threat:** Denial-of-Service (DoS) Attack on PD

    *   **Description:** An attacker sends a flood of requests to the Placement Driver (PD) nodes, overwhelming their resources (CPU, memory, network). This prevents PD from performing its cluster management functions, rendering the entire TiKV cluster unusable. The attacker might use various techniques, such as sending malformed requests or exploiting vulnerabilities in the PD service.
    *   **Impact:** Complete cluster unavailability.  The application cannot read or write data.
    *   **Affected Component:** PD: All components, particularly the gRPC server and etcd client.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Redundant PD Nodes:** Deploy at least three PD nodes (preferably five) for high availability.
        *   **Rate Limiting:** Implement rate limiting at the network level (firewall, load balancer) and within the PD service itself.
        *   **Network Segmentation:** Isolate PD nodes on a dedicated network segment.
        *   **DDoS Protection:** Consider using a DDoS protection service.
        *   **Resource Quotas:** Configure resource quotas to limit the resources consumed by individual clients or requests.
        *   **Input Validation:** Ensure PD properly validates all incoming requests to prevent exploitation of vulnerabilities.

## Threat: [Malicious Data Modification via Compromised TiKV Node](./threats/malicious_data_modification_via_compromised_tikv_node.md)

*   **Threat:** Malicious Data Modification via Compromised TiKV Node

    *   **Description:** An attacker gains full control of a TiKV node (e.g., through a compromised operating system or a vulnerability in the TiKV server). They bypass the Raft consensus mechanism and directly modify data within the RocksDB storage engine using low-level tools. This allows them to corrupt data without detection by other TiKV nodes.
    *   **Impact:** Data integrity violation.  Data can be silently corrupted or modified.
    *   **Affected Component:** TiKV: RocksDB storage engine (SST files).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strong Network Segmentation:** Isolate TiKV nodes on a highly restricted network segment.
        *   **Operating System Hardening:** Implement strict security measures on the operating systems of TiKV nodes.
        *   **Intrusion Detection/Prevention:** Deploy intrusion detection and prevention systems (IDS/IPS).
        *   **Regular Security Audits:** Conduct regular security audits of the TiKV infrastructure.
        *   **Application-Level Checksums (Optional):** Implement application-level checksums or other integrity checks to detect data modification that bypasses TiKV's normal mechanisms.

