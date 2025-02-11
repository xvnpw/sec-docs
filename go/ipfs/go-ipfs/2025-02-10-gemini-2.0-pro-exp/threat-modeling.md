# Threat Model Analysis for ipfs/go-ipfs

## Threat: [DHT Poisoning / Eclipse Attack](./threats/dht_poisoning__eclipse_attack.md)

*   **Description:** An attacker floods the Distributed Hash Table (DHT) with malicious nodes or incorrect routing information. This allows the attacker to control the results returned when the application queries for a specific CID. The application may then retrieve malicious content instead of the intended data, or the attacker may isolate the node from the legitimate network.
    *   **Impact:**
        *   Retrieval of malicious content, leading to potential code execution, data breaches, or display of unwanted content.
        *   Denial of service for legitimate content retrieval.
        *   Compromise of application integrity.
    *   **Affected go-ipfs Component:**
        *   `go-ipfs/core/coreapi`:  The `Resolve()` function (and related path resolution mechanisms) within the Core API.
        *   `go-ipfs/routing`: The DHT implementation itself.
        *   `go-libp2p/p2p/discovery/routing`: Routing discovery mechanisms.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Multiple Gateway Fallback:** Use multiple, reputable IPFS gateways as a fallback.
        *   **DHT Hardening (Passive):** Stay updated with the latest `go-ipfs` releases.
        *   **Content Verification (Post-Retrieval):** *Always* verify retrieved content against a known-good hash (if available) *after* retrieval.
        *   **Reputation Systems (Future):** Explore future CID/gateway reputation systems.

## Threat: [Resource Exhaustion via Bitswap](./threats/resource_exhaustion_via_bitswap.md)

*   **Description:** An attacker sends a large number of requests to the `go-ipfs` node for data blocks via Bitswap, overwhelming the node's bandwidth, CPU, or memory. The attacker might request non-existent or very large blocks repeatedly.
    *   **Impact:**
        *   Denial of service for legitimate users.
        *   Application slowdown or unavailability.
        *   Potential system instability.
    *   **Affected go-ipfs Component:**
        *   `go-ipfs/exchange/bitswap`: The Bitswap protocol implementation.
        *   `go-libp2p/p2p/net/network`: The underlying network stack.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Rate Limiting (Application Level):** Implement application-level rate limiting for IPFS requests.
        *   **Bitswap Configuration:** Tune Bitswap parameters (e.g., `Bitswap.MaxInboundBytesPerSec`) in the `go-ipfs` configuration.
        *   **Resource Monitoring:** Monitor the `go-ipfs` node's resource usage.
        *   **Connection Limits:** Configure `go-ipfs` and libp2p to limit concurrent connections.

## Threat: [Remote Code Execution via go-ipfs Vulnerability](./threats/remote_code_execution_via_go-ipfs_vulnerability.md)

*   **Description:** A vulnerability exists within the `go-ipfs` codebase (e.g., in the DAG service, a codec, or a transport protocol). An attacker crafts a malicious IPFS object or network message that exploits this vulnerability, leading to arbitrary code execution on the system running the `go-ipfs` node.
    *   **Impact:**
        *   Complete system compromise.
        *   Data theft or destruction.
        *   Use of the compromised system for further attacks.
    *   **Affected go-ipfs Component:**
        *   Potentially *any* component. Examples:
            *   `go-ipfs/core`: Core node logic.
            *   `go-ipfs/merkledag`: Merkle DAG service.
            *   `go-ipfs/unixfs`: UnixFS implementation.
            *   `go-libp2p`: Any libp2p sub-component.
            *   `go-ipfs-cmds`: Command-line interface and API handling.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Update `go-ipfs` Immediately:** Keep `go-ipfs` and dependencies *up-to-date*. Monitor security advisories.
        *   **Least Privilege:** Run the `go-ipfs` node with *minimum* privileges. Do *not* run as root.
        *   **Containerization:** Run the `go-ipfs` node within a container.
        *   **Security Audits (If Possible):** Consider security audits of relevant components.

## Threat: [API Misconfiguration / Unauthorized Access](./threats/api_misconfiguration__unauthorized_access.md)

*   **Description:** The `go-ipfs` API is exposed without proper authentication or with weak credentials. An attacker gains access to the API and can control the node, potentially adding, deleting, or pinning content, modifying the configuration, or accessing sensitive information.
    *   **Impact:**
        *   Unauthorized modification of IPFS content.
        *   Exposure of sensitive data.
        *   Control over the node's behavior.
        *   Potential denial of service.
    *   **Affected go-ipfs Component:**
        *   `go-ipfs/core/corehttp`: The HTTP API server.
        *   `go-ipfs-cmds`: Command-line interface and API handling.
        *   `go-ipfs/config`: The configuration file.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strong Authentication:** Configure the API with strong authentication (e.g., API keys, JWTs).
        *   **Firewall Rules:** Restrict access to the API port (default: 5001) via firewall rules.
        *   **TLS Encryption:** Enable TLS encryption for the API.
        *   **Reverse Proxy:** Use a reverse proxy for authentication, TLS termination, and rate limiting.
        *   **Regular Configuration Review:** Periodically review the `go-ipfs` configuration.

