# Threat Model Analysis for ethereum/go-ethereum

## Threat: [Unsecured RPC/IPC Exposure](./threats/unsecured_rpcipc_exposure.md)

*   **Description:** An attacker scans for publicly accessible Geth nodes with open RPC (Remote Procedure Call) or IPC (Inter-Process Communication) ports.  The attacker uses these open interfaces to issue commands to the node, potentially gaining full control. They could steal funds (if private keys are accessible), submit malicious transactions, or disrupt the node.
*   **Impact:**
    *   Complete compromise of the Geth node.
    *   Potential theft of funds.
    *   Arbitrary transaction submission.
    *   Service disruption.
    *   Potential use of the node for malicious activities.
*   **Affected Geth Component:**
    *   `rpc` package (HTTP, WebSocket, and IPC servers).
    *   Configuration flags: `--http`, `--ws`, `--ipcpath`, `--http.addr`, `--http.port`, `--ws.addr`, `--ws.port`, `--http.api`, `--ws.api`, `--authrpc.*`
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Firewall Rules:** *Strictly* limit access to RPC/IPC ports using a firewall. Allow only `localhost` or a *very* limited set of trusted IPs within a private network. *Never* expose publicly without additional protection.
    *   **Disable Unnecessary APIs:** Use `--http.api` and `--ws.api` to enable *only* required APIs. *Never* enable `admin`, `personal`, or `debug` on a publicly accessible node. Minimize enabled APIs even on private networks.
    *   **Authentication:**
        *   **JWT Secret:** Use `--authrpc.jwtsecret` for JWT authentication.
        *   **API Keys (Less Secure):** Avoid if possible; JWT is preferred.
    *   **Reverse Proxy:** Use a reverse proxy (Nginx, Apache, Caddy) for:
        *   TLS Termination (HTTPS).
        *   Authentication (basic auth, client certificates).
        *   Rate Limiting.
        *   Request Filtering.
    *   **VPC/Private Network:** Run Geth and the application within a VPC or private network.
    *   **Regular Updates:** Keep Geth updated.

## Threat: [Denial-of-Service (DoS) against the Node](./threats/denial-of-service__dos__against_the_node.md)

*   **Description:** An attacker floods the Geth node with requests (RPC calls, peer connections, transactions), overwhelming its resources (CPU, memory, bandwidth, I/O) and preventing it from functioning.
*   **Impact:**
    *   Application unavailability.
    *   Delayed/failed transactions.
    *   Loss of synchronization.
    *   Potential resource exhaustion.
*   **Affected Geth Component:**
    *   `rpc` package (RPC requests).
    *   `p2p` package (peer connections).
    *   `eth` package (transaction processing, synchronization).
    *   Resource limit flags: `--maxpeers`, `--cache`, `--txpool.*`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Rate Limiting (RPC):**
        *   **Geth's Built-in (Limited):** Use with caution; external solutions are more robust.
        *   **Reverse Proxy:** Implement sophisticated rate limiting (IP, frequency, etc.).
    *   **Connection Limits:**
        *   `--maxpeers`: Limit peer connections.
        *   `--maxpendpeers`: Limit pending connections.
    *   **Resource Limits:**
        *   `--cache`: Adjust cache size.
        *   `--txpool.*`: Configure transaction pool settings.
    *   **Firewall:** Block malicious IPs/networks.
    *   **IDS/IPS:** Detect and block malicious traffic.
    *   **Cloud Provider DDoS Protection:** Leverage cloud provider services.
    *   **Network Monitoring:** Continuously monitor traffic and resource usage.

## Threat: [Chain Reorganization (Reorg) Mishandling](./threats/chain_reorganization__reorg__mishandling.md)

*   **Description:** The Ethereum blockchain experiences a reorg, replacing previously confirmed blocks.  An attacker might try to exploit this. If the application doesn't handle reorgs correctly, it might process invalid transactions.
*   **Impact:**
    *   Double-spending.
    *   Processing invalid transactions.
    *   Data inconsistencies.
    *   Loss of user trust.
*   **Affected Geth Component:**
    *   `eth` package (synchronization, event subscriptions).
    *   `core/blockchain` package.
    *   Event subscriptions: `SubscribeChainEvent`, `SubscribeChainHeadEvent`, `SubscribeChainSideEvent`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Confirmation Depth:** Wait for sufficient confirmations (e.g., 12+) before considering a transaction final.
    *   **Reorg Event Handling:**
        *   **Subscribe to Events:** Use Geth's event subscriptions.
        *   **Rollback Mechanism:** Implement a robust rollback to revert actions from reorged-out blocks.
        *   **Database Transactions:** Use database transactions for atomicity.
    *   **State Management:** Design state management to be resilient to reorgs.
    *   **Testing:** Thoroughly test reorg handling.

## Threat: [Compromised Geth Dependency (Supply Chain Attack)](./threats/compromised_geth_dependency__supply_chain_attack_.md)

*   **Description:** An attacker compromises a library that Geth depends on, injecting malicious code. This code can then execute when your application uses the compromised Geth version.
*   **Impact:**
    *   Potentially *anything* (complete compromise, theft, data exfiltration, disruption, malware).
*   **Affected Geth Component:**
    *   Potentially *any* part of Geth.
    *   Go modules system (`go.mod`, `go.sum`).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Dependency Pinning:** Use Go modules (`go.mod`) to pin *exact* dependency versions.
    *   **Dependency Verification:**
        *   **`go.sum`:** Go automatically verifies checksums. *Never* modify `go.sum` manually.
        *   **Checksum Database (sum.golang.org):** Go uses this to verify integrity.
    *   **Vulnerability Scanning:** Use tools like `go list -m -u all | nancy`, Snyk, or Dependabot.
    *   **Regular Updates (with Caution):**
        1.  **Review Changelogs:** Check for security updates.
        2.  **Test Thoroughly:** Test in a staging environment.
        3.  **Update Gradually:** Update one at a time or in small groups.
    *   **SBOM:** Maintain a Software Bill of Materials.
    *   **Vendor Dependencies (Optional):** Copy dependency source code into your project.
    *   **Monitor Security Advisories:** Stay informed about vulnerabilities.

