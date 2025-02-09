# Mitigation Strategies Analysis for ripple/rippled

## Mitigation Strategy: [Peer Protocol Hardening](./mitigation_strategies/peer_protocol_hardening.md)

*   **Description:**
    1.  **Identify Trusted Peers:** Create a list of known, trusted `rippled` nodes (validators and other servers).
    2.  **Configure `[ips_fixed]`:** In `rippled.cfg`, add the IP addresses and ports of trusted peers to the `[ips_fixed]` section. This ensures `rippled` *always* attempts to connect to these.
        ```
        [ips_fixed]
        192.168.1.10 51235
        validator.example.com 51235
        ```
    3.  **Configure `[ips]` (Optional):**  Use the `[ips]` section for dynamically discovered peers, but prioritize `[ips_fixed]`.
    4.  **Disable Public Peer Discovery (Recommended):** Set `peer_private=1` in the `[peer_private]` section of `rippled.cfg`. This prevents `rippled` from accepting incoming connections from unknown peers and from actively searching for new peers.
    5.  **Regularly Review:** Periodically review and update the `[ips_fixed]` and `[ips]` lists.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) / DDoS:** (Severity: High) - Reduces the attack surface.
    *   **Eclipse Attacks:** (Severity: High) - Prevents isolation from the legitimate network.
    *   **Sybil Attacks:** (Severity: Medium) - Makes it harder to create fake identities.

*   **Impact:**
    *   **DoS/DDoS:** Reduces the risk by limiting connections.
    *   **Eclipse Attacks:**  Virtually eliminates the risk with `peer_private=1` and a well-configured `[ips_fixed]`.
    *   **Sybil Attacks:** Reduces effectiveness, but doesn't completely eliminate them.

*   **Currently Implemented:** Partially. `[ips_fixed]` has some validators; `peer_private=0`.

*   **Missing Implementation:**
    *   Set `peer_private=1`.
    *   Expand `[ips_fixed]` to include *all* trusted peers.
    *   Establish a review process for `[ips_fixed]`.

## Mitigation Strategy: [Resource Limits Configuration](./mitigation_strategies/resource_limits_configuration.md)

*   **Description:**
    1.  **Analyze Resource Usage:** Monitor `rippled`'s resource usage (CPU, memory, disk I/O, network).
    2.  **Configure `[server]` Limits:** Adjust settings in `rippled.cfg`'s `[server]` section:
        *   `io_threads`: Limit I/O threads.
        *   `rpc_threads`: Limit RPC threads.
        *   `peer_connect_threads`: Limit peer connection threads.
    3.  **Configure `[limits]` Limits:** Adjust settings in the `[limits]` section:
        *   `database_size`: Set a maximum database size.
        *   `ledger_history`: Control how many past ledgers are stored.
        *   `fetch_depth`: Limit ledger fetching during sync.
    4.  **Configure `[overlay]` Limits:** Adjust `max_peers` in the `[overlay]` section to limit peer connections.
    5.  **Test and Monitor:** Test after adjusting limits and continuously monitor.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) / DDoS:** (Severity: High) - Prevents resource exhaustion.
    *   **Resource Exhaustion Attacks:** (Severity: High) - Protects against targeted resource consumption.

*   **Impact:**
    *   **DoS/DDoS & Resource Exhaustion:** Significantly reduces the risk. The node may become less responsive under load but should remain operational.

*   **Currently Implemented:** Partially. Default limits exist but haven't been tuned.

*   **Missing Implementation:**
    *   Perform a comprehensive resource analysis.
    *   Adjust limits in `[server]`, `[limits]`, and `[overlay]` based on the analysis.
    *   Establish a monitoring and adjustment process.

## Mitigation Strategy: [RPC Access Control](./mitigation_strategies/rpc_access_control.md)

*   **Description:**
    1. **Identify Sensitive RPC Methods:** Determine which RPC methods are sensitive (e.g., `stop`, `validation_create`, `ledger_closed`, potentially others depending on your application).
    2. **Configure `[rpc_startup]` (if applicable):** If you are using the `[rpc_startup]` section to define custom RPC commands, ensure that you are not exposing any sensitive functionality without proper authentication and authorization.
    3. **Configure `[rpc_allow_admin]`:** Set this to `false` unless absolutely necessary.  This setting controls whether administrative commands can be executed without authentication.  If set to `true`, *anyone* can execute administrative commands.
    4. **Configure IP-Based Restrictions (using `[rpc_ip]` and `[rpc_port]`):**
        *   Use `[rpc_ip]` to bind the RPC interface to a specific IP address.  Ideally, bind it to `127.0.0.1` (localhost) if RPC access is only needed locally.  If remote access is required, use a *very* restrictive IP address or range.  *Never* bind to `0.0.0.0` (all interfaces) without additional security measures (like an API gateway).
        *   Use `[rpc_port]` to specify a non-standard port for the RPC interface. This is security through obscurity, but it can help deter casual attackers.
    5. **Disable Unnecessary RPC Methods:** While `rippled` doesn't have a direct way to disable individual RPC methods *within* `rippled.cfg`, you *must* rely on external tools (API Gateway, firewall) to achieve this.  This strategy focuses on the `rippled.cfg` aspects.
    6. **Regularly Review Configuration:** Periodically review the RPC-related settings in `rippled.cfg` to ensure they are still appropriate.

*   **Threats Mitigated:**
    *   **Unauthorized Access to RPC:** (Severity: High) - Limits who can connect to the RPC interface.
    *   **Abuse of RPC Methods:** (Severity: High) - Reduces the risk of attackers using RPC to disrupt the node.
    *   **DoS/DDoS via RPC:** (Severity: Medium) - Some mitigation by limiting access, but an API gateway is much more effective.

*   **Impact:**
    *   **Unauthorized Access:** Significantly reduces risk if properly configured (especially binding to localhost).
    *   **Abuse of RPC Methods:** Reduces risk, particularly if `[rpc_allow_admin]` is `false`.
    *   **DoS/DDoS:** Provides limited protection; external tools are essential.

*   **Currently Implemented:** Partially. `[rpc_ip]` is set to `127.0.0.1`. `[rpc_allow_admin]` is set to `false`.

*   **Missing Implementation:**
    *   If remote RPC access is needed, a more secure solution (API Gateway) is *required*.  The current configuration is only suitable for local access.
    *   Regular review of the RPC configuration.

## Mitigation Strategy: [Ledger History Management](./mitigation_strategies/ledger_history_management.md)

*   **Description:**
    1.  **Assess Data Needs:** Determine how much historical ledger data your application *actually* requires.  Do you need the full history, or can you operate with a smaller subset?
    2.  **Configure `ledger_history`:** In the `[limits]` section of `rippled.cfg`, set the `ledger_history` parameter to an appropriate value.  This controls the number of past ledgers `rippled` stores.  Lower values reduce disk space usage and can improve performance.  Common values:
        *   `256`:  Stores the last 256 ledgers (sufficient for many applications).
        *   `full`: Stores the entire ledger history (requires significant disk space).
        *   A specific number (e.g., `10000`): Stores the last 10,000 ledgers.
    3.  **Monitor Disk Usage:** Regularly monitor the disk space used by the `rippled` database.  Adjust `ledger_history` if necessary.

*   **Threats Mitigated:**
    *   **Disk Space Exhaustion:** (Severity: Medium) - Prevents `rippled` from consuming excessive disk space, which could lead to a denial of service.
    *   **Performance Degradation:** (Severity: Low) - Reducing the amount of historical data can improve performance, especially for queries that access older ledgers.

*   **Impact:**
    *   **Disk Space Exhaustion:** Directly controls disk space usage.
    *   **Performance Degradation:** Can improve performance, particularly for historical data queries.

*   **Currently Implemented:** Partially. `ledger_history` is set to `256`.

*   **Missing Implementation:**
    *   Regular monitoring of disk usage and adjustment of `ledger_history` if needed.

