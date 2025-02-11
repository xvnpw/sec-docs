# Threat Model Analysis for lightningnetwork/lnd

## Threat: [Channel Force-Closure Griefing](./threats/channel_force-closure_griefing.md)

*   **Description:** A malicious peer repeatedly opens Lightning channels with the victim's `lnd` node and then immediately forces them closed.  The attacker does this to inflict on-chain transaction fees on the victim and potentially deplete their on-chain funds.  They might use automated scripts to open many channels quickly. `lnd`'s internal logic for handling channel opens and closures is directly exploited.
    *   **Impact:**
        *   Financial loss due to on-chain fees.
        *   Resource exhaustion (CPU, bandwidth) on the victim's node.
        *   Potential denial of service if the node runs out of on-chain funds or becomes overwhelmed.
    *   **Affected `lnd` Component:**
        *   `channelmanager`: Handles channel opening and closing.
        *   `contractcourt`: Resolves on-chain disputes (force-closures).
        *   `peer`: Manages connections to other Lightning nodes.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Channel Limits:** Limit the number of channels allowed from a single peer (using `lnd`'s `maxpendingchannels`).
        *   **Minimum Channel Size:** Configure `lnd`'s `minchansize` to prevent opening very small, easily griefed channels.
        *   **Monitoring:** Actively monitor channel open/close events within `lnd` logs and look for patterns of abuse.
        *   **Watchtowers:** Utilize watchtowers (`wtclient` in `lnd`) to monitor channels for breaches while offline.

## Threat: [Channel Jamming](./threats/channel_jamming.md)

*   **Description:** An attacker opens multiple channels with the victim's node and initiates numerous payments (HTLCs) that they intentionally never settle. These "stuck" HTLCs tie up the victim's liquidity, preventing legitimate payments from being routed. This directly impacts `lnd`'s HTLC handling.
    *   **Impact:**
        *   Denial of service for legitimate payments.
        *   Loss of routing fees.
        *   Reputational damage.
    *   **Affected `lnd` Component:**
        *   `htlcswitch`: Manages HTLC routing and forwarding.
        *   `channelmanager`:  Channels become congested.
        *   `peer`: Connections to the attacker's nodes.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **HTLC Limits:** Use `lnd`'s `max-htlc-value-in-flight-msat` and `max-concurrent-htlcs` to limit the total value and number of outstanding HTLCs per channel.
        *   **Monitoring:** Track HTLC counts, durations, and failure rates within `lnd`.

## Threat: [Unauthorized Access to `lnd` API](./threats/unauthorized_access_to__lnd__api.md)

*   **Description:** An attacker gains access to the `lnd` gRPC or REST API, either through network intrusion or stolen credentials (macaroons).  The attacker can then control the `lnd` node, steal funds, close channels, or disrupt operations. This is a direct attack on `lnd`'s exposed interface.
    *   **Impact:**
        *   Complete loss of funds.
        *   Full control of the Lightning node.
        *   Severe reputational damage.
        *   Potential legal liability.
    *   **Affected `lnd` Component:**
        *   `rpcserver`:  Handles gRPC and REST API requests.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strong Authentication:** Use strong, unique macaroons for API access.  Restrict macaroon permissions to the minimum required.  Rotate macaroons regularly.
        *   **TLS Encryption:**  Always use TLS for API communication.  Ensure certificates are valid and properly configured.
        *   **Network Segmentation:**  Restrict network access to the `lnd` API to only authorized hosts.  Use firewalls and network policies.
        *   **Rate Limiting:** Implement rate limiting on the API using `lnd`'s built-in features.

## Threat: [`lnd` Node Compromise (Remote Code Execution)](./threats/_lnd__node_compromise__remote_code_execution_.md)

*   **Description:** An attacker exploits a vulnerability in `lnd` itself (e.g., a buffer overflow, a bug in a dependency) to gain remote code execution on the server running `lnd`. This is a direct attack on the `lnd` software.
    *   **Impact:**
        *   Complete loss of funds.
        *   Full control of the Lightning node and potentially the server.
        *   Severe reputational damage.
        *   Potential legal liability.
    *   **Affected `lnd` Component:**
        *   Potentially any component of `lnd`, depending on the vulnerability.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Update `lnd`:**  Regularly update `lnd` to the latest stable version to patch security vulnerabilities.  Subscribe to security announcements.
        *   **Least Privilege:**  Run `lnd` as a non-root user with minimal permissions.
        *   **Containerization:**  Run `lnd` in a container (e.g., Docker) to isolate it from the host system.
        *   **Security Hardening:** Follow security best practices for the OS running `lnd`.

## Threat: [Denial-of-Service (DoS) against `lnd`](./threats/denial-of-service__dos__against__lnd_.md)

*   **Description:** An attacker floods `lnd` with a large number of requests (e.g., connection attempts, API calls, invalid payments), overwhelming its resources and making it unresponsive. This directly targets `lnd`'s network-facing components.
    *   **Impact:**
        *   Inability to send or receive Lightning payments.
        *   Loss of routing fees.
        *   Reputational damage.
    *   **Affected `lnd` Component:**
        *   `rpcserver`:  If the API is targeted.
        *   `peer`:  If the attacker floods with connection attempts.
        *   `htlcswitch`:  If the attacker floods with invalid payments.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Rate Limiting:** Implement rate limiting on the `lnd` API and network connections using `lnd`'s built-in features.
        *   **Resource Limits:** Configure resource limits (CPU, memory, file descriptors) for the `lnd` process.
        *   **Network Filtering:** Use firewalls to block malicious traffic to `lnd`.

## Threat: [HTLC Preimage Revelation Attack (within `lnd`)](./threats/htlc_preimage_revelation_attack__within__lnd__.md)

* **Description:** A bug *within `lnd` itself* causes it to prematurely reveal the preimage of an HTLC *before* receiving the corresponding settlement from the next hop.  While unlikely, a bug in `lnd`'s core logic could cause this.
    * **Impact:**
        * Loss of funds for the sender.
    * **Affected `lnd` Component:**
        * `htlcswitch`: Manages HTLC routing and preimage revelation.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Update `lnd`:** Keep `lnd` updated to the latest version, as this type of bug would likely be patched quickly.
        * **Code Audits (for `lnd` developers):**  Rigorous code audits and testing of `lnd`'s core payment logic are essential.

## Threat: [Time-Lock Delta Manipulation](./threats/time-lock_delta_manipulation.md)

*   **Description:** An attacker along a payment route attempts to modify the CLTV (CheckLockTimeVerify) expiry of an HTLC. By reducing the time-lock delta, they can potentially force a channel closure in their favor before the payment can be properly settled. `lnd` must correctly enforce these time-locks.
    *   **Impact:**
        *   Potential loss of funds for the sender or receiver.
        *   Disruption of payment routing.
    *   **Affected `lnd` Component:**
        *   `htlcswitch`:  Handles HTLC routing and enforces time-locks.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **`lnd`'s Protocol Enforcement:** Ensure you are using a recent version of `lnd`, which is designed to strictly enforce time-lock rules.
        *   **Monitoring:** Monitor for unexpected payment failures or channel closures related to time-lock violations within `lnd` logs.

