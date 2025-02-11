# Mitigation Strategies Analysis for juanfont/headscale

## Mitigation Strategy: [Pre-shared Keys (PSKs) and Node Approval](./mitigation_strategies/pre-shared_keys__psks__and_node_approval.md)

**Mitigation Strategy:** Enforce strong authentication for node registration *within Headscale*.

**Description:**
1.  **Enable PSKs in `config.yaml`:**  In Headscale's configuration file (`config.yaml`), set the `pre_auth_keys` section.  This section defines the pre-shared keys that will be used for node registration.  You can specify multiple keys and set their expiration times.  Example:
    ```yaml
    pre_auth_keys:
      - key: "your-strong-random-key-1"
        reusable: false
        expiration: "2024-12-31T23:59:59Z"
        user: "user1"
      - key: "another-strong-key-2"
        reusable: true # Use with caution!
        expiration: "2025-06-30T23:59:59Z"
        user: "user2"
    ```
2.  **Generate Strong PSKs:** Use a strong random string generator (e.g., `openssl rand -base64 32`) to create the keys.
3.  **Distribute PSKs Securely:**  Provide the appropriate PSK to each user/device that needs to register.  Use a secure method (not plain email).
4.  **Manual Node Approval (CLI):**  *Do not* rely on automatic approval.  After a node attempts to register using a PSK, use the Headscale command-line interface (CLI) to *manually* approve it:
    ```bash
    headscale nodes list # To see pending nodes
    headscale nodes approve <node-id>
    ```
5.  **Out-of-Band Verification:**  Before approving, confirm the node's identity through a separate, secure channel.

**Threats Mitigated:**
*   **Unauthorized Node Registration (Severity: Critical):**  Prevents attackers from registering malicious nodes without a valid PSK.
*   **Man-in-the-Middle Attacks (Severity: High):**  Makes it significantly harder for an attacker to impersonate a legitimate node during registration.

**Impact:**
*   **Unauthorized Node Registration:** Significantly reduces the risk.
*   **Man-in-the-Middle Attacks:** Significantly reduces the risk.

**Currently Implemented:**
*   Fully supported and implemented *within* Headscale.  The features are built-in.

**Missing Implementation:**
*   Missing if the `pre_auth_keys` section is not configured in `config.yaml`, or if the `headscale nodes approve` command is not used for manual approval.

## Mitigation Strategy: [Headscale Configuration Hardening](./mitigation_strategies/headscale_configuration_hardening.md)

**Mitigation Strategy:**  Securely configure Headscale's settings.

**Description:**
1.  **`listen_addr` (in `config.yaml`):**  Bind Headscale to a *specific*, internal IP address.  *Avoid* `0.0.0.0` unless absolutely necessary (and then, only with a properly configured reverse proxy and firewall).  Prefer a loopback address (`127.0.0.1`) if using a reverse proxy.  Example:
    ```yaml
    listen_addr: "127.0.0.1:8080"
    ```
2.  **`server_url` (in `config.yaml`):**  Ensure this is set to the correct, publicly accessible URL (if applicable) *and that it uses HTTPS*.  This is crucial for clients to connect securely.  Example:
    ```yaml
    server_url: "https://headscale.example.com"
    ```
3.  **`metrics_listen_addr` (in `config.yaml`):**  If exposing metrics, bind this to a *separate*, restricted port and IP address.  Do *not* expose metrics publicly.  Ideally, only allow access from a dedicated monitoring system. Example:
    ```yaml
    metrics_listen_addr: "127.0.0.1:9090"
    ```
4.  **`log_level` (in `config.yaml`):**  Set the log level appropriately.  `info` is usually sufficient.  Use `debug` only for troubleshooting.  Example:
    ```yaml
    log_level: "info"
    ```
 5. **`unix_socket`** Use unix socket instead of TCP socket. Example:
    ```yaml
    unix_socket: /var/run/headscale.sock
    ```

**Threats Mitigated:**
*   **Unauthorized Access to Headscale Server (Severity: High):**  `listen_addr` and `metrics_listen_addr` limit the network exposure of the server.
*   **Eavesdropping on Coordination Traffic (Severity: High):**  `server_url` with HTTPS ensures encrypted communication.
*   **Information Disclosure (Severity: Medium):**  Appropriate `log_level` prevents excessive logging that might reveal sensitive information.
*   **DoS (Severity: Medium):** Using unix socket can improve performance and reduce risk of DoS.

**Impact:**
*   **Unauthorized Access:** Moderately reduces the risk (best combined with network segmentation).
*   **Eavesdropping:** Eliminates the risk if `server_url` uses HTTPS correctly.
*   **Information Disclosure:** Reduces the risk.
*   **DoS:** Slightly reduces the risk.

**Currently Implemented:**
*   Fully supported and implemented *within* Headscale's configuration file.

**Missing Implementation:**
*   Missing if these settings are not configured correctly in `config.yaml`.  Default values might not be secure.

## Mitigation Strategy: [Node Key Updates (via CLI)](./mitigation_strategies/node_key_updates__via_cli_.md)

**Mitigation Strategy:**  Update a node's WireGuard public key in Headscale.

**Description:**
1.  **Generate New Key Pair (on the Node):**  On the client node, generate a new WireGuard key pair.
2.  **Update Node Configuration (on the Node):** Update the WireGuard configuration file on the client node with the new private key.
3.  **Update Headscale (CLI):** Use the `headscale nodes register` command with the `-k` flag to update the node's public key in Headscale.  Example:
    ```bash
    headscale nodes register -k <new-public-key> -n <node-name> -u <user>
    ```
    *   `<new-public-key>`: The new public key from the client node.
    *   `<node-name>`: The name of the node in Headscale.
    *   `<user>`: The user the node belongs to.
4.  **Test Connectivity:**  Verify that the node can still connect after the key update.

**Threats Mitigated:**
*   **Compromised Node Keys (Severity: High):**  Allows you to revoke an old key and replace it with a new one, limiting the impact of a key compromise.

**Impact:**
*   **Compromised Node Keys:** Significantly reduces the risk (allows for key revocation).

**Currently Implemented:**
*   The `headscale nodes register` command with the `-k` flag provides the mechanism for updating keys *within* Headscale.

**Missing Implementation:**
*   This is a *manual* process.  There's no built-in automated key rotation.  The missing implementation is the *automation* and the *policy* of regularly updating keys. The *capability* exists within Headscale.

## Mitigation Strategy: [Stay Updated (Headscale Software)](./mitigation_strategies/stay_updated__headscale_software_.md)

**Mitigation Strategy:**  Update the Headscale software itself.

**Description:**
1.  **Monitor for Releases:**  Regularly check the Headscale GitHub repository for new releases.
2.  **Download New Version:** Download the latest release of Headscale.
3.  **Stop Headscale:** Stop the running Headscale service.
4.  **Replace Binary:** Replace the existing Headscale binary with the new version.
5.  **Restart Headscale:** Start the Headscale service.
6.  **Verify Functionality:**  Check that Headscale is running correctly and that nodes can connect.

**Threats Mitigated:**
*   **Vulnerabilities in Headscale Code (Severity: Variable, potentially Critical):**  Updating to the latest version patches any known security vulnerabilities in the Headscale software itself.

**Impact:**
*   **Vulnerabilities in Headscale Code:**  Significantly reduces the risk (the primary mitigation).

**Currently Implemented:**
*   Headscale provides release builds and instructions for updating. This is inherent to the project's release process.

**Missing Implementation:**
*   The *action* of regularly checking for and applying updates is missing if the user is not doing it.

