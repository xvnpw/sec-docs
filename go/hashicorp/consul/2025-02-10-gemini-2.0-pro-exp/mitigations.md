# Mitigation Strategies Analysis for hashicorp/consul

## Mitigation Strategy: [Enable TLS Encryption (Consul-Managed)](./mitigation_strategies/enable_tls_encryption__consul-managed_.md)

**Description:**
1.  **Generate Certificates (Consul CA):** Use Consul's built-in CA to generate server and client certificates.  This simplifies certificate management.  Use `consul tls cert create -server` and `consul tls cert create -client`.
2.  **Configure Consul Agents:** Modify the Consul agent configuration file (`config.json` or similar) on *each* agent:
    *   `verify_incoming = true`: Enforces TLS verification for incoming connections.
    *   `verify_outgoing = true`: Enforces TLS verification for outgoing connections.
    *   `verify_server_hostname = true`: Verifies the server's hostname against the certificate.
    *   `ca_file = "/path/to/consul-agent-ca.pem"`: Path to the Consul CA certificate.
    *   `cert_file = "/path/to/agent.crt"`: Path to the agent's certificate.
    *   `key_file = "/path/to/agent.key"`: Path to the agent's private key.
    *   `auto_encrypt = {enabled = true}`: (Optional, but recommended) Enables automatic TLS certificate management for clients.
3.  **Restart Consul Agents:** Restart all Consul agents to apply the new configuration.
4.  **Configure Applications (if not using `auto_encrypt`):** If `auto_encrypt` is not enabled, applications need to be configured to use HTTPS and provide the CA certificate.
5.  **Automated Certificate Rotation (Consul's `auto_encrypt`):** Leverage Consul's `auto_encrypt` feature for automatic client certificate provisioning and rotation. This simplifies client-side configuration.

*   **Threats Mitigated:**
    *   **Man-in-the-Middle (MITM) Attacks:** (Severity: High) - Prevents attackers from intercepting and modifying communication.
    *   **Unauthorized Agent Access:** (Severity: High) - Requires valid certificates for agents to join.
    *   **Data Eavesdropping:** (Severity: High) - Encrypts all communication.

*   **Impact:**
    *   MITM Attacks: Risk reduced to near zero (with proper CA management).
    *   Unauthorized Agent Access: Risk significantly reduced.
    *   Data Eavesdropping: Risk reduced to near zero.

*   **Currently Implemented:**
    *   TLS is enabled for server-to-server communication (datacenter `dc1`).
    *   `auto_encrypt` is enabled for some clients.

*   **Missing Implementation:**
    *   `auto_encrypt` is not consistently used for all clients.
    *   TLS is *not* enabled in the `staging` environment.

## Mitigation Strategy: [Gossip Encryption (Consul Keyring)](./mitigation_strategies/gossip_encryption__consul_keyring_.md)

**Description:**
1.  **Generate Encryption Key:** Generate a strong, random encryption key using `consul keygen`.
2.  **Configure Agents:** Add the `encrypt` parameter to the Consul agent configuration file on *all* agents:
    *   `encrypt = "<your_generated_key>"`
3.  **Restart Agents:** Restart all Consul agents.
4.  **Key Rotation (Consul Keyring):** Use `consul keyring` commands to manage and rotate the gossip encryption key without cluster downtime.  This involves:
    *   `consul keyring install <new_key>` (on all servers)
    *   `consul keyring use <new_key>` (on all servers)
    *   `consul keyring remove <old_key>` (on all servers, after a grace period)

*   **Threats Mitigated:**
    *   **Service Discovery Eavesdropping:** (Severity: Medium)
    *   **Limited MITM Protection:** (Severity: Medium)

*   **Impact:**
    *   Service Discovery Eavesdropping: Risk significantly reduced.
    *   Limited MITM Protection: Additional layer of defense.

*   **Currently Implemented:**
    *   Gossip encryption is enabled in all environments.

*   **Missing Implementation:**
    *   Automated key rotation using `consul keyring` is not yet scripted.

## Mitigation Strategy: [Agent Tokens (ACLs - Consul's Authorization System)](./mitigation_strategies/agent_tokens__acls_-_consul's_authorization_system_.md)

**Description:**
1.  **Enable ACLs:** Set `acl.enabled = true` in the Consul server configuration.
2.  **Bootstrap Token:** Use the bootstrap token *only* for initial setup.  Immediately create a new management token with limited privileges.
3.  **Default Policy:** Set `acl.default_policy = "deny"` to deny all actions by default.
4.  **Create Agent Tokens:** Create individual tokens for *each* Consul agent using the `consul acl token create` command.  Use the built-in `agent` policy or a custom policy with minimal permissions.
5.  **Create Application Tokens:** Create tokens for *each* application using `consul acl token create`.  Define specific permissions using `service`, `node`, `key`, `query`, and `event` rules to grant only the necessary access.
6.  **Token TTLs:** Set appropriate TTLs (Time-To-Live) for all tokens using the `-ttl` flag with `consul acl token create`.
7.  **Regular Review (Consul ACL commands):** Use `consul acl policy list`, `consul acl token list`, and `consul acl token read` to regularly review and audit ACL policies and tokens.

*   **Threats Mitigated:**
    *   **Unauthorized Access to Consul:** (Severity: High)
    *   **Privilege Escalation:** (Severity: High)
    *   **Data Breach:** (Severity: High)
    *   **Cluster Disruption:** (Severity: High)

*   **Impact:**
    *   All listed threats: Risk significantly reduced (with proper policy design).

*   **Currently Implemented:**
    *   ACLs are enabled.
    *   `acl.default_policy = "deny"`.
    *   Agent tokens are used.
    *   Basic application tokens exist.

*   **Missing Implementation:**
    *   Not all applications have dedicated, least-privilege tokens.
    *   Token TTLs are not consistently used.
    *   Regular ACL audits are not automated.
    *   Fine-grained K/V access control is incomplete.

## Mitigation Strategy: [Consul UI Access Control (Using Consul's ACLs)](./mitigation_strategies/consul_ui_access_control__using_consul's_acls_.md)

**Description:**
1.  **Authentication (Consul's Built-in or External):** Configure authentication for the Consul UI.  Consul supports built-in authentication (username/password) or integration with external identity providers (LDAP, OIDC) via configuration.
2.  **HTTPS (Requires TLS):** Ensure the Consul UI is *only* accessible over HTTPS (this requires TLS configuration, as described in strategy #1).
3.  **ACLs (Consul's Authorization):** Use Consul's ACL system to restrict access to specific UI features and data.  Create ACL policies and tokens that grant only the necessary permissions to different users or groups.  For example, you might have a "read-only" UI token and an "operator" UI token.
4. **Disable if Unnecessary:** If the UI is not strictly required, disable it via configuration (`ui = false`).

*   **Threats Mitigated:**
    *   **Unauthorized UI Access:** (Severity: High)
    *   **Information Disclosure:** (Severity: Medium)
    *   **Cluster Manipulation:** (Severity: High)

*   **Impact:**
    *   Unauthorized UI Access: Risk significantly reduced.
    *   Information Disclosure: Risk reduced.
    *   Cluster Manipulation: Risk significantly reduced.

*   **Currently Implemented:**
    *   UI is accessible over HTTPS.
    *   Basic authentication is enabled (Consul's built-in).

*   **Missing Implementation:**
    *   ACLs are *not* used to restrict UI access; all authenticated users have full access.
    *   Integration with a centralized identity provider is not implemented.

## Mitigation Strategy: [Prepared Queries (with ACL Control)](./mitigation_strategies/prepared_queries__with_acl_control_.md)

**Description:**
1.  **Define Prepared Queries:** Create prepared queries using the `consul query create` command or the API.  These queries define specific data retrieval patterns.
2.  **ACL Control:** Use ACLs to restrict who can:
    *   Create prepared queries (`query` rule with `write` permission).
    *   Modify existing prepared queries (`query` rule with `write` permission).
    *   Execute prepared queries (`query` rule with `read` permission).
3. **Input Validation (Within Query Definition):** Within the prepared query definition itself, use Consul's templating features to validate and sanitize any input parameters to prevent injection attacks.
4. **Limit Query Complexity:** Avoid overly complex or resource-intensive prepared queries that could be used for denial-of-service.

*   **Threats Mitigated:**
    *   **Data Exfiltration via Malicious Queries:** (Severity: Medium) - Prevents attackers from crafting arbitrary queries to extract sensitive data.
    *   **Service Discovery Disruption:** (Severity: Medium) - Prevents attackers from manipulating service discovery results through malicious queries.
    *   **Denial of Service (DoS):** (Severity: Low) - Limits the potential for resource exhaustion through complex queries.

*   **Impact:**
    *   Data Exfiltration: Risk significantly reduced.
    *   Service Discovery Disruption: Risk significantly reduced.
    *   DoS: Risk partially mitigated.

*   **Currently Implemented:**
    *   Prepared queries are used for some service discovery tasks.

*   **Missing Implementation:**
    *   ACLs are not consistently used to control access to prepared queries.
    *   Input validation within prepared query definitions is not comprehensive.

## Mitigation Strategy: [Event Handling (Watches with ACL Control)](./mitigation_strategies/event_handling__watches_with_acl_control_.md)

**Description:**
1.  **Define Watches:** Create watches using the Consul configuration file or the API. Watches trigger handlers (scripts or HTTP endpoints) based on changes in Consul's state.
2.  **ACL Control:** Use ACLs to restrict who can create and modify watches (`event` rule with `write` permission). This prevents unauthorized users from setting up watches that could trigger malicious actions.
3.  **Resource Limits (Handler-Side):** Implement resource limits (CPU, memory) *within the handler scripts or applications* that are triggered by watches. This prevents a compromised or misconfigured watch from consuming excessive resources. This is not directly a Consul feature, but is crucial when using watches.
4. **Secure Handlers:** Ensure that the scripts or HTTP endpoints triggered by watches are secure and do not introduce vulnerabilities.

*   **Threats Mitigated:**
    *   **Unauthorized Actions Triggered by Watches:** (Severity: Medium) - Prevents attackers from configuring watches to execute arbitrary code or trigger unwanted actions.
    *   **Resource Exhaustion:** (Severity: Low) - Limits the potential for watches to consume excessive resources.

*   **Impact:**
    *   Unauthorized Actions: Risk significantly reduced.
    *   Resource Exhaustion: Risk partially mitigated (primarily handled by handler-side limits).

*   **Currently Implemented:**
    *   Watches are used for some automation tasks.

*   **Missing Implementation:**
    *   ACLs are not used to control access to watch creation/modification.
    *   Resource limits are not consistently implemented within the watch handlers.

