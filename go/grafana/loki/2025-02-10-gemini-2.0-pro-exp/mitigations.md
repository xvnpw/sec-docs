# Mitigation Strategies Analysis for grafana/loki

## Mitigation Strategy: [Robust Multi-Tenant Authentication and Authorization (Loki-Direct)](./mitigation_strategies/robust_multi-tenant_authentication_and_authorization__loki-direct_.md)

**Description:**
1.  **Enable Authentication:** Set `auth_enabled: true` in the Loki configuration file (`loki.yaml` or equivalent). This is the foundational step for enabling Loki's built-in authentication.
2.  **OIDC Integration (Configuration):** Configure Loki's `server` section to integrate with your chosen OIDC provider. This involves specifying:
    *   `client_id`: The client ID obtained from your IdP.
    *   `client_secret`: The client secret (store securely, *never* in plain text).
    *   `issuer_url`: The discovery URL of your IdP.
    *   `scopes`: The OIDC scopes to request (e.g., `openid`, `profile`, `email`).
    *   `username_claim`: The claim in the ID token that represents the username (e.g., `sub`, `email`).
    *   `groups_claim`: The claim that contains the user's group memberships (if using groups for RBAC).
3.  **`X-Scope-OrgID` Enforcement (Client-Side, but Loki-Related):**  While the *enforcement* happens on the client side (Promtail, Grafana, etc.), this is *directly* related to Loki's multi-tenancy.  Loki *relies* on this header for tenant isolation.  Document clearly that all clients *must* send the `X-Scope-OrgID` header with the correct tenant ID.
4. **Test Configuration:** Use `curl` or a similar tool to directly test Loki's API with and without the `X-Scope-OrgID` header and with different JWTs (JSON Web Tokens) from your IdP to verify that authentication and authorization are working as expected.

*   **Threats Mitigated:**
    *   **Unauthorized Access to Logs (Critical):** Prevents users from accessing logs belonging to other tenants.
    *   **Data Exfiltration (Critical):** Reduces the risk of unauthorized users downloading log data.
    *   **Privilege Escalation (High):** Limits the ability of a compromised account to access logs outside its tenant.

*   **Impact:**
    *   **Unauthorized Access:** Risk reduced from *Critical* to *Low*.
    *   **Data Exfiltration:** Risk reduced from *Critical* to *Low*.
    *   **Privilege Escalation:** Risk reduced from *High* to *Low*.

*   **Currently Implemented:**
    *   `auth_enabled: true` is set.
    *   OIDC configuration with Keycloak is present in `loki.yaml`.
    *   Documentation emphasizes the need for the `X-Scope-OrgID` header.

*   **Missing Implementation:**
    *   Automated testing of the OIDC configuration with various tokens and headers is not yet part of the CI/CD pipeline.

## Mitigation Strategy: [Rate Limiting and Resource Quotas (Loki Configuration)](./mitigation_strategies/rate_limiting_and_resource_quotas__loki_configuration_.md)

**Description:**
1.  **`limits_config` Section:**  Configure the `limits_config` section within your `loki.yaml` file. This is *entirely* within Loki's configuration.
2.  **Ingestion Limits:**
    *   `ingestion_rate_mb`: Set the per-tenant average ingestion rate limit (in MB/s).
    *   `ingestion_burst_size_mb`: Set the per-tenant burst size (in MB).
3.  **Query Limits:**
    *   `max_entries_limit_per_query`: Limit the maximum number of log entries a single query can return.
    *   `max_chunks_per_query`: Limit the maximum number of chunks a single query can return.
    *   `query_timeout`: Set a maximum duration for a query to execute.
4. **Per-Tenant Overrides:** Use the `per_tenant_override_config` setting to specify a separate configuration file that allows you to define different limits for specific tenants. This is useful if some tenants have higher or lower resource requirements.
5. **Test Limits:** Use load testing tools to simulate various ingestion and query loads to verify that the limits are effective and tuned appropriately.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (High):** Prevents attackers from overwhelming Loki with excessive data or queries.
    *   **Resource Exhaustion (High):** Protects Loki from crashing due to excessive resource usage.

*   **Impact:**
    *   **DoS:** Risk reduced from *High* to *Medium*.
    *   **Resource Exhaustion:** Risk reduced from *High* to *Low*.

*   **Currently Implemented:**
    *   Basic `limits_config` settings are present in `loki.yaml`.

*   **Missing Implementation:**
    *   `per_tenant_override_config` is not currently used.
    *   Thorough load testing and fine-tuning of the limits are needed.

## Mitigation Strategy: [Audit Logging (Loki-Direct, if Supported)](./mitigation_strategies/audit_logging__loki-direct__if_supported_.md)

**Description:**
1.  **Check for Audit Log Support:** Determine if your Loki version supports built-in audit logging.  This feature may not be available in all versions. Refer to the official Loki documentation.
2.  **Enable Audit Logging (Configuration):** If supported, enable audit logging within the Loki configuration file (`loki.yaml`).  The specific configuration options will vary depending on the Loki version.  Look for settings related to "audit" or "audit logging."
3. **Configure Audit Log Destination:** Specify where Loki should send the audit log data. Ideally, this should be a *separate* file or a dedicated logging pipeline (e.g., sending to another Loki instance). *Do not store audit logs in the same location as the primary log data.*
4. **Test Audit Logging:** After enabling audit logging, perform some actions (e.g., queries, configuration changes) and verify that the audit log entries are being generated and stored as expected.

*   **Threats Mitigated:**
    *   **Data Exfiltration (High):** Provides visibility into data access patterns.
    *   **Insider Threats (High):** Helps detect malicious insider activity.
    *   **Compromise Detection (Medium):** Aids in investigating security incidents.

*   **Impact:**
    *   **Data Exfiltration:** Risk reduced from *High* to *Medium*.
    *   **Insider Threats:** Risk reduced from *High* to *Medium*.
    *   **Compromise Detection:** Significantly improves detection capabilities.

*   **Currently Implemented:**
    *   None (pending verification of audit log support in the current Loki version).

*   **Missing Implementation:**
    *   All aspects of audit logging are currently missing.

## Mitigation Strategy: [`reject_old_samples` Configuration](./mitigation_strategies/_reject_old_samples__configuration.md)

**Description:**
1.  **Locate `limits_config`:**  Within your `loki.yaml` file, find the `limits_config` section.
2.  **Enable Rejection:** Set `reject_old_samples: true`. This is the primary toggle.
3.  **Set Time Window:** Configure `reject_old_samples_max_age: <duration>`.  Replace `<duration>` with a time duration string (e.g., `168h` for one week, `24h` for one day).  This defines how far back in time Loki will accept log entries.  Choose a value appropriate for your log ingestion pipeline and latency.
4. **Test Rejection:** Attempt to ingest log entries with timestamps older than the configured `reject_old_samples_max_age`. Verify that Loki rejects these entries.

*   **Threats Mitigated:**
    *   **Log Tampering (Medium):** Prevents attackers from injecting old, potentially misleading log entries to cover their tracks or replay old events.
    *   **Data Integrity Issues (Low):** Helps maintain the chronological order of logs.

*   **Impact:**
    *   **Log Tampering:** Risk reduced from *Medium* to *Low*.
    *   **Data Integrity:** Improves data integrity.

*   **Currently Implemented:**
      * Not implemented.

*   **Missing Implementation:**
    *   All aspects are currently missing.  This should be added to the `limits_config`.

