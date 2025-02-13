# Mitigation Strategies Analysis for typicode/json-server

## Mitigation Strategy: [Network Isolation via Localhost Binding](./mitigation_strategies/network_isolation_via_localhost_binding.md)

**Description:**
1.  Identify the current binding configuration. Check the startup script or command for options like `--host`.
2.  Modify the startup command to *explicitly* bind `json-server` to localhost (127.0.0.1) using the `--host` flag:
    ```bash
    json-server --watch db.json --host 127.0.0.1
    ```
3.  Restart `json-server`.
4.  Verify the binding (e.g., using `netstat` or `Resource Monitor`) to confirm it's only listening on 127.0.0.1.  Attempt access from another machine; it should be denied.

**Threats Mitigated:**
*   **Threat:** Accidental Public Exposure (Severity: High) - Binding to all interfaces (0.0.0.0) makes the server accessible from any machine on the network, and potentially the public internet.
*   **Threat:** Unauthorized Access from Local Network (Severity: Medium) - Other users/devices on the local network could access the server if it's not restricted.

**Impact:**
*   Accidental Public Exposure: Risk reduced from High to Very Low.
*   Unauthorized Access from Local Network: Risk reduced from Medium to Very Low.

**Currently Implemented:** Partially.  `--host` is used in some scripts, but not consistently. Documentation mentions it, but it's not enforced.

**Missing Implementation:**
*   Standardized startup scripts across all environments to ensure consistent use of `--host 127.0.0.1`.
*   Automated checks (pre-commit hook, CI/CD) to verify `json-server` is *not* running on 0.0.0.0.
*   Clearer documentation and developer training.

## Mitigation Strategy: [Data Protection with Dummy Data](./mitigation_strategies/data_protection_with_dummy_data.md)

**Description:**
1.  Establish a policy: *Only* mock/dummy data with no real-world value is allowed in `db.json`.
2.  Create a script to generate dummy data (e.g., JavaScript/Python script creating a JSON file with placeholders).
3.  Integrate this script into the workflow (e.g., run before starting `json-server` or as part of a build).
4.  Regularly review `db.json` (manually or automated) to ensure no sensitive data has been introduced.
5. Ensure `db.json` is in `.gitignore`.

**Threats Mitigated:**
*   **Threat:** Exposure of Sensitive Data (Severity: Critical) - Real user data, API keys, etc., in `db.json` could lead to data breaches, financial loss, and reputational damage.
*   **Threat:** Accidental Data Modification (Severity: Medium) - If real data is used, developers might accidentally modify it, potentially impacting production.

**Impact:**
*   Exposure of Sensitive Data: Risk reduced from Critical to Very Low (if the policy is strictly followed).
*   Accidental Data Modification: Risk reduced from Medium to Very Low.

**Currently Implemented:** Partially. Developers are generally aware, but there's no formal policy, automated generation, or review. `db.json` is in `.gitignore`.

**Missing Implementation:**
*   Formal written policy.
*   Automated dummy data generation script.
*   Regular review process (e.g., monthly audit).
*   Integration of the data generation script into the workflow.

## Mitigation Strategy: [Read-Only Mode](./mitigation_strategies/read-only_mode.md)

**Description:**
1.  Modify the `json-server` startup command to include the `--read-only` or `-ro` flag:
    ```bash
    json-server --watch db.json --read-only
    ```
2.  Restart `json-server`.
3.  Verify that POST, PUT, PATCH, and DELETE requests return an error (e.g., 403 or 405).

**Threats Mitigated:**
*   **Threat:** Unauthorized Data Modification (Severity: Medium) - Prevents modification through the API, relevant if the server is exposed more widely than intended.
*   **Threat:** Accidental Data Corruption (Severity: Low) - Reduces accidental modification via API calls during testing.

**Impact:**
*   Unauthorized Data Modification: Risk reduced from Medium to Low (data can still be read, but not altered via the API).
*   Accidental Data Corruption: Risk reduced from Low to Very Low.

**Currently Implemented:** No.  `--read-only` is not used.

**Missing Implementation:**
*   Update all startup scripts and documentation to include `--read-only`.
*   Consider making this the default, with an option to enable write access for specific testing.

## Mitigation Strategy: [Custom Routes for Limited Access Control](./mitigation_strategies/custom_routes_for_limited_access_control.md)

**Description:**
1.  Create a `routes.json` file.
2.  Define custom routes that add a basic check, such as a required query parameter:
    ```json
    {
      "/api/data?secret=mysecret": "/data"
    }
    ```
3.  Start `json-server` with the `--routes` option:
    ```bash
    json-server db.json --routes routes.json
    ```
4. Test to ensure only requests with the correct query parameter work.

**Threats Mitigated:**
*   **Threat:** Casual Unauthorized Access (Severity: Low) - Deters casual attempts to access the data, but is easily bypassed.  *Not a robust security measure.*

**Impact:**
*   Casual Unauthorized Access: Risk slightly reduced, but remains Low. This is more of a deterrent than actual protection.

**Currently Implemented:** No.

**Missing Implementation:**
*   Creation of a `routes.json` file.
*   Modification of the startup command to include `--routes`.
*   Documentation and developer awareness.  *Emphasis should be placed on the fact that this is not a strong security measure.*

