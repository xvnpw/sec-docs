# Mitigation Strategies Analysis for ifttt/jazzhands

## Mitigation Strategy: [Source Identity Configuration within Jazzhands](./mitigation_strategies/source_identity_configuration_within_jazzhands.md)

**Mitigation Strategy:** Configure `jazzhands` to set `sts:SourceIdentity`.

**Description:**
1.  **Identify Source Identity Mapping:** Determine how `jazzhands` will obtain the user's or service's identity.  This often involves integrating with your identity provider (e.g., Okta).  For example, you might map the Okta username to the `SourceIdentity`.
2.  **Modify Jazzhands Configuration:**  Within the `jazzhands` configuration file (usually YAML), locate the section that controls how `AssumeRole` calls are made.  Add or modify the configuration to include the `source_identity` parameter.  This parameter should dynamically populate the `sts:SourceIdentity` value in the `AssumeRole` request.
3.  **Example (Conceptual YAML):**
    ```yaml
    aws:
      account_id: '123456789012'
      role_name: 'MyRole'
      source_identity: '{{ user.username }}'  # Placeholder - how this is populated depends on your setup
    ```
4.  **Testing:**  After configuring, thoroughly test that `jazzhands` is correctly setting the `SourceIdentity` in the `AssumeRole` requests.  You can verify this by examining CloudTrail logs.

**Threats Mitigated:**
*   **Credential Theft and Reuse (High Severity):** Prevents stolen `jazzhands`-obtained credentials from being used to assume roles intended for other users.
*   **Lateral Movement (High Severity):** Limits an attacker's ability to move laterally by assuming different roles.
*   **Impersonation (High Severity):** Prevents an attacker from impersonating a legitimate user.

**Impact:**
*   **Credential Theft and Reuse:** Significantly reduces the risk.
*   **Lateral Movement:** Makes lateral movement much more difficult.
*   **Impersonation:** Prevents impersonation.

**Currently Implemented:**
*   (e.g., "Implemented using the `okta.username` variable in the `jazzhands.yml` configuration file.")

**Missing Implementation:**
*   (e.g., "Currently, `SourceIdentity` is not being set.  The `jazzhands.yml` file needs to be updated to include the `source_identity` parameter.")

## Mitigation Strategy: [External ID Configuration within Jazzhands (Cross-Account)](./mitigation_strategies/external_id_configuration_within_jazzhands__cross-account_.md)

**Mitigation Strategy:** Configure `jazzhands` to provide `sts:ExternalId`.

**Description:**
1.  **Identify Cross-Account Roles:** Determine which roles accessed via `jazzhands` reside in *different* AWS accounts.
2.  **Obtain External IDs:** Obtain the correct `ExternalId` value for each cross-account role. This value should be provided by the administrator of the target AWS account.
3.  **Modify Jazzhands Configuration:**  In the `jazzhands` configuration, locate the section for each cross-account role.  Add or modify the configuration to include the `external_id` parameter, setting it to the correct value.
4.  **Example (Conceptual YAML):**
    ```yaml
    aws:
      account_id: '987654321098'  # Target account ID
      role_name: 'CrossAccountRole'
      external_id: 'MySecretExternalId'
    ```
5.  **Testing:**  Test the cross-account access to ensure that `jazzhands` is correctly providing the `ExternalId` and that the role can be assumed.

**Threats Mitigated:**
*   **Confused Deputy Problem (High Severity):** Prevents a service in one account from being tricked into assuming a role in another account.

**Impact:**
*   **Confused Deputy Problem:** Eliminates the risk in cross-account scenarios.

**Currently Implemented:**
*   (e.g., "Implemented for all cross-account roles.  The `external_id` values are stored securely and referenced in the `jazzhands` configuration.")

**Missing Implementation:**
*   (e.g., "Not applicable, as `jazzhands` is only used within a single AWS account.") OR (e.g., "Missing for the role that accesses resources in the `staging` account. The `external_id` needs to be added to the configuration.")

## Mitigation Strategy: [Session Duration Control within Jazzhands](./mitigation_strategies/session_duration_control_within_jazzhands.md)

**Mitigation Strategy:** Configure `jazzhands` for short session durations.

**Description:**
1.  **Analyze Task Durations:** For each task or workflow that uses `jazzhands`, determine the *minimum* time required for completion.
2.  **Configure Default Session Duration:**  In the `jazzhands` configuration file, set the `default_session_duration` (or a similarly named parameter, depending on the `jazzhands` version) to a short, reasonable value (e.g., 15 minutes). This will be the default for all roles unless overridden.
3.  **Configure Role-Specific Durations (Optional):** If specific roles require longer or shorter durations, you can override the default on a per-role basis within the configuration.
4.  **Example (Conceptual YAML):**
    ```yaml
    aws:
      default_session_duration: 900  # 15 minutes (in seconds)
      roles:
        - account_id: '123456789012'
          role_name: 'MyRole'
        - account_id: '123456789012'
          role_name: 'LongerRole'
          session_duration: 3600  # 1 hour (in seconds)
    ```
5. **Testing:** Verify that credentials obtained via `jazzhands` have the expected session durations.

**Threats Mitigated:**
*   **Credential Exposure (High Severity):** Reduces the window of opportunity for an attacker to use compromised temporary credentials.
*   **Session Hijacking (Medium Severity):** Makes session hijacking more difficult.

**Impact:**
*   **Credential Exposure:** Significantly reduces the impact.
*   **Session Hijacking:** Reduces the likelihood.

**Currently Implemented:**
*   (e.g., "Implemented with a `default_session_duration` of 900 seconds (15 minutes).")

**Missing Implementation:**
*   (e.g., "The `LongerRole` still has a default session duration.  A specific, shorter `session_duration` needs to be set for this role.")

## Mitigation Strategy: [Role Session Name Control within Jazzhands](./mitigation_strategies/role_session_name_control_within_jazzhands.md)

**Mitigation Strategy:** Configure `jazzhands` to use predictable `RoleSessionName`.

**Description:**
1.  **Define a Naming Convention:**  Establish a clear and consistent naming convention for the `RoleSessionName`.  This should include elements that help with auditing and tracking, such as a fixed prefix (e.g., "JazzhandsSession-"), a timestamp, and potentially a user identifier.  Avoid using user-supplied input directly to prevent injection attacks.
2.  **Configure Jazzhands:**  Modify the `jazzhands` configuration to use the defined naming convention.  This might involve using template variables or custom logic within the configuration.
3.  **Example (Conceptual - Implementation Details Vary):**
    *   You might configure `jazzhands` to generate a `RoleSessionName` like: `JazzhandsSession-{timestamp}-{user_id}`. The specific mechanism for doing this depends on `jazzhands`'s features and your integration with your identity provider.
4.  **Testing:**  Verify that the `RoleSessionName` in CloudTrail logs adheres to the defined convention.

**Threats Mitigated:**
*   **Auditing and Tracking (Medium Severity):** Makes it easier to track and audit `AssumeRole` events in CloudTrail.
*   **Injection Attacks (Low Severity):** Prevents potential injection attacks if user input were to be used directly in the `RoleSessionName`.

**Impact:**
*   **Auditing and Tracking:** Improves auditability and traceability.
*   **Injection Attacks:** Mitigates a low-risk injection vulnerability.

**Currently Implemented:**
*   (e.g., "Implemented using a combination of a fixed prefix and a UUID: `JazzhandsSession-{uuid.uuid4()}`")

**Missing Implementation:**
*   (e.g., "Currently, the `RoleSessionName` is not consistently formatted.  A clear naming convention needs to be defined and implemented in the `jazzhands` configuration.")

## Mitigation Strategy: [Restrict Role Chaining (Configuration within Jazzhands and IAM)](./mitigation_strategies/restrict_role_chaining__configuration_within_jazzhands_and_iam_.md)

**Mitigation Strategy:** Prevent or control role chaining initiated by `jazzhands`.

**Description:**
1.  **Identify Role Chaining Scenarios:** Determine if any roles assumed via `jazzhands` are *further* assuming other roles (role chaining).
2.  **Disable Role Chaining (Preferred):** If role chaining is not *absolutely* necessary, the best approach is to disable it. This can be done by:
    *   **Jazzhands Configuration (If Supported):** Some versions or configurations of `jazzhands` might have options to prevent role chaining. Check the documentation.
    *   **IAM Policy Modification:** Modify the IAM policies of the roles assumed by `jazzhands` to *remove* the `sts:AssumeRole` permission. This prevents those roles from assuming any other roles.
3.  **Control Role Chaining (If Necessary):** If role chaining is unavoidable, implement strict controls:
    *   **Explicitly Allow Chaining:** In the trust policy of the *final* role in the chain, explicitly allow the *intermediate* role (the one assumed by `jazzhands`) to assume it. Use the `sts:SourceIdentity` and potentially `sts:ExternalId` conditions for added security.
    *   **Minimize Permissions:** Ensure that *all* roles in the chain have the absolute minimum permissions required.
    *   **Intensive Monitoring:** Implement very close monitoring of role chaining events through CloudTrail and other logging mechanisms.

**Threats Mitigated:**
*   **Privilege Escalation (High Severity):** Uncontrolled role chaining can allow an attacker to gain significantly elevated privileges.
*   **Lateral Movement (High Severity):** Role chaining can be used to move laterally within the AWS environment.

**Impact:**
*   **Privilege Escalation:** Significantly reduces or eliminates the risk, depending on whether chaining is disabled or strictly controlled.
*   **Lateral Movement:** Makes lateral movement much more difficult.

**Currently Implemented:**
*   (e.g., "Role chaining is disabled. The IAM policies of roles assumed by `jazzhands` do not include the `sts:AssumeRole` permission.")

**Missing Implementation:**
*   (e.g., "Role chaining is currently allowed and uncontrolled.  The IAM policies need to be reviewed and modified to either disable chaining or implement strict controls.")

