# Mitigation Strategies Analysis for peergos/peergos

## Mitigation Strategy: [Implement Robust Peer Verification and Authentication (Peergos Focused)](./mitigation_strategies/implement_robust_peer_verification_and_authentication__peergos_focused_.md)

**Description:**
1.  **Step 1: Utilize Peergos Identity Mechanisms:**  Ensure your application strictly leverages `peergos`'s built-in peer identity management. This involves using cryptographic keys and identity protocols provided by `peergos` for peer identification and connection establishment. Refer to `peergos` documentation for the correct APIs and configurations.
2.  **Step 2: Configure Peergos Authentication Levels:** If `peergos` offers different levels of peer authentication or security settings for connections, configure them according to your application's security requirements. Choose the strongest authentication level supported by `peergos` that is practical for your use case.
3.  **Step 3: Peer ID Management within Application:**  Within your application code, consistently use and verify peer IDs provided by `peergos` when interacting with peers. Avoid relying on external or less secure methods for peer identification when `peergos` provides a secure mechanism.
4.  **Step 4: Monitor Peergos Peer Connection Events:** Utilize `peergos`'s logging or event mechanisms to monitor peer connection attempts, authentication successes, and failures. Analyze these logs to detect suspicious peer activity or potential authentication bypass attempts related to `peergos`.

*   **List of Threats Mitigated:**
    *   **Malicious Peer Injection via Peergos (High Severity):** Unauthorized peers exploiting weaknesses in `peergos`'s peer discovery or authentication to join the network and inject malicious content or attacks.
    *   **Man-in-the-Middle Attacks against Peergos Connections (Medium Severity):** Attackers attempting to intercept or impersonate peers during `peergos` connection establishment if peer verification is weak or bypassed.
    *   **Unauthorized Data Access via Peergos Peers (High Severity):**  Unverified or malicious peers gaining access to data or functionalities exposed through the `peergos` network due to inadequate peer authentication.

*   **Impact:**
    *   **Malicious Peer Injection via Peergos:** High Impact - Significantly reduces the risk by ensuring only properly authenticated peers, as verified by `peergos`, can participate in the network.
    *   **Man-in-the-Middle Attacks against Peergos Connections:** Medium Impact - Reduces the risk by strengthening the initial peer connection phase managed by `peergos`.
    *   **Unauthorized Data Access via Peergos Peers:** High Impact - Prevents unauthorized access by limiting network participation to peers authenticated through `peergos` mechanisms.

*   **Currently Implemented:**
    *   Basic `peergos` peer identity verification is likely used as it's fundamental to `peergos`'s operation. The application probably relies on `peergos` for peer discovery and connection, which inherently involves some level of cryptographic identity.

*   **Missing Implementation:**
    *   Configuration of stronger `peergos` authentication levels (if available) might be missing, relying on default or weaker settings.
    *   Explicit application-level checks to consistently verify `peergos` peer IDs in all peer interactions might be lacking.
    *   Detailed monitoring and analysis of `peergos` peer connection events for security purposes are likely not implemented.


## Mitigation Strategy: [Rate Limiting and Connection Limits (Peergos Peer Focused)](./mitigation_strategies/rate_limiting_and_connection_limits__peergos_peer_focused_.md)

**Description:**
1.  **Step 1: Configure Peergos Connection Limits:** Utilize `peergos`'s configuration options to set limits on the number of incoming peer connections accepted by your `peergos` nodes. This directly controls how many peers can connect to your `peergos` instance.
2.  **Step 2: Implement Peer-Specific Rate Limiting (if Peergos Allows):** If `peergos` provides features for rate limiting requests or data transfer from individual peers, configure these limits to prevent abuse from malicious or misbehaving peers.
3.  **Step 3: Monitor Peergos Peer Connection Metrics:** Use `peergos`'s monitoring or metrics capabilities to track the number of active peer connections, connection rates, and data transfer rates per peer. Monitor these metrics for anomalies that might indicate DoS attacks targeting your `peergos` nodes.
4.  **Step 4: Dynamic Peer Blacklisting based on Peergos Metrics:**  If unusual activity is detected from specific peers based on `peergos` metrics (e.g., excessive connection attempts, high data transfer rates), implement mechanisms to dynamically blacklist or temporarily disconnect these peers through `peergos`'s API or configuration.

*   **List of Threats Mitigated:**
    *   **Peergos Peer Connection Flooding DoS (High Severity):** Attackers overwhelming your `peergos` nodes with a flood of connection requests from numerous malicious peers, exploiting `peergos`'s peer-to-peer networking.
    *   **Resource Exhaustion DoS via Peergos Peers (Medium Severity):** Malicious peers consuming excessive resources (bandwidth, processing power) on your `peergos` nodes through high volumes of requests or data transfer within the `peergos` network.
    *   **Abuse of Peergos Services by Malicious Peers (Medium Severity):** Malicious peers exploiting functionalities offered by `peergos` (e.g., data storage, retrieval, computation if applicable) in an abusive or resource-intensive manner.

*   **Impact:**
    *   **Peergos Peer Connection Flooding DoS:** High Impact - Significantly reduces the risk by limiting the number of peer connections `peergos` will accept, preventing connection-based DoS attacks.
    *   **Resource Exhaustion DoS via Peergos Peers:** Medium Impact - Reduces the risk by limiting resource consumption from individual peers or the total number of peers connected to `peergos`.
    *   **Abuse of Peergos Services by Malicious Peers:** Medium Impact - Helps mitigate abuse by limiting the rate at which peers can interact with `peergos` services.

*   **Currently Implemented:**
    *   Default connection limits within `peergos` might be in place, but they might not be specifically configured for security or tuned to application needs.

*   **Missing Implementation:**
    *   Customized `peergos` connection limits optimized for security and resource capacity are likely not configured.
    *   Peer-specific rate limiting within `peergos` (if available) is probably not implemented.
    *   Monitoring of `peergos` peer connection metrics for security purposes is likely missing.
    *   Dynamic peer blacklisting based on `peergos` metrics is probably not implemented, requiring manual intervention to block abusive peers.


## Mitigation Strategy: [Content Verification and Integrity Checks (Peergos Content Addressing)](./mitigation_strategies/content_verification_and_integrity_checks__peergos_content_addressing_.md)

**Description:**
1.  **Step 1: Enforce Peergos Content Addressing Usage:**  Ensure your application *always* uses `peergos`'s content addressing (CIDs) when referencing data stored and retrieved through `peergos`. Avoid using location-based addressing or any methods that bypass content addressing.
2.  **Step 2: Implement Peergos Content Hash Verification:**  After retrieving data from `peergos` using a CID, *always* verify that the hash of the received data matches the expected CID. Utilize `peergos`'s API or libraries to perform this hash verification.
3.  **Step 3: Handle Peergos Content Verification Failures:** Implement robust error handling for cases where `peergos` content hash verification fails. Treat such data as potentially compromised or corrupted. Log verification failures and prevent the application from using unverified data.
4.  **Step 4: Explore Peergos Content Signing/Attestation (If Available):** Investigate if `peergos` offers features for content signing or cryptographic attestation. If so, implement these features to further enhance content authenticity and non-repudiation within your `peergos` based system.

*   **List of Threats Mitigated:**
    *   **Data Tampering within Peergos Network (High Severity):** Malicious peers or nodes within the `peergos` network modifying data after it's stored, exploiting potential vulnerabilities in `peergos`'s data handling.
    *   **Content Replacement/Spoofing in Peergos (Medium Severity):** Attackers attempting to replace legitimate content stored in `peergos` with malicious content while trying to maintain or manipulate content identifiers (if content addressing is not strictly enforced).
    *   **Data Corruption during Peergos Storage/Retrieval (Low Severity):** Accidental data corruption occurring during `peergos`'s storage or retrieval processes, which can be detected by content hash verification.

*   **Impact:**
    *   **Data Tampering within Peergos Network:** High Impact - Significantly reduces the risk by ensuring data integrity is cryptographically verified upon retrieval from `peergos`, detecting any tampering.
    *   **Content Replacement/Spoofing in Peergos:** Medium Impact - Reduces the risk by relying on content hashes, making it extremely difficult to replace content without detection if content addressing is correctly used and verified.
    *   **Data Corruption during Peergos Storage/Retrieval:** Low Impact - Helps detect accidental data corruption issues within the `peergos` system.

*   **Currently Implemented:**
    *   The application likely uses `peergos`'s content addressing for data storage and retrieval as it's a core principle of `peergos`.

*   **Missing Implementation:**
    *   Explicit and consistent content hash verification after every data retrieval from `peergos` might not be implemented in all application code paths.
    *   Robust error handling and logging for `peergos` content verification failures are likely missing.
    *   Utilization of `peergos` content signing or attestation features (if available) is probably not implemented.


## Mitigation Strategy: [Data Encryption at Rest and in Transit (Leverage Peergos Features)](./mitigation_strategies/data_encryption_at_rest_and_in_transit__leverage_peergos_features_.md)

**Description:**
1.  **Step 1: Configure Peergos Encryption at Rest:**  Thoroughly investigate `peergos`'s capabilities for encrypting data at rest within its storage layer. Configure `peergos` to enable encryption at rest using strong encryption algorithms and secure key management practices as offered by `peergos`. Consult `peergos` documentation for specific configuration steps.
2.  **Step 2: Enforce Peergos Encryption in Transit:** Verify and ensure that `peergos` is configured to use encryption for all data in transit, especially for peer-to-peer communication and any API interactions with `peergos`. This typically involves using secure protocols like TLS/SSL within `peergos`'s network communication settings.
3.  **Step 3: Utilize Peergos Key Management (If Secure):** If `peergos` provides secure key management features for its encryption, utilize these features. Ensure that encryption keys used by `peergos` are generated, stored, and managed securely according to best practices and `peergos`'s recommendations.
4.  **Step 4: Monitor Peergos Encryption Configuration:** Regularly review and monitor `peergos`'s encryption configuration to ensure that encryption at rest and in transit remain enabled and are using strong cryptographic settings. Check `peergos` logs or monitoring tools for any encryption-related issues.

*   **List of Threats Mitigated:**
    *   **Data Confidentiality Breach via Peergos Storage (High Severity):** Unauthorized access to sensitive data if `peergos` storage is compromised or accessed by malicious actors, mitigated by `peergos` encryption at rest.
    *   **Data Interception in Peergos Network (Medium Severity):** Eavesdropping on network traffic within the `peergos` network or between your application and `peergos`, mitigated by `peergos` encryption in transit.
    *   **Data Exposure in Case of Peergos Node Compromise (High Severity):** If a `peergos` node or storage component is compromised, encryption at rest prevents immediate access to plaintext data.

*   **Impact:**
    *   **Data Confidentiality Breach via Peergos Storage:** High Impact - Significantly reduces the risk by rendering data unreadable to unauthorized parties even if they gain access to the underlying `peergos` storage.
    *   **Data Interception in Peergos Network:** Medium Impact - Reduces the risk of passive eavesdropping on sensitive data exchanged within the `peergos` network.
    *   **Data Exposure in Case of Peergos Node Compromise:** High Impact - Provides a strong layer of defense against data exposure even if physical or logical security of `peergos` infrastructure is breached.

*   **Currently Implemented:**
    *   `Peergos` likely has default encryption features, but the specific configuration and strength might be unknown or not optimized for security.

*   **Missing Implementation:**
    *   Explicit configuration and verification of `peergos`'s encryption at rest are likely missing.
    *   Verification that `peergos` is enforcing encryption in transit for all relevant communication channels is probably missing.
    *   Secure key management practices specifically for `peergos` encryption keys might not be implemented.
    *   Regular monitoring of `peergos` encryption configuration and status is likely not in place.


## Mitigation Strategy: [Access Control and Permissions Management within Peergos](./mitigation_strategies/access_control_and_permissions_management_within_peergos.md)

**Description:**
1.  **Step 1: Utilize Peergos Access Control Features:**  Explore and utilize `peergos`'s built-in access control and permissions management features. Understand how `peergos` allows you to define permissions for data, functionalities, or resources within its system.
2.  **Step 2: Define Granular Peergos Access Control Policies:** Implement granular access control policies within `peergos` based on the principle of least privilege. Grant peers and application components only the minimum necessary permissions to access and interact with data and functionalities managed by `peergos`.
3.  **Step 3: Integrate Application Authorization with Peergos Access Control:** If your application has its own authorization logic, integrate it with `peergos`'s access control mechanisms. Ensure that application-level authorization decisions are enforced by `peergos`'s permission system.
4.  **Step 4: Regularly Audit Peergos Access Control Configuration:** Periodically review and audit the access control configurations within `peergos`. Verify that permissions are correctly assigned, policies are up-to-date, and access control is effectively enforcing security requirements.

*   **List of Threats Mitigated:**
    *   **Unauthorized Data Access via Peergos (High Severity):**  Unauthorized peers or application components gaining access to sensitive data stored in `peergos` due to inadequate access control within `peergos`.
    *   **Privilege Escalation within Peergos (Medium Severity):**  Attackers or compromised components exploiting weaknesses in `peergos`'s access control to gain higher privileges than intended, allowing unauthorized actions.
    *   **Data Modification or Deletion by Unauthorized Entities (High Severity):**  Unauthorized peers or components modifying or deleting data managed by `peergos` due to insufficient access control enforcement.

*   **Impact:**
    *   **Unauthorized Data Access via Peergos:** High Impact - Significantly reduces the risk by restricting access to data within `peergos` only to authorized entities as defined by `peergos`'s access control policies.
    *   **Privilege Escalation within Peergos:** Medium Impact - Reduces the risk of privilege escalation by enforcing clear permission boundaries within the `peergos` system.
    *   **Data Modification or Deletion by Unauthorized Entities:** High Impact - Prevents unauthorized modification or deletion of data by controlling write and delete permissions within `peergos`.

*   **Currently Implemented:**
    *   Basic access control features might be enabled in `peergos` by default, but granular policies tailored to application needs are likely missing.

*   **Missing Implementation:**
    *   Detailed access control policies within `peergos` based on the principle of least privilege are probably not defined.
    *   Integration between application-level authorization and `peergos` access control is likely missing, potentially leading to inconsistent enforcement.
    *   Regular audits of `peergos` access control configurations are probably not performed.


## Mitigation Strategy: [Regularly Update Peergos and its Dependencies](./mitigation_strategies/regularly_update_peergos_and_its_dependencies.md)

**Description:**
1.  **Step 1: Monitor Peergos Releases and Security Advisories:** Regularly monitor the `peergos` project's release notes, security advisories, and vulnerability databases for any reported security issues or updates. Subscribe to `peergos` mailing lists or forums if available to receive security notifications.
2.  **Step 2: Establish Peergos Update Process:** Define a process for promptly applying updates to `peergos` and its dependencies. This process should include testing updates in a non-production environment before deploying them to production.
3.  **Step 3: Use Dependency Management Tools:** Utilize dependency management tools to track and manage `peergos` and its dependencies. These tools can help identify outdated or vulnerable dependencies and simplify the update process.
4.  **Step 4: Automate Peergos Updates (Where Possible and Safe):** Explore options for automating the update process for `peergos` and its dependencies, where appropriate and safe. Automated updates can help ensure timely patching of vulnerabilities, but should be carefully tested and monitored.

*   **List of Threats Mitigated:**
    *   **Exploitation of Known Peergos Vulnerabilities (High Severity):** Attackers exploiting publicly known security vulnerabilities in `peergos` or its dependencies if updates are not applied promptly.
    *   **Zero-Day Vulnerabilities in Peergos (High Severity):** While updates don't prevent zero-day attacks, staying up-to-date reduces the overall attack surface and ensures you benefit from community security efforts.
    *   **Dependency Vulnerabilities in Peergos Stack (High Severity):** Vulnerabilities in libraries or components used by `peergos` that could be exploited to compromise `peergos` or your application.

*   **Impact:**
    *   **Exploitation of Known Peergos Vulnerabilities:** High Impact - Significantly reduces the risk by patching known vulnerabilities that attackers could exploit.
    *   **Zero-Day Vulnerabilities in Peergos:** Medium Impact - Reduces the overall attack surface and improves resilience against potential future vulnerabilities.
    *   **Dependency Vulnerabilities in Peergos Stack:** High Impact - Mitigates risks arising from vulnerabilities in the broader software ecosystem that `peergos` relies upon.

*   **Currently Implemented:**
    *   There might be a general process for updating software components, but it might not be specifically focused on `peergos` and its dependencies.

*   **Missing Implementation:**
    *   A dedicated process for monitoring `peergos` releases and security advisories is likely missing.
    *   A defined and tested process for applying `peergos` updates promptly is probably not in place.
    *   Dependency management tools might not be specifically used to track `peergos` dependencies and identify vulnerabilities.
    *   Automated update mechanisms for `peergos` are likely not implemented.


## Mitigation Strategy: [Security Audits and Code Reviews of Peergos Integration](./mitigation_strategies/security_audits_and_code_reviews_of_peergos_integration.md)

**Description:**
1.  **Step 1: Conduct Regular Security Audits of Peergos Integration:** Schedule periodic security audits specifically focused on your application's integration with `peergos`. These audits should be performed by security experts familiar with `peergos` and decentralized systems.
2.  **Step 2: Perform Code Reviews of Peergos Interaction Code:** Conduct code reviews of all application code that interacts with `peergos`'s API, handles data from `peergos`, and manages peer connections. Focus on identifying potential security vulnerabilities in your integration logic.
3.  **Step 3: Focus Audits on Peergos-Specific Risks:** Ensure that security audits specifically address the unique risks introduced by using `peergos`, such as peer-to-peer networking vulnerabilities, decentralized data storage risks, and potential issues in `peergos`'s implementation.
4.  **Step 4: Address Audit Findings and Remediate Vulnerabilities:**  Prioritize and address any security vulnerabilities identified during audits and code reviews. Implement necessary code changes, configuration adjustments, or mitigation measures to remediate these vulnerabilities.

*   **List of Threats Mitigated:**
    *   **Integration Vulnerabilities in Peergos Usage (High Severity):** Security flaws introduced in your application's code when integrating with `peergos`, such as improper API usage, insecure data handling, or vulnerabilities in peer interaction logic.
    *   **Configuration Errors in Peergos Setup (Medium Severity):** Misconfigurations in `peergos` settings that could weaken security, such as insecure default settings, improperly configured access control, or weak encryption settings.
    *   **Unforeseen Security Risks in Peergos Integration (Medium Severity):**  Security vulnerabilities that might not be immediately obvious but could be uncovered through expert security analysis of your specific `peergos` integration.

*   **Impact:**
    *   **Integration Vulnerabilities in Peergos Usage:** High Impact - Significantly reduces the risk by identifying and fixing security flaws in your application's code related to `peergos` integration.
    *   **Configuration Errors in Peergos Setup:** Medium Impact - Reduces the risk of misconfigurations that could weaken `peergos` security posture.
    *   **Unforeseen Security Risks in Peergos Integration:** Medium Impact - Helps uncover and mitigate less obvious security risks that might be missed by standard development practices.

*   **Currently Implemented:**
    *   Regular security audits and code reviews specifically focused on `peergos` integration are likely not performed. General code reviews might occur, but without a `peergos` security focus.

*   **Missing Implementation:**
    *   Scheduled security audits of `peergos` integration by security experts are likely not in place.
    *   Code reviews specifically targeting `peergos` interaction code for security vulnerabilities are probably not conducted.
    *   Security audits might not be specifically focused on the unique risks introduced by `peergos`.
    *   A formal process for addressing and remediating security findings from `peergos` integration audits is likely missing.


## Mitigation Strategy: [Monitor Peergos Project Security Posture](./mitigation_strategies/monitor_peergos_project_security_posture.md)

**Description:**
1.  **Step 1: Follow Peergos Security Channels:** Identify and follow official security communication channels for the `peergos` project. This might include security mailing lists, issue trackers with security labels, or dedicated security sections on the `peergos` website or documentation.
2.  **Step 2: Track Peergos Security Disclosures:** Actively track security disclosures and vulnerability reports related to `peergos`. Pay attention to the severity of reported vulnerabilities and the recommended mitigation steps.
3.  **Step 3: Participate in Peergos Security Community (If Possible):** If you have security expertise, consider participating in the `peergos` security community. This could involve reporting potential vulnerabilities, contributing to security discussions, or helping with security testing and code reviews within the `peergos` project (if welcomed by the project).
4.  **Step 4: Assess Impact of Peergos Security Issues on Your Application:** When security issues are reported in `peergos`, promptly assess the potential impact on your application. Determine if your application's usage patterns are affected by the vulnerability and prioritize mitigation accordingly.

*   **List of Threats Mitigated:**
    *   **Unawareness of Peergos Security Vulnerabilities (High Severity):**  Failing to be aware of and react to newly discovered security vulnerabilities in `peergos`, leaving your application vulnerable to exploitation.
    *   **Delayed Response to Peergos Security Issues (Medium Severity):**  Slow response to security disclosures, resulting in a prolonged window of vulnerability for your application.
    *   **Misunderstanding of Peergos Security Risks (Medium Severity):**  Lack of understanding of the specific security risks associated with `peergos`, leading to inadequate mitigation strategies.

*   **Impact:**
    *   **Unawareness of Peergos Security Vulnerabilities:** High Impact - Significantly reduces the risk of being caught off guard by known `peergos` vulnerabilities.
    *   **Delayed Response to Peergos Security Issues:** Medium Impact - Reduces the window of vulnerability by enabling faster reaction to security disclosures.
    *   **Misunderstanding of Peergos Security Risks:** Medium Impact - Improves overall security posture by fostering better understanding of `peergos`-specific risks and appropriate mitigations.

*   **Currently Implemented:**
    *   Proactive monitoring of `peergos` project security posture is likely not implemented. The team might rely on general software update practices, but not specifically track `peergos` security.

*   **Missing Implementation:**
    *   Identification and active following of `peergos` security communication channels are likely missing.
    *   A process for tracking `peergos` security disclosures and vulnerability reports is probably not in place.
    *   Active participation in the `peergos` security community (if applicable) is likely not occurring.
    *   A defined process for assessing the impact of `peergos` security issues on the application and prioritizing mitigation is probably missing.


## Mitigation Strategy: [Specific Peergos Feature Risks (Tailor to your usage - e.g., Computation, IAM)](./mitigation_strategies/specific_peergos_feature_risks__tailor_to_your_usage_-_e_g___computation__iam_.md)

**Description:**
1.  **Step 1: Identify Peergos Features in Use:**  List all specific features of `peergos` that your application utilizes (e.g., decentralized storage, content addressing, peer-to-peer networking, computation features, identity and access management features, etc.).
2.  **Step 2: Analyze Security Risks per Peergos Feature:** For each `peergos` feature in use, conduct a security risk analysis to identify potential threats and vulnerabilities specific to that feature. Refer to `peergos` documentation, security advisories, and community discussions for feature-specific security considerations.
3.  **Step 3: Implement Feature-Specific Mitigations:** Based on the risk analysis, implement mitigation strategies tailored to each `peergos` feature you are using. This might involve specific configuration settings, usage patterns, or application-level security controls to address feature-specific risks.
4.  **Step 4: Regularly Review Feature-Specific Security:**  Periodically review the security of your application's usage of each `peergos` feature. As `peergos` evolves and new security information becomes available, reassess feature-specific risks and update mitigation strategies as needed.

*   **List of Threats Mitigated:**
    *   **Feature-Specific Vulnerabilities in Peergos (Variable Severity):** Security vulnerabilities that might be present in specific features of `peergos` (e.g., vulnerabilities in computation execution, IAM implementation, or specific networking protocols). Severity depends on the feature and vulnerability.
    *   **Misuse or Insecure Configuration of Peergos Features (Variable Severity):**  Improper usage or insecure configuration of `peergos` features by your application, leading to security weaknesses. Severity depends on the feature and misconfiguration.
    *   **Unintended Security Consequences of Peergos Feature Interactions (Variable Severity):**  Unexpected security issues arising from the interaction of different `peergos` features or the combination of `peergos` features with your application logic. Severity depends on the specific interaction and consequences.

*   **Impact:**
    *   **Feature-Specific Vulnerabilities in Peergos:** Variable Impact - Impact depends on the severity of the vulnerability and the criticality of the affected feature for your application.
    *   **Misuse or Insecure Configuration of Peergos Features:** Variable Impact - Impact depends on the feature misconfigured and the potential consequences of the misconfiguration.
    *   **Unintended Security Consequences of Peergos Feature Interactions:** Variable Impact - Impact depends on the nature and severity of the unintended security consequences.

*   **Currently Implemented:**
    *   Feature-specific security analysis and mitigation strategies for `peergos` are likely not systematically implemented. Security considerations might be general rather than feature-focused.

*   **Missing Implementation:**
    *   A systematic identification of `peergos` features in use and feature-specific risk analysis is probably not conducted.
    *   Mitigation strategies tailored to specific `peergos` features are likely not implemented.
    *   Regular reviews of feature-specific security considerations for `peergos` are probably not performed.


