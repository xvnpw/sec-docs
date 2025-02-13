# Threat Model Analysis for acra/acra

## Threat: [Master Key Compromise via File System Access](./threats/master_key_compromise_via_file_system_access.md)

*   **Threat:** Master Key Compromise via File System Access

    *   **Description:** An attacker gains unauthorized read access to the server's file system where Acra's master keys are stored (e.g., through a compromised service account, a vulnerability in another application, or physical access). The attacker copies the master key files.
    *   **Impact:** Complete data compromise. All data encrypted with Acra can be decrypted by the attacker.
    *   **Affected Component:** `Key Storage` (wherever the master keys are stored, typically files or a KMS).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Store master keys in a Hardware Security Module (HSM).
        *   Use a dedicated Key Management Service (KMS) like AWS KMS, Azure Key Vault, or Google Cloud KMS.
        *   Implement strict file system permissions and access controls (least privilege).
        *   Use a separate, isolated server for key management (key server).
        *   Implement file integrity monitoring (FIM) to detect unauthorized access to key files.
        *   Regularly rotate master keys.

## Threat: [Client Keypair Compromise via Application Vulnerability (If Acra Keys are Stored In-App)](./threats/client_keypair_compromise_via_application_vulnerability__if_acra_keys_are_stored_in-app_.md)

*   **Threat:** Client Keypair Compromise via Application Vulnerability (If Acra Keys are Stored In-App)

    *   **Description:**  *If* the application stores Acra client keypairs directly within its own codebase or configuration (which is *not* recommended), an attacker exploits a vulnerability in the application (e.g., remote code execution) to gain access to the client-side keypair.  This threat is *only* relevant if the application is directly managing Acra keys, rather than delegating to a separate secrets management system.
    *   **Impact:** The attacker can decrypt data associated with that specific client keypair. Impact is limited to the data accessible to that client.
    *   **Affected Component:** `Client-side Key Storage` (within the application, if applicable).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strongly Recommended:** Do *not* store Acra keys directly within the application. Use a dedicated secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager, environment variables).
        *   If keys *must* be stored in the application (strongly discouraged), implement strong encryption of the key storage itself.
        *   Regularly conduct security assessments and penetration testing of the application.
        *   Use short-lived keypairs and rotate them frequently.

## Threat: [Configuration File Disclosure via Directory Traversal (If Config Contains Key Paths)](./threats/configuration_file_disclosure_via_directory_traversal__if_config_contains_key_paths_.md)

*   **Threat:** Configuration File Disclosure via Directory Traversal (If Config Contains Key Paths)

    *   **Description:** An attacker exploits a directory traversal vulnerability in a web server or application component to read Acra's configuration file.  This is *most* critical if the configuration file contains *paths* to key files (rather than using a KMS).
    *   **Impact:** The attacker gains access to sensitive information, including database credentials and *potentially key locations*, enabling further attacks.
    *   **Affected Component:** `AcraServer/AcraTranslator Configuration` (the configuration file itself).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strict file system permissions on the configuration file.
        *   **Best Practice:** Avoid storing key paths directly in the configuration file. Use environment variables or a secrets management solution, or a KMS.
        *   Sanitize all user-supplied input to prevent directory traversal attacks.
        *   Regularly audit configuration files for sensitive information.

## Threat: [Denial of Service (DoS) against AcraTranslator](./threats/denial_of_service__dos__against_acratranslator.md)

*   **Threat:** Denial of Service (DoS) against AcraTranslator

    *   **Description:** An attacker floods AcraTranslator with a large number of requests, overwhelming its resources and making it unavailable to legitimate clients.
    *   **Impact:** The application becomes unable to communicate with the database, resulting in service disruption.
    *   **Affected Component:** `AcraTranslator` (the proxy component).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement rate limiting on incoming requests to AcraTranslator.
        *   Deploy AcraTranslator behind a load balancer to distribute traffic across multiple instances.
        *   Use a Web Application Firewall (WAF) to filter malicious traffic.
        *   Monitor AcraTranslator's resource usage and performance.

## Threat: [Supply Chain Attack on Acra Dependencies](./threats/supply_chain_attack_on_acra_dependencies.md)

*   **Threat:** Supply Chain Attack on Acra Dependencies

    *   **Description:** An attacker compromises a library or dependency used by Acra. The compromised dependency contains malicious code that steals keys, decrypts data, or otherwise compromises Acra's security.
    *   **Impact:** Complete compromise of Acra and the data it protects.
    *   **Affected Component:** `AcraServer/AcraTranslator` (any component that uses the compromised dependency).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use a software bill of materials (SBOM) to track dependencies.
        *   Regularly update dependencies to the latest secure versions.
        *   Use dependency scanning tools to identify known vulnerabilities in dependencies.
        *   Consider using a private package repository to control the dependencies used.
        *   Implement code signing and verification for Acra and its dependencies.

## Threat: [Memory Dump Exposing Decrypted Data (AcraServer/Translator)](./threats/memory_dump_exposing_decrypted_data__acraservertranslator_.md)

*   **Threat:** Memory Dump Exposing Decrypted Data (AcraServer/Translator)

    *   **Description:** An attacker gains access to a memory dump of the *AcraServer or AcraTranslator* process (e.g., through a core dump or a vulnerability that allows reading process memory). The memory dump contains decrypted data or keys. This is distinct from a memory dump of the *application* process.
    *   **Impact:** Exposure of decrypted data and potentially keys.
    *   **Affected Component:** `AcraServer/AcraTranslator` (the process memory).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Minimize the amount of time that decrypted data and keys are held in memory by AcraServer/Translator.
        *   Configure the operating system to prevent core dumps or to encrypt them.
        *   Use memory-safe programming languages and techniques where possible.
        *   Regularly patch the operating system and Acra to address vulnerabilities that could allow memory access.

