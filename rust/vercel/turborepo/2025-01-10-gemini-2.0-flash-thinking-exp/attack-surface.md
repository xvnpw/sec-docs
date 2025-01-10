# Attack Surface Analysis for vercel/turborepo

## Attack Surface: [Remote Cache Poisoning](./attack_surfaces/remote_cache_poisoning.md)

* **Description:** A malicious actor gains write access to the remote cache and injects compromised build artifacts.
    * **How Turborepo Contributes:** Turborepo's core functionality relies on caching build outputs remotely to speed up subsequent builds. If this remote cache is compromised, all users relying on it can receive malicious artifacts.
    * **Example:** An attacker compromises the credentials for the remote cache storage (e.g., AWS S3 bucket) and replaces a legitimate build output of a critical package with a version containing a backdoor. Developers subsequently building the application will pull this backdoored version from the cache.
    * **Impact:**  Widespread compromise of applications built using the poisoned cache, potentially leading to data breaches, unauthorized access, or system compromise.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:
        * Implement strong authentication and authorization mechanisms for accessing the remote cache (e.g., API keys, IAM roles).
        * Use secure communication protocols (HTTPS) for all interactions with the remote cache.
        * Implement integrity checks (e.g., checksums, signatures) for cached artifacts to detect tampering.
        * Regularly audit access logs for the remote cache.
        * Consider using a private and managed remote cache service with built-in security features.

## Attack Surface: [Remote Cache Snooping/Information Disclosure](./attack_surfaces/remote_cache_snoopinginformation_disclosure.md)

* **Description:** Unauthorized access to the remote cache allows attackers to view cached build outputs, potentially revealing sensitive information.
    * **How Turborepo Contributes:** Turborepo stores build outputs in the remote cache. If access controls are weak, attackers can potentially download these outputs.
    * **Example:** An attacker gains read access to the remote cache storage and downloads cached build artifacts containing environment variables with API keys or database credentials.
    * **Impact:** Exposure of sensitive information, potentially leading to unauthorized access to other systems or data.
    * **Risk Severity:** High
    * **Mitigation Strategies:
        * Implement strict access control policies for the remote cache, limiting read access to authorized users and systems only.
        * Avoid storing sensitive information directly in build outputs or environment variables that are cached.
        * Consider encrypting cached artifacts at rest.
        * Regularly review and update access control lists for the remote cache.

## Attack Surface: [Malicious Script Injection in `turbo.json`](./attack_surfaces/malicious_script_injection_in__turbo_json_.md)

* **Description:** An attacker gains write access to the repository and modifies the `turbo.json` configuration file to execute arbitrary commands during the build process.
    * **How Turborepo Contributes:** `turbo.json` defines the build pipeline and tasks, which are central to Turborepo's operation. Malicious modifications can directly lead to code execution within the Turborepo managed build process.
    * **Example:** An attacker adds a malicious script to a task definition in `turbo.json` that executes after a successful build. This script could exfiltrate data, install malware, or compromise the build environment.
    * **Impact:** Code execution on developer machines or build servers, potentially leading to data breaches, system compromise, or supply chain attacks.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:
        * Implement strict access control for modifying the repository and critical configuration files like `turbo.json`.
        * Enforce code review processes for all changes to `turbo.json`.
        * Use a version control system and track changes to `turbo.json`.
        * Consider using a configuration management system to manage and audit changes to build configurations.

