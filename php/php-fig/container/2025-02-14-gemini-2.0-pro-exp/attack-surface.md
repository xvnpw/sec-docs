# Attack Surface Analysis for php-fig/container

## Attack Surface: [1. Malicious Service Injection](./attack_surfaces/1__malicious_service_injection.md)

*   **Description:** An attacker gains control over the container's configuration and replaces legitimate service definitions with malicious ones.
*   **Container Contribution:** The container is the *direct* mechanism by which these malicious services are instantiated and used by the application. It is the central point of control and execution for these injected services.
*   **Example:** An attacker modifies a configuration file to replace the `DatabaseConnection` service with a class that sends all database queries to an attacker-controlled server.
*   **Impact:** Complete application compromise, data theft, arbitrary code execution, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict File Permissions:** Protect container configuration files (and any data sources used to build the container) with the most restrictive file permissions possible. Only the web server user should have read access (and *no* write access after initial setup).
    *   **Configuration Validation:** Implement rigorous validation of all container configuration data. Use a schema validator if possible. Whitelist allowed class names and factory methods. Reject any configuration that uses dynamic code evaluation (e.g., `eval`).
    *   **Immutable Configuration:** After the application starts, prevent any further modification of the container configuration. Load the configuration into memory and prevent changes to the source files.
    *   **Configuration Signing:** Cryptographically sign the container configuration to detect any tampering. Verify the signature before loading the configuration.
    *   **Principle of Least Privilege (Application User):** Ensure the application runs under a user account with minimal privileges. This limits the damage an attacker can do even if they compromise the application.

## Attack Surface: [2. Overly Permissive Service Definitions (Unintentional)](./attack_surfaces/2__overly_permissive_service_definitions__unintentional_.md)

*   **Description:** Services are configured in a way that makes them vulnerable to injection attacks, even without malicious intent. This often involves passing unsanitized user input to service constructors or methods.
*   **Container Contribution:** The container *directly* facilitates the instantiation and wiring of these vulnerable services, making them accessible throughout the application. The container's configuration defines how these services are created and connected, thus directly contributing to the vulnerability if the configuration is flawed.
*   **Example:** A `Logger` service is configured to accept a file path as a constructor argument, and this path is taken directly from user input without validation, leading to a path traversal vulnerability. The container is responsible for creating this `Logger` instance with the attacker-controlled file path.
*   **Impact:** Varies depending on the service, but can include code injection, denial of service, information disclosure, or file system manipulation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation (within Services):** Each service *must* validate its own inputs, regardless of where they come from. Do not assume that data from the container is safe.
    *   **Type Hinting and Value Objects:** Use strict type hinting in service constructors and methods. Use value objects to encapsulate and validate data passed between services.
    *   **Principle of Least Privilege (Service Dependencies):** Design services to depend only on the specific data and other services they absolutely need. Avoid passing large, untyped objects.
    *   **Code Reviews:** Thoroughly review all service definitions and constructor logic for potential vulnerabilities.

## Attack Surface: [3. Service Alias Manipulation](./attack_surfaces/3__service_alias_manipulation.md)

*   **Description:** If the container supports service aliases, an attacker who can modify the alias definitions can redirect requests for legitimate services to malicious ones.
*   **Container Contribution:** The container's aliasing mechanism is the *direct* vector for this attack. The container itself handles the resolution of aliases to concrete service instances.
*   **Example:** An attacker changes the alias for "payment_processor" to point to a malicious class that steals credit card information. The container is responsible for resolving the "payment_processor" alias to the attacker's malicious class.
*   **Impact:** Similar to malicious service injection: data theft, arbitrary code execution, denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable or Restrict Aliasing:** If aliases are not strictly necessary, disable the feature entirely. If they are needed, restrict the ability to create or modify aliases after the container is built.
    *   **Alias Target Validation:** Ensure that aliases can only point to known, valid service identifiers. Implement a whitelist of allowed alias targets.
    *   **Auditing:** Log all alias creation and modification events.

