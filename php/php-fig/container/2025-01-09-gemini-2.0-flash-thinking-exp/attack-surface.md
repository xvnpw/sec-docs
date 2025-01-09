# Attack Surface Analysis for php-fig/container

## Attack Surface: [Arbitrary Class Instantiation via Configuration](./attack_surfaces/arbitrary_class_instantiation_via_configuration.md)

**Description:** The container allows defining services by specifying class names in the configuration. If this configuration is influenced by untrusted input, an attacker can force the instantiation of arbitrary classes, including those with vulnerabilities or that can be abused for malicious purposes.

**How Container Directly Involved:** The container's core functionality of mapping configuration keys to class instantiation directly enables this attack vector.

**Example:** An attacker modifies a configuration file (if accessible) or influences a configuration value read from an environment variable to define a service with the class `SystemCommandExecutor` (a hypothetical class allowing system command execution). The application then unknowingly instantiates and potentially uses this malicious service *because the container is instructed to do so via the configuration*.

**Impact:**  Remote Code Execution (RCE), privilege escalation, denial of service.

**Risk Severity: Critical**

**Mitigation Strategies:**
* **Secure Configuration Sources:** Ensure container configurations are loaded from trusted sources with strict access controls.
* **Configuration Validation:** Implement strict validation of class names specified in the configuration, potentially using a whitelist of allowed classes.
* **Avoid Dynamic Configuration:** Minimize or eliminate the ability to dynamically alter container configuration based on external input.

## Attack Surface: [Code Injection via Factory/Closure Definitions](./attack_surfaces/code_injection_via_factoryclosure_definitions.md)

**Description:** The container allows defining services using factories or closures. If the code within these factories or closures is dynamically generated based on untrusted input, it can lead to code injection vulnerabilities.

**How Container Directly Involved:** The container's feature of allowing arbitrary PHP code execution through factory functions or closures for service instantiation is the direct mechanism exploited.

**Example:** A factory function for a logging service uses a user-provided log file path without proper sanitization. An attacker could inject malicious PHP code into the file path, which is then executed *when the container invokes the factory to create the service*.

**Impact:** Remote Code Execution (RCE), information disclosure, data manipulation.

**Risk Severity: Critical**

**Mitigation Strategies:**
* **Avoid Dynamic Code Generation:** Refrain from generating factory or closure code based on untrusted input.
* **Input Sanitization:** Thoroughly sanitize any external input used within factory or closure logic.
* **Code Reviews:** Carefully review all factory and closure definitions for potential code injection vulnerabilities.

## Attack Surface: [Abuse of Dependency Injection through Public Setters/Properties](./attack_surfaces/abuse_of_dependency_injection_through_public_settersproperties.md)

**Description:** If services have publicly accessible setters or properties that are used for dependency injection, an attacker might be able to manipulate the state of these services by directly setting these values if they gain access to the service instance.

**How Container Directly Involved:** The container creates and manages the lifecycle of these service instances. While the vulnerability lies in the service's design, the container's role in instantiating and potentially making these services accessible contributes to the attack surface.

**Example:** A database connection service has a public `setCredentials()` method. If an attacker can obtain a reference to this service instance *managed by the container*, they could potentially change the database credentials.

**Impact:** Data breach, unauthorized access, data manipulation.

**Risk Severity: High**

**Mitigation Strategies:**
* **Immutable Services:** Design services to be as immutable as possible after instantiation.
* **Private or Protected Setters:** Avoid public setters for dependencies. Use constructor injection or private/protected setters with controlled access.
* **Secure Service Access:** Limit how and where service instances can be accessed within the application.

