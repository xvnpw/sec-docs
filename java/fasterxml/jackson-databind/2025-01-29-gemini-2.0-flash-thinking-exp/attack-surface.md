# Attack Surface Analysis for fasterxml/jackson-databind

## Attack Surface: [Polymorphic Deserialization Exploitation](./attack_surfaces/polymorphic_deserialization_exploitation.md)

*   **Description:** Attackers control the class instantiated during deserialization by manipulating JSON type information, leading to arbitrary code execution.
*   **Jackson-databind Contribution:** `jackson-databind`'s polymorphic type handling (using `@type`, `@class`, `@javaType`) enables specifying class instantiation from JSON, which can be exploited if not secured.
*   **Example:** Sending JSON with `@type` pointing to a vulnerable class like `org.springframework.context.support.ClassPathXmlApplicationContext` and a malicious XML URL, resulting in Remote Code Execution (RCE).
*   **Impact:** Remote Code Execution (RCE), full system compromise.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Disable Default Typing:** Avoid `ObjectMapper.enableDefaultTyping()` unless absolutely necessary.
    *   **Implement Polymorphic Type Validators:** Use `PolymorphicTypeValidator` to strictly whitelist allowed classes for deserialization.
    *   **Minimize Polymorphism:** Reduce or eliminate the need for polymorphic deserialization in API design.

## Attack Surface: [Gadget Chain Exploitation](./attack_surfaces/gadget_chain_exploitation.md)

*   **Description:** Attackers leverage known vulnerabilities in classpath classes (gadget chains) through `jackson-databind`'s polymorphic deserialization to execute malicious code.
*   **Jackson-databind Contribution:** `jackson-databind` allows instantiation of arbitrary classes via polymorphic deserialization, enabling attackers to trigger gadget chains present in application dependencies.
*   **Example:** Using polymorphic deserialization to instantiate classes from vulnerable libraries like `commons-collections` to trigger known RCE gadget chains.
*   **Impact:** Remote Code Execution (RCE), potential for data breaches and system takeover.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Keep Jackson-databind Up-to-Date:** Regularly update `jackson-databind` to the latest patched version.
    *   **Dependency Management:** Minimize and audit application dependencies, removing vulnerable libraries.
    *   **Runtime Classpath Scanning:** Scan runtime classpath for known vulnerable libraries.
    *   **Polymorphic Type Validators (as in #1):** Restrict allowed classes for deserialization to limit gadget chain options.

## Attack Surface: [Unsafe Deserialization Features Enabled](./attack_surfaces/unsafe_deserialization_features_enabled.md)

*   **Description:** Enabling insecure `jackson-databind` features increases vulnerability to exploitation.
*   **Jackson-databind Contribution:** `jackson-databind` offers features that, if misused or enabled without caution, can create pathways for attacks.
*   **Example:** Using custom deserializers without proper input validation, which could lead to vulnerabilities if external data is processed unsafely.
*   **Impact:** High risk of deserialization vulnerabilities, potentially leading to RCE or data manipulation.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:** Only enable necessary `jackson-databind` features.
    *   **Secure Defaults:** Configure `jackson-databind` with secure settings, avoiding insecure defaults.
    *   **Code Review:** Carefully review `jackson-databind` configurations and custom deserializers for security implications.

