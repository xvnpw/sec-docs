# Attack Surface Analysis for automapper/automapper

## Attack Surface: [Accidental Mapping of Sensitive Data](./attack_surfaces/accidental_mapping_of_sensitive_data.md)

*   **Description:**  Incorrect or overly permissive mapping configurations unintentionally copy sensitive data from a source object to a destination object where it shouldn't be.
    *   **How AutoMapper Contributes to the Attack Surface:**  AutoMapper's flexibility in mapping properties, especially with automatic mapping conventions, can lead to the accidental inclusion of sensitive fields if not configured carefully.
    *   **Example:** Mapping a `User` entity with properties like `PasswordHash` or `SocialSecurityNumber` to a `UserDto` intended for public display, without explicitly ignoring these sensitive properties in the mapping configuration.
    *   **Impact:** Confidentiality breach, unauthorized access to sensitive information, potential compliance violations.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Principle of Least Privilege in Mapping:** Explicitly define the properties to be mapped. Avoid relying solely on automatic mapping conventions, especially for objects containing sensitive data.
        *   **Explicitly Ignore Sensitive Properties:** Use AutoMapper's `Ignore()` functionality to explicitly exclude sensitive properties from being mapped.
        *   **Code Reviews:** Conduct thorough code reviews of mapping configurations to identify potential leaks of sensitive information.
        *   **Static Analysis Tools:** Utilize static analysis tools that can detect potential over-mapping or exposure of sensitive data.

## Attack Surface: [Code Injection through Custom Resolvers/Converters](./attack_surfaces/code_injection_through_custom_resolversconverters.md)

*   **Description:**  Malicious input can be injected into custom resolvers or type converters, leading to the execution of arbitrary code on the server.
    *   **How AutoMapper Contributes to the Attack Surface:** AutoMapper allows developers to define custom logic for property mapping through resolvers and converters. If these components process user-controlled input without proper sanitization, they become potential injection points.
    *   **Example:** A custom resolver that dynamically constructs a database query based on a string property from the source object, without proper input validation. An attacker could manipulate this string to inject malicious SQL.
    *   **Impact:**  Complete system compromise, data breach, denial of service, arbitrary code execution.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Validation and Sanitization:**  Thoroughly validate and sanitize any user-controlled input before using it within custom resolvers or converters.
        *   **Avoid Dynamic Code Execution:**  Minimize or eliminate the need for dynamic code execution within resolvers and converters. If necessary, carefully sandbox or restrict the execution environment.
        *   **Secure Coding Practices:** Follow secure coding practices when implementing custom resolvers and converters, including avoiding string concatenation for building commands or queries.
        *   **Principle of Least Privilege for Resolvers/Converters:** Ensure that resolvers and converters have only the necessary permissions to perform their intended tasks.

