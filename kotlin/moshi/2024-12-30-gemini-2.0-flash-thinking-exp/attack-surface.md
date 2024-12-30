*   **Attack Surface:** Polymorphic Type Handling Vulnerabilities Leading to Code Injection or Information Disclosure
    *   **Description:** When using Moshi's polymorphic type adapter generation (e.g., with `@JsonClass(generateAdapter = true, generator = "sealed:type")`), if the "type" discriminator in the JSON is attacker-controlled, it could lead to the instantiation of unexpected and potentially malicious classes.
    *   **How Moshi Contributes to the Attack Surface:** Moshi's feature to deserialize into different concrete types based on a discriminator field makes the application vulnerable if the source of this discriminator is untrusted user input.
    *   **Example:** An attacker crafts a JSON payload with a "type" field pointing to a class that has dangerous methods or can be used to access sensitive data. Upon deserialization, Moshi instantiates this class, and the application might unknowingly execute malicious code or expose information.
    *   **Impact:** Remote code execution (if a malicious class is instantiated and its methods are invoked), information disclosure (if a class exposing sensitive data is instantiated), and potential for other arbitrary actions depending on the capabilities of the instantiated class.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Whitelist Allowed Types:  Strictly define and enforce a whitelist of allowed types for polymorphic deserialization. Do not rely solely on the "type" field from the input.
        *   Sanitize or Ignore Discriminator: If the discriminator comes from an untrusted source, sanitize it thoroughly or ignore it and use alternative methods to determine the target type.
        *   Avoid Deserializing Directly into Potentially Dangerous Classes: Design your data model to avoid deserializing directly into classes that have significant side effects or access sensitive resources. Use intermediate, safe data transfer objects (DTOs).

*   **Attack Surface:** Information Disclosure through Unintended Serialization
    *   **Description:** Sensitive information within objects might be unintentionally serialized and exposed if not properly handled.
    *   **How Moshi Contributes to the Attack Surface:** Moshi, by default, serializes all public and non-transient fields of an object. If developers are not careful about which fields are exposed, sensitive data can be leaked.
    *   **Example:** An object containing user passwords or API keys is serialized and sent in a response or logged without explicitly excluding these sensitive fields using annotations like `@Transient` or `@JsonIgnore`.
    *   **Impact:** Exposure of sensitive data, potentially leading to account compromise, unauthorized access, or other security breaches.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Explicitly Exclude Sensitive Fields: Use annotations like `@Transient` or `@JsonIgnore` to prevent sensitive fields from being serialized.
        *   Use DTOs for Serialization: Create specific Data Transfer Objects (DTOs) that only contain the data intended for serialization, avoiding the risk of accidentally including sensitive information from domain objects.
        *   Review Serialization Logic: Regularly review the classes being serialized to ensure no sensitive information is inadvertently being exposed.