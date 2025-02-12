# Attack Surface Analysis for fasterxml/jackson-core

## Attack Surface: [Unsafe Deserialization of Untrusted Data (Polymorphic Typing)](./attack_surfaces/unsafe_deserialization_of_untrusted_data__polymorphic_typing_.md)

*   **Description:**  Jackson's polymorphic type handling, specifically when using features like `@JsonTypeInfo` or default typing with untrusted input, is the most significant vulnerability.  This allows attackers to specify arbitrary classes to be instantiated during deserialization.  If a malicious class with harmful side effects (a "gadget") is present on the classpath, it can be instantiated and its code executed. This is often referred to as "deserialization of untrusted data" or "unsafe deserialization".
*   **How Jackson-core contributes:**  `jackson-databind` relies on `jackson-core` for the underlying parsing and object creation.  `jackson-core` provides the low-level mechanisms for reading and writing JSON, but `jackson-databind`'s handling of type information and object instantiation is where the vulnerability lies.  The core library provides the tools, but the databind module uses them in a way that can be exploited.
*   **Example:**  An attacker could send a JSON payload like `{"@class": "com.example.malicious.ExploitClass", "data": "..."}`. If `com.example.malicious.ExploitClass` exists and has harmful code in its constructor or other methods called during deserialization, it will be executed.
*   **Impact:**  Remote Code Execution (RCE), complete system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Default Typing:**  Never use `ObjectMapper.enableDefaultTyping()` or similar methods that enable polymorphic deserialization without restrictions.
    *   **Strict Whitelisting:**  Use `@JsonTypeInfo` with a tightly controlled whitelist of allowed classes using `@JsonSubTypes`.  Only include classes that are absolutely necessary and have been thoroughly vetted.  Prefer `@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "@class")` and `@JsonSubTypes({@JsonSubTypes.Type(value = SafeClass1.class, name = "Safe1"), ...})`.  Avoid using `JsonTypeInfo.Id.CLASS` or `JsonTypeInfo.Id.MINIMAL_CLASS` with untrusted input.
    *   **Use a Safe Default Typing Implementation:** If default typing is absolutely required, use a custom `TypeResolverBuilder` or `TypeIdResolver` that implements strict validation and filtering of allowed types.  Consider using a library like `jackson-databind-blacklist` (though keep in mind that blacklists are inherently less secure than whitelists).
    *   **Input Validation:**  Implement robust input validation *before* deserialization to reject any JSON containing suspicious class names or structures.  This is a defense-in-depth measure.
    *   **Least Privilege:** Run the application with the lowest possible privileges to limit the damage an attacker can do if they achieve code execution.
    *   **Regular Updates:** Keep Jackson libraries (core, databind, annotations) up-to-date to benefit from the latest security patches and fixes for known vulnerabilities.
    *   **Consider Alternatives:** If possible, explore alternative serialization formats or libraries that are less susceptible to deserialization vulnerabilities (e.g., Protocol Buffers, Avro, or even simpler formats like CSV if appropriate).

## Attack Surface: [XML External Entity (XXE) Injection (via `jackson-dataformat-xml`)](./attack_surfaces/xml_external_entity__xxe__injection__via__jackson-dataformat-xml__.md)

*   **Description:** If using the `jackson-dataformat-xml` module, attackers can craft malicious XML input that includes external entity references.  This can lead to information disclosure (reading local files), server-side request forgery (SSRF), or denial-of-service (DoS) attacks.
*   **How jackson-core contributes:** While `jackson-dataformat-xml` handles the XML-specific aspects, `jackson-core` is still involved in the underlying parsing and processing of the data stream. The vulnerability stems from how external entities are resolved.
*   **Example:** An attacker might include a DTD with an external entity reference: `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> <foo>&xxe;</foo>`.
*   **Impact:**  Information disclosure (reading arbitrary files), SSRF (making requests to internal or external systems), DoS.
*   **Risk Severity:** High (potentially Critical, depending on the accessible resources)
*   **Mitigation Strategies:**
    *   **Disable External Entity Resolution:**  The most effective mitigation is to completely disable the processing of external entities. This can often be done through configuration options on the `XMLInputFactory` used by Jackson.  For example:
        ```java
        XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // Disable DTDs entirely
        xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false); // Disable external entities
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // Disable DTDs
        xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false); // Disable external entities
        xmlInputFactory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
        xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
        xmlInputFactory.setXMLResolver(new XMLResolver() {
            @Override
            public Object resolveEntity(String publicID, String systemID, String baseURI, String namespace) {
                return null; // Or throw an exception
            }
        });
        ```
    *   **Use a Safe XML Parser:** If you must process external entities, use a well-vetted and securely configured XML parser.
    *   **Input Validation:**  Sanitize and validate all XML input before processing it with Jackson.

## Attack Surface: [Large Number Handling (DoS)](./attack_surfaces/large_number_handling__dos_.md)

*   **Description:**  Extremely large numbers (either integers or floating-point) in JSON input can cause excessive memory allocation or CPU consumption, leading to a denial-of-service.
*   **How jackson-core contributes:** `jackson-core` is responsible for parsing numeric values from the JSON input stream.  If the numbers are excessively large, it can lead to resource exhaustion.
*   **Example:**  A JSON payload containing a number like `1e9999999999999999999` could cause problems.
*   **Impact:**  Denial of Service (DoS) due to excessive memory or CPU usage.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit Input Size:**  Enforce a reasonable maximum size limit on the entire JSON input.
    *   **Use Streaming API:** For very large JSON documents, consider using Jackson's streaming API (`JsonParser`) to process the input incrementally, rather than loading the entire document into memory at once.
    *   **Configure Number Limits:**  Explore Jackson's configuration options to limit the size or precision of numbers that can be parsed.  This might involve custom `JsonFactory` configurations.
    * **Input Validation:** Validate the size and format of numeric values before parsing them.

## Attack Surface: [Deeply Nested JSON (Stack Overflow)](./attack_surfaces/deeply_nested_json__stack_overflow_.md)

*   **Description:**  JSON with excessively deep nesting can cause a stack overflow error, leading to application crashes.
*   **How jackson-core contributes:**  Jackson's recursive descent parser can be vulnerable to stack overflow errors if the JSON structure is too deeply nested.
*   **Example:**  A JSON object with many nested objects: `{"a":{"b":{"c":{"d":{"e": ... }}}}`.
*   **Impact:**  Denial of Service (DoS) due to application crash.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit Nesting Depth:**  Configure the `JsonParser` to limit the maximum nesting depth.  This can often be done through `JsonFactory` settings or by using a custom `JsonFactory`.
    *   **Input Validation:**  Validate the structure of the JSON input to prevent excessively deep nesting.

## Attack Surface: [YAML Deserialization (if using `jackson-dataformat-yaml`)](./attack_surfaces/yaml_deserialization__if_using__jackson-dataformat-yaml__.md)

*   **Description:**  Similar to JSON, YAML deserialization can be vulnerable to code injection if untrusted YAML is processed, especially with custom constructors or tags.
*   **How jackson-core contributes:** While `jackson-dataformat-yaml` handles the YAML specifics, it relies on `jackson-core` for the underlying parsing and object creation.
*   **Example:**  YAML input that uses a custom tag to instantiate a malicious class.
*   **Impact:**  Remote Code Execution (RCE), similar to the JSON polymorphic typing vulnerability.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Use Safe YAML Loading:**  Use `YAMLFactory.builder().disable(YAMLFeature.FAIL_ON_UNRESOLVED_OBJECT_IDS).build()` to create a `YAMLFactory` that is less susceptible to certain types of attacks.
    *   **Avoid Untrusted YAML:**  Do not deserialize YAML from untrusted sources unless absolutely necessary.
    *   **Whitelist Allowed Types:**  If you must deserialize YAML with custom types, use a whitelist to restrict the allowed classes.
    *   **Regular Updates:** Keep the `jackson-dataformat-yaml` library up-to-date.

## Attack Surface: [Resource Exhaustion via Malformed Input](./attack_surfaces/resource_exhaustion_via_malformed_input.md)

*   **Description:**  Specially crafted, malformed JSON input (e.g., extremely long strings, deeply nested arrays without closing brackets) can cause excessive resource consumption (CPU, memory) during parsing, leading to a denial-of-service.
*   **How jackson-core contributes:** The core parsing logic in `jackson-core` is responsible for handling the input stream.  Malformed input can trigger excessive looping or memory allocation.
*   **Example:**  A JSON string with a very long sequence of opening brackets without corresponding closing brackets, or a string with an extremely large number of characters.
*   **Impact:** Denial of Service (DoS).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:**  Implement strict input validation to reject excessively long strings, deeply nested structures, or other malformed input *before* passing it to Jackson.
    *   **Timeouts:**  Set reasonable timeouts for parsing operations to prevent the parser from getting stuck indefinitely.
    *   **Resource Limits:**  Configure resource limits (e.g., memory limits) for the application to prevent it from consuming all available resources.
    *   **Streaming API:** Use the streaming API (`JsonParser`) for large inputs to process the data in chunks, reducing memory consumption.

