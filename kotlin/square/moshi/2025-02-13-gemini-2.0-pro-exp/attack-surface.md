# Attack Surface Analysis for square/moshi

## Attack Surface: [Unsafe Polymorphic Deserialization](./attack_surfaces/unsafe_polymorphic_deserialization.md)

**Description:** Deserializing data where the concrete type is determined by a field in the JSON (e.g., `@type`), allowing an attacker to specify an arbitrary class to instantiate.
    *   **How Moshi Contributes:** Moshi's `PolymorphicJsonAdapterFactory` directly enables this functionality.  If misused (without a strict whitelist), it's the *direct* mechanism of the attack.
    *   **Example:** An API expects a `PaymentProcessor` interface. An attacker sends `{"@type": "com.example.MaliciousProcessor", "details": "..."}`. If `MaliciousProcessor` is on the classpath and not whitelisted, Moshi instantiates it, potentially executing malicious code.
    *   **Impact:** Remote Code Execution (RCE), arbitrary object instantiation, leading to a wide range of severe consequences.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Whitelisting:** Use `PolymorphicJsonAdapterFactory` with a *strictly defined and rigorously enforced* whitelist of allowed subtypes. Reject *any* JSON with an unknown or unexpected type identifier.  This is the primary defense.
        *   **Avoid Polymorphism When Unnecessary:** If the set of possible types is small and known in advance, use separate, concrete type adapters instead of polymorphic deserialization.
        *   **Thorough Code Review:** Carefully review all uses of `PolymorphicJsonAdapterFactory` to ensure the whitelist is comprehensive, correctly implemented, and cannot be bypassed.

## Attack Surface: [Overly Permissive Custom JsonAdapters](./attack_surfaces/overly_permissive_custom_jsonadapters.md)

**Description:** Custom `JsonAdapter` implementations that fail to properly validate input, or that instantiate objects or perform actions based on untrusted data without sufficient security checks.
    *   **How Moshi Contributes:** Moshi provides the `JsonAdapter` API, allowing developers to create custom serialization/deserialization logic.  This is a *direct* contribution; the vulnerability exists *within* the custom adapter code.
    *   **Example:** A custom adapter for a `FileOperation` class might accept a `filePath` from the JSON and directly use it in a file system operation without validating it. An attacker could provide a path like `/etc/passwd` to read sensitive system files, or `../../malicious.sh` to potentially execute a script.
    *   **Impact:** Highly variable, depending on the adapter's logic. Can range from information disclosure to RCE, depending on what the adapter does with the untrusted input and what resources it interacts with.
    *   **Risk Severity:** High to Critical (severity depends directly on the adapter's functionality)
    *   **Mitigation Strategies:**
        *   **Rigorous Input Validation:** Thoroughly validate *all* input within the `fromJson` method of *every* custom adapter. Use whitelisting, regular expressions, length checks, and any other relevant validation techniques.  Assume all input is malicious.
        *   **Avoid Unsafe Reflection:** Do *not* use reflection to instantiate arbitrary types or call methods based on untrusted input within the adapter.  This is a common source of vulnerabilities.
        *   **Principle of Least Privilege:** Ensure the adapter (and the objects it creates) only have the *minimum* necessary permissions to perform their intended function.
        *   **Prefer Generated Adapters:** Whenever possible, use `@JsonClass(generateAdapter = true)` and let Moshi generate the adapter. While you should still review the generated code, it's generally much safer than manually written adapters, as it avoids common pitfalls.
        * **Sanitize and Escape:** If the deserialized data from custom adapter will be used in any other context (SQL queries, HTML, etc.), make sure to properly sanitize and escape it.

