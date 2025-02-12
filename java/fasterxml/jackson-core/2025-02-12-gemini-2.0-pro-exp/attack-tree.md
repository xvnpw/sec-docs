# Attack Tree Analysis for fasterxml/jackson-core

Objective: Execute Arbitrary Code OR Exfiltrate Sensitive Data via Jackson-core Vulnerabilities

## Attack Tree Visualization

                                      Attacker's Goal:
                      Execute Arbitrary Code OR Exfiltrate Sensitive Data
                                 via Jackson-core Vulnerabilities
                                                | [CN]
                      -------------------------------------------------
                      |
        1.  Polymorphic Deserialization Vulnerabilities [CN][HR]
                      |
        ------------------------------
        |
1.1 Gadget Chain  
    Exploitation [CN][HR]
        |
  -------------
  |
1.1.1
Known
Gadgets [HR]

## Attack Tree Path: [1. Polymorphic Deserialization Vulnerabilities [CN][HR]](./attack_tree_paths/1__polymorphic_deserialization_vulnerabilities__cn__hr_.md)

*   **Description:** This is the core vulnerability area. Jackson's ability to deserialize JSON into objects of varying types (polymorphism), controlled by type identifiers in the JSON (like `@type`), allows attackers to specify arbitrary classes to be instantiated. This is the foundation for most serious Jackson exploits.
*   **Why it's Critical [CN]:** It's the gateway to RCE. Without this, gadget chain exploitation is not possible.
*   **Why it's High-Risk [HR]:** If enabled without proper safeguards (whitelists), it's a relatively easy attack vector to exploit, especially with known gadgets.
*   **Attack Steps:**
    1.  Attacker identifies an endpoint that accepts JSON input and uses Jackson for deserialization.
    2.  Attacker determines if polymorphic deserialization is enabled (often by trial and error, sending different type identifiers).
    3.  Attacker crafts a malicious JSON payload containing a type identifier that points to a known gadget class.
    4.  Attacker sends the payload to the vulnerable endpoint.
    5.  Jackson deserializes the JSON, instantiating the gadget class.
    6.  The gadget's code executes, leading to RCE.
*   **Mitigations:**
    *   **Disable Polymorphic Deserialization:** The most effective mitigation. If you don't need to deserialize into different types based on the JSON, disable this feature entirely.
    *   **Use a Whitelist (Allowlist):** If polymorphic deserialization is *required*, strictly control which classes can be instantiated using a whitelist. This is far more secure than a blacklist.
    *   **Input Validation:** Validate the structure and content of the JSON *before* it reaches the deserialization process. This can help prevent unexpected type identifiers.
    *   **Regular Updates:** Keep Jackson and all dependencies up-to-date to benefit from security patches.

## Attack Tree Path: [1.1 Gadget Chain Exploitation [CN][HR]](./attack_tree_paths/1_1_gadget_chain_exploitation__cn__hr_.md)

*   **Description:** This is the mechanism by which RCE is achieved. A "gadget chain" is a sequence of classes that, when instantiated and their methods called in a specific order, perform unintended actions, ultimately leading to arbitrary code execution.
    *   **Why it's Critical [CN]:** It's the direct path to RCE.
    *   **Why it's High-Risk [HR]:** Exploits using known gadget chains are often publicly available, making this a relatively easy attack to execute if polymorphic deserialization is enabled.
    *   **Attack Steps:** (Same as 1. Polymorphic Deserialization, as this is the core mechanism)
    *   **Mitigations:** (Same as 1. Polymorphic Deserialization)

## Attack Tree Path: [1.1.1 Known Gadgets [HR]](./attack_tree_paths/1_1_1_known_gadgets__hr_.md)

*   **Description:** These are publicly documented classes (or sequences of classes) from commonly used libraries that, when deserialized, can lead to RCE. Security researchers and attackers actively search for these gadgets.
    *   **Why it's High-Risk [HR]:** Exploits are readily available, and the impact is very high (RCE).
    *   **Attack Steps:**
        1.  Attacker identifies a vulnerable endpoint (as described above).
        2.  Attacker selects a known gadget chain exploit (often from public databases or exploit frameworks).
        3.  Attacker crafts a JSON payload containing the necessary type identifiers and data to trigger the gadget chain.
        4.  Attacker sends the payload to the vulnerable endpoint.
        5.  Jackson deserializes the JSON, triggering the gadget chain and leading to RCE.
    *   **Mitigations:**
        *   **Disable Polymorphic Deserialization:** The primary mitigation.
        *   **Use a Whitelist:** If polymorphic deserialization is required, a whitelist prevents the instantiation of known gadget classes.
        *   **Regular Updates:** Updates often include blacklists of newly discovered gadgets, but this is a reactive measure and should not be relied upon as the sole defense.
        *   **Dependency Management:** Carefully review and manage project dependencies to minimize the inclusion of libraries with known vulnerabilities.

