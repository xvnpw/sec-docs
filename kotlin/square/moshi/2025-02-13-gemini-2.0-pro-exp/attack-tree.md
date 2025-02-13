# Attack Tree Analysis for square/moshi

Objective: Execute Arbitrary Code OR Exfiltrate Sensitive Data via Moshi

## Attack Tree Visualization

```
                                      Attacker's Goal:
                      Execute Arbitrary Code OR Exfiltrate Sensitive Data via Moshi
                                                |
          -------------------------------------------------------------------------
          |
  **1.  Exploit Deserialization Vulnerabilities [HIGH]**
          |
  ---------------------------------
  |               |
1.1  Polymorphic  1.2  Custom
     Type         Adapters
     Confusion    Vulnerabilities
          |               |
  --------|--------       |--------
  |                       |
1.1.1                   1.2.1
[HIGH]                  [HIGH]
Craft                   Inject
JSON                    Code
with                    via
Known                   Custom
Gadget                  Adapter
Class                   Logic
```

## Attack Tree Path: [1. Exploit Deserialization Vulnerabilities [HIGH] (Critical Node)](./attack_tree_paths/1__exploit_deserialization_vulnerabilities__high___critical_node_.md)

*   **Description:** This is the most dangerous attack vector. Deserialization of untrusted data can lead to arbitrary code execution. Moshi, while safer than some other libraries, is still vulnerable if not used carefully, particularly with polymorphic types and custom adapters.
    *   **Likelihood:** High (Overall, considering sub-paths)
    *   **Impact:** High (Potential for complete system compromise)
    *   **Effort:** Medium (Requires crafting specific JSON and understanding of vulnerabilities)
    *   **Skill Level:** High (Requires in-depth knowledge of Java, serialization, and Moshi)
    *   **Detection Difficulty:** Medium (Sophisticated attacks can be difficult to detect)

## Attack Tree Path: [1.1 Polymorphic Type Confusion](./attack_tree_paths/1_1_polymorphic_type_confusion.md)

*   **Description:** Attackers exploit Moshi's handling of polymorphic types (where a single field can represent different classes) to force the instantiation of an unintended class.

## Attack Tree Path: [1.1.1 Craft JSON with Known Gadget Class [HIGH]](./attack_tree_paths/1_1_1_craft_json_with_known_gadget_class__high_.md)

*   **Description:** The attacker crafts a JSON payload that includes a type discriminator (or similar mechanism) that points to a known "gadget" class. A gadget class is a class present in the application's classpath that, when deserialized, performs actions that can be exploited by the attacker (e.g., executing system commands). This is a classic Java deserialization vulnerability, but Moshi's sealed class feature mitigates it significantly *if used*. Reflection-based polymorphism is more vulnerable.
            *   **Likelihood:** Medium (Requires a known gadget class on the classpath and the ability to control the type discriminator. Sealed classes, if used, significantly reduce this likelihood.)
            *   **Impact:** High (Arbitrary code execution, leading to full system compromise)
            *   **Effort:** Medium (Requires finding a suitable gadget class and crafting the malicious JSON)
            *   **Skill Level:** High (Requires deep understanding of Java serialization vulnerabilities, Moshi's internals, and the application's classpath)
            *   **Detection Difficulty:** Medium (Suspicious class instantiation *might* be logged, but sophisticated attackers can often bypass logging.  Requires advanced monitoring and anomaly detection.)

## Attack Tree Path: [1.2 Custom Adapters Vulnerabilities](./attack_tree_paths/1_2_custom_adapters_vulnerabilities.md)

*   **Description:** Moshi allows developers to write custom `JsonAdapter` classes to handle specific serialization/deserialization logic. These adapters are essentially custom code and can contain vulnerabilities.

## Attack Tree Path: [1.2.1 Inject Code via Custom Adapter Logic [HIGH]](./attack_tree_paths/1_2_1_inject_code_via_custom_adapter_logic__high_.md)

*   **Description:** The attacker crafts a JSON payload that, when processed by a vulnerable custom `JsonAdapter`, triggers the execution of malicious code embedded within the adapter's `fromJson()` method (or other methods involved in deserialization). This is a direct code injection vulnerability within the custom adapter.
            *   **Likelihood:** High (If custom adapters are present and not thoroughly vetted for security vulnerabilities, this is a very likely attack vector. Developers often make mistakes in custom code.)
            *   **Impact:** High (Arbitrary code execution within the context of the application, potentially leading to full system compromise)
            *   **Effort:** Medium (Requires understanding the custom adapter's code and crafting a malicious JSON payload that exploits the vulnerability)
            *   **Skill Level:** High (Requires strong understanding of Java, Moshi's adapter API, and secure coding practices to identify and exploit vulnerabilities in the custom adapter)
            *   **Detection Difficulty:** Medium (Code review *should* catch this, but runtime detection is difficult without specific monitoring of the adapter's behavior.  Static analysis tools can help.)

