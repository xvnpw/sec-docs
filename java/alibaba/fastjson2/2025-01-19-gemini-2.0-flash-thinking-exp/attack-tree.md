# Attack Tree Analysis for alibaba/fastjson2

Objective: Achieve Remote Code Execution (RCE) or exfiltrate sensitive data from the application by exploiting vulnerabilities within the Fastjson2 library.

## Attack Tree Visualization

```
* Compromise Application via Fastjson2
    * *** Exploit Deserialization Vulnerabilities ***
        * [CRITICAL] Exploit AutoType Feature
            * *** Force Deserialization of Malicious Classes (JNDI Injection) ***
                * Send JSON Payload with JNDI Lookup
                    * Craft JSON with "@type" pointing to a JNDI-enabled class (e.g., JdbcRowSetImpl)
                    * Include "dataSourceName" or "rmiURL" pointing to attacker-controlled server
                    * [CRITICAL] Application attempts to deserialize and perform JNDI lookup, fetching malicious code
            * Force Deserialization of Malicious Classes (Gadget Chains)
                * Application deserializes the object, leading to code execution [CRITICAL]
            * *** Exploit Type Confusion Vulnerabilities ***
                * [CRITICAL] Bypass AutoType Restrictions
                    * Application attempts to deserialize the bypassed class, leading to exploitation [CRITICAL]
        * *** Exploit Known Deserialization Bugs in Fastjson2 ***
            * [CRITICAL] Identify publicly disclosed deserialization vulnerabilities (CVEs)
            * Application processes the malicious JSON, leading to exploitation [CRITICAL]
```


## Attack Tree Path: [Exploit Deserialization Vulnerabilities](./attack_tree_paths/exploit_deserialization_vulnerabilities.md)

This overarching category represents a significant threat due to Fastjson2's handling of object deserialization. Attackers can craft malicious JSON payloads that, when processed by the application, lead to the instantiation of unintended and potentially dangerous classes.

## Attack Tree Path: [[CRITICAL] Exploit AutoType Feature](./attack_tree_paths/_critical__exploit_autotype_feature.md)

The `autoType` feature in Fastjson2 automatically attempts to deserialize JSON into specific Java classes based on the `@type` field in the JSON. This feature, while intended for convenience, allows attackers to control which classes are instantiated, opening the door for various exploitation techniques.

## Attack Tree Path: [Force Deserialization of Malicious Classes (JNDI Injection)](./attack_tree_paths/force_deserialization_of_malicious_classes__jndi_injection_.md)

**Attack Vector:** Attackers leverage the `autoType` feature to force the deserialization of classes that can perform Java Naming and Directory Interface (JNDI) lookups.

**How it Works:**

*   The attacker crafts a JSON payload with the `@type` field set to a class like `com.sun.rowset.JdbcRowSetImpl`.
*   The payload includes properties like `dataSourceName` or `rmiURL` pointing to a malicious server controlled by the attacker.
*   When Fastjson2 deserializes this object, it attempts to connect to the attacker's server via JNDI/RMI.
*   The attacker's server provides a malicious Java object, which is then loaded and executed by the application, leading to Remote Code Execution.
*   **[CRITICAL] Application attempts to deserialize and perform JNDI lookup, fetching malicious code:** This specific node represents the critical point where the application fetches and executes the attacker's malicious code.

## Attack Tree Path: [Force Deserialization of Malicious Classes (Gadget Chains)](./attack_tree_paths/force_deserialization_of_malicious_classes__gadget_chains_.md)

**Attack Vector:** Attackers exploit the `autoType` feature to instantiate a chain of existing classes (gadget chain) within the application's classpath. These classes, when their methods are invoked in a specific sequence, can lead to arbitrary code execution.

**How it Works:**

*   The attacker needs to identify a suitable gadget chain within the application's dependencies. This requires significant reverse engineering.
*   The attacker crafts a JSON payload with the `@type` field pointing to the entry point of the gadget chain.
*   The payload includes parameters that, when deserialized, trigger the chain of method calls leading to code execution.
*   **[CRITICAL] Application deserializes the object, leading to code execution:** This node represents the critical point where the carefully crafted chain of method calls results in the execution of arbitrary code.

## Attack Tree Path: [Exploit Type Confusion Vulnerabilities](./attack_tree_paths/exploit_type_confusion_vulnerabilities.md)

**Attack Vector:** Attackers attempt to confuse Fastjson2's type handling by providing JSON payloads where the declared type in `@type` doesn't match the actual data structure. This can lead to unexpected behavior or vulnerabilities.

## Attack Tree Path: [[CRITICAL] Bypass AutoType Restrictions](./attack_tree_paths/_critical__bypass_autotype_restrictions.md)

**Attack Vector:** Attackers identify and exploit weaknesses in Fastjson2's `autoType` filtering mechanisms to bypass intended restrictions.

**How it Works:**

*   Attackers research known bypass techniques, which might involve specific character sequences, alternative class names, or other methods to circumvent the filtering logic.
*   They craft JSON payloads using these bypass techniques to instantiate classes that would normally be blocked by the `autoType` filter.
*   **[CRITICAL] Application attempts to deserialize the bypassed class, leading to exploitation:** This node represents the critical point where the bypassed class is instantiated, allowing for further exploitation, often leading to Remote Code Execution.

## Attack Tree Path: [Exploit Known Deserialization Bugs in Fastjson2](./attack_tree_paths/exploit_known_deserialization_bugs_in_fastjson2.md)

**Attack Vector:** Attackers exploit publicly disclosed deserialization vulnerabilities (identified by CVEs) within specific versions of Fastjson2.

**How it Works:**

*   Attackers identify a relevant CVE affecting the application's version of Fastjson2.
*   They craft specific JSON payloads designed to trigger the vulnerability described in the CVE. These payloads often exploit specific weaknesses in Fastjson2's deserialization process for certain classes or data structures.
*   **[CRITICAL] Identify publicly disclosed deserialization vulnerabilities (CVEs):** This node represents the crucial step for the attacker to find a known weakness to exploit.
*   **[CRITICAL] Application processes the malicious JSON, leading to exploitation:** This node represents the critical point where the application processes the CVE-specific payload, resulting in the exploitation, which can range from Remote Code Execution to Denial of Service or Information Disclosure, depending on the specific vulnerability.

