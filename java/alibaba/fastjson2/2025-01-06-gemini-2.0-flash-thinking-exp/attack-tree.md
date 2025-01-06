# Attack Tree Analysis for alibaba/fastjson2

Objective: Compromise Application Using Fastjson2 Vulnerabilities

## Attack Tree Visualization

```
Compromise Application Using Fastjson2
*   OR
    *   **Exploit Deserialization Vulnerabilities**
        *   OR
            *   ***Exploit autoType Bypass***
                *   AND
                    *   **Identify a gadget chain in the classpath**
                    *   **Craft a malicious JSON payload with specific class names**
                *   **Consequence: Remote Code Execution**
        *   **Default `autoType` Enabled**
            *   **Consequence:  Direct path to Deserialization Vulnerabilities (see above)**
```


## Attack Tree Path: [Identify a gadget chain in the classpath](./attack_tree_paths/identify_a_gadget_chain_in_the_classpath.md)

Compromise Application Using Fastjson2
*   OR
    *   **Exploit Deserialization Vulnerabilities**
        *   OR
            *   ***Exploit autoType Bypass***
                *   AND
                    *   **Identify a gadget chain in the classpath**

## Attack Tree Path: [Craft a malicious JSON payload with specific class names](./attack_tree_paths/craft_a_malicious_json_payload_with_specific_class_names.md)

Compromise Application Using Fastjson2
*   OR
    *   **Exploit Deserialization Vulnerabilities**
        *   OR
            *   ***Exploit autoType Bypass***
                *   AND
                    *   **Craft a malicious JSON payload with specific class names**

## Attack Tree Path: [Default `autoType` Enabled](./attack_tree_paths/default__autotype__enabled.md)

Compromise Application Using Fastjson2
*   OR
    *   **Default `autoType` Enabled**

