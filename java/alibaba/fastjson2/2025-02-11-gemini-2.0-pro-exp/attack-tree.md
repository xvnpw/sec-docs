# Attack Tree Analysis for alibaba/fastjson2

Objective: Execute Arbitrary Code on the Server (Remote Code Execution - RCE) or Exfiltrate Sensitive Data via Deserialization Vulnerabilities in Fastjson2.

## Attack Tree Visualization

```
                                      +-------------------------------------------------+
                                      |  Attacker Achieves RCE or Data Exfiltration     |
                                      |  via Fastjson2 Deserialization Vulnerabilities  |
                                      +-------------------------------------------------+
                                                        |
          +----------------------------------------------------------------------------------------------------------------+
          |                                                                                                                |
+-------------------------+                                                                                +-------------------------+
|  Exploit Deserialization |                                                                                |  Exploit Configuration  |
|     Vulnerabilities     | [HIGH-RISK]                                                                       |       Weaknesses        | [HIGH-RISK]
+-------------------------+                                                                                +-------------------------+
          |                                                                                                                |
+---------------------+---------------------+                                                         +---------------------+---------------------+
|  AutoType Bypass  |  Unexpected Type  |                                                         |  Insecure Defaults  |  Misconfigured     |
|      (if enabled) |    Deserialization |                                                         |      (if any)      |  AutoType Settings |
|     [HIGH-RISK]   |     [HIGH-RISK]    |                                                         +---------------------+---------------------+
          |                     |                                                                                 |                     |
+---------+---------+   +---------+---------+                                                         +---------+---------+   +---------+---------+
|  Known  |  Crafted |   |  Gadget |         |                                                         |  No     |  Use of |   |  Enable |  Disable |
|  Bypass |  Payload |   |  Chains |         |                                                         |  Checks |  Weak   |   |  Auto-  |  Safe   |
|  Techn. |  (e.g.,  |   | [HIGH-RISK]|         |                                                         | [CRITICAL]|  Filters|   |  Type  |  Mode   |
| [CRITICAL]|  using   |   |         |         |                                                         |         | [HIGH-RISK]|   | [CRITICAL]|  Incorrectly|
|         |  known   |   |         |         |                                                         |         |         |   |         | [CRITICAL]|
|         |  classes)|   |         |         |                                                         |         |         |   |         |         |
|         | [CRITICAL]|   |         |         |                                                         |         |         |   |         |         |
+---------+---------+   +---------+---------+                                                         +---------+---------+   +---------+---------+
```

## Attack Tree Path: [Exploit Deserialization Vulnerabilities [HIGH-RISK]](./attack_tree_paths/exploit_deserialization_vulnerabilities__high-risk_.md)

*   **Description:** This is the overarching category for attacks that leverage weaknesses in how Fastjson2 handles the deserialization process (converting JSON data back into Java objects).  Deserialization vulnerabilities are a common and high-impact class of security flaws.
*   **Mechanism:** Attackers craft malicious JSON payloads that, when deserialized, trigger unintended behavior, often leading to arbitrary code execution.
*   **Mitigation (General):**
    *   Avoid deserializing data from untrusted sources.
    *   Use specific, well-defined Java classes (POJOs) for deserialization, rather than generic types.
    *   Implement robust input validation.
    *   Keep Fastjson2 updated to the latest version.

## Attack Tree Path: [AutoType Bypass (if enabled) [HIGH-RISK]](./attack_tree_paths/autotype_bypass__if_enabled___high-risk_.md)

*   **Description:** AutoType is a Fastjson2 feature that allows the deserialization of objects based on the class name specified in the JSON data.  This feature is inherently dangerous and has been the source of numerous vulnerabilities.
*   **Mechanism:** Attackers exploit weaknesses in the AutoType mechanism (or its absence) to instantiate arbitrary Java classes, even those not intended to be deserialized.
*   **Mitigation:**
    *   **Disable AutoType completely.** This is the strongest and most recommended mitigation.
    *   If AutoType *must* be used, implement a very strict whitelist of allowed classes.  *Never* rely on a blacklist.
    *   Ensure `safeMode` is enabled and properly configured.

## Attack Tree Path: [2.a Known Bypass Techniques [CRITICAL]](./attack_tree_paths/2_a_known_bypass_techniques__critical_.md)

*   **Description:**  Researchers and attackers have discovered various techniques to bypass Fastjson2's AutoType restrictions over time.  These bypasses often involve exploiting subtle flaws in the library's logic or using specific class names or combinations of characters.
*   **Mechanism:**  The attacker uses a publicly known or privately discovered bypass technique to circumvent the security checks intended to prevent arbitrary class instantiation.
*   **Mitigation:**
            *   Keep Fastjson2 updated to the latest version, as patches often address known bypasses.
            *   Monitor security advisories and research related to Fastjson2.
            *   Disable AutoType.

## Attack Tree Path: [2.b Crafted Payload (e.g., using known classes) [CRITICAL]](./attack_tree_paths/2_b_crafted_payload__e_g___using_known_classes___critical_.md)

*   **Description:**  Even without a specific bypass technique, if AutoType is enabled, an attacker can craft a JSON payload that specifies a dangerous class to be instantiated.
*   **Mechanism:** The attacker identifies a class that, when instantiated and its methods called, can lead to RCE (e.g., a class that executes system commands).  They then create a JSON payload that instructs Fastjson2 to deserialize an instance of that class.
*   **Mitigation:**
            *   Disable AutoType.
            *   Use a strict whitelist of allowed classes.

## Attack Tree Path: [3. Unexpected Type Deserialization [HIGH-RISK]](./attack_tree_paths/3__unexpected_type_deserialization__high-risk_.md)

    *   **3.a Gadget Chains [HIGH-RISK]**
        *   **Description:** Even if AutoType is disabled, if the application deserializes data into generic types (like `Object`, interfaces, or abstract classes), an attacker might be able to construct a "gadget chain."  A gadget chain is a sequence of seemingly harmless class instantiations that, when executed in a specific order, lead to malicious code execution.
        *   **Mechanism:** The attacker carefully crafts a JSON payload that, when deserialized, creates a chain of objects.  The methods of these objects, when called during the deserialization process or later in the application's logic, interact in a way that ultimately results in RCE.  This is a complex and sophisticated attack.
        *   **Mitigation:**
            *   Use specific, well-defined Java classes (POJOs) for deserialization.  Avoid generic types.
            *   If generic types *must* be used, be extremely cautious and thoroughly analyze the potential for gadget chains.

## Attack Tree Path: [Gadget Chains [HIGH-RISK]](./attack_tree_paths/gadget_chains__high-risk_.md)

*   **Description:** Even if AutoType is disabled, if the application deserializes data into generic types (like `Object`, interfaces, or abstract classes), an attacker might be able to construct a "gadget chain."  A gadget chain is a sequence of seemingly harmless class instantiations that, when executed in a specific order, lead to malicious code execution.
        *   **Mechanism:** The attacker carefully crafts a JSON payload that, when deserialized, creates a chain of objects.  The methods of these objects, when called during the deserialization process or later in the application's logic, interact in a way that ultimately results in RCE.  This is a complex and sophisticated attack.
        *   **Mitigation:**
            *   Use specific, well-defined Java classes (POJOs) for deserialization.  Avoid generic types.
            *   If generic types *must* be used, be extremely cautious and thoroughly analyze the potential for gadget chains.

## Attack Tree Path: [4. Exploit Configuration Weaknesses [HIGH-RISK]](./attack_tree_paths/4__exploit_configuration_weaknesses__high-risk_.md)

*   **Description:**  Misconfigurations of Fastjson2 can significantly increase the attack surface, making it easier for attackers to exploit vulnerabilities.

## Attack Tree Path: [4.a Insecure Defaults (No Checks) [CRITICAL]](./attack_tree_paths/4_a_insecure_defaults__no_checks___critical_.md)

*   **Description:**  Using Fastjson2 without any security checks (no whitelists, no `safeMode`, and potentially with AutoType enabled) is extremely dangerous.
        *   **Mechanism:**  This configuration provides no protection against deserialization attacks, making RCE trivial.
        *   **Mitigation:**
            *   Enable `safeMode`.
            *   Implement a strict whitelist of allowed classes if AutoType is necessary.
            *   Disable AutoType if possible.

## Attack Tree Path: [4.b Use of Weak Filters [HIGH-RISK]](./attack_tree_paths/4_b_use_of_weak_filters__high-risk_.md)

*   **Description:**  Developers might implement whitelists or blacklists, but these filters can be incomplete, flawed, or easily bypassed.
        *   **Mechanism:**  The attacker identifies weaknesses in the filter implementation (e.g., missing entries, regular expressions that can be circumvented) and crafts a payload that bypasses the filter.
        *   **Mitigation:**
            *   Use a strict whitelist approach, and regularly review and update the whitelist.
            *   Avoid using blacklists, as they are almost always incomplete.
            *   Thoroughly test the filter implementation with various malicious payloads.

## Attack Tree Path: [4.c Misconfigured AutoType Settings: Enable AutoType [CRITICAL]](./attack_tree_paths/4_c_misconfigured_autotype_settings_enable_autotype__critical_.md)

*   **Description:**  Explicitly enabling AutoType without implementing strong safeguards (like a strict whitelist) is a critical vulnerability.
            *   **Mechanism:**  This configuration makes it easy for attackers to instantiate arbitrary classes.
            *   **Mitigation:** Disable AutoType.

## Attack Tree Path: [4.c Misconfigured AutoType Settings: Disable Safe Mode Incorrectly [CRITICAL]](./attack_tree_paths/4_c_misconfigured_autotype_settings_disable_safe_mode_incorrectly__critical_.md)

*   **Description:** `safeMode` provides a baseline level of protection.  Disabling it or misconfiguring it significantly weakens Fastjson2's security.
            *   **Mechanism:**  This configuration removes or weakens built-in security checks, increasing the attack surface.
            *   **Mitigation:** Ensure `safeMode` is enabled and properly configured according to the Fastjson2 documentation.

