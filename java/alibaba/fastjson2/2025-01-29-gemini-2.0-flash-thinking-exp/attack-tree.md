# Attack Tree Analysis for alibaba/fastjson2

Objective: Compromise application using fastjson2 by exploiting vulnerabilities within fastjson2.

## Attack Tree Visualization

```
Compromise Application via fastjson2 **[CRITICAL NODE]**
├───[OR]─ **[HIGH RISK]** Exploit Deserialization Vulnerabilities **[CRITICAL NODE]**
│   ├───[OR]─ **[HIGH RISK]** Remote Code Execution (RCE) via Deserialization **[CRITICAL NODE]**
│   │   ├───[AND]─ **[HIGH RISK]** Exploit Polymorphic Deserialization/`autoType` Feature **[CRITICAL NODE]**
│   │   │   ├───[OR]─ **[HIGH RISK]** Leverage Known Gadget Classes **[CRITICAL NODE]**
│   │   │   │   └─── Utilize publicly known exploit chains (e.g., using classes present in common Java libraries on the classpath) to achieve RCE when deserialized.
│   │   │   ├───[OR]─ Bypass `autoType` Blacklist/Whitelist (if enabled)
│   │   │   │   ├─── Find Bypass Techniques
│   │   │   │   │   ├─── Case Sensitivity Issues
│   │   │   │   │   │   └─── Exploit case sensitivity differences in class names if blacklist/whitelist is case-sensitive.
│   │   │   │   │   ├─── Whitespace/Control Characters
│   │   │   │   │   │   └─── Inject whitespace or control characters into class names to bypass string-based filters.
│   │   │   │   │   ├─── Encoding/Obfuscation
│   │   │   │   │   │   └─── Use encoding techniques (e.g., URL encoding, Unicode escapes) to obfuscate class names.
│   │   │   │   │   └─── Logic Flaws in Filtering
│   │   │   │   │       └─── Identify and exploit weaknesses in the blacklist/whitelist logic itself.
│   │   │   └───[AND]─ **[HIGH RISK]** Craft Malicious JSON Payload **[CRITICAL NODE]**
│   │   │       └─── Construct a JSON payload that, when deserialized by fastjson2 with `autoType` enabled, instantiates and executes malicious code.
├───[OR]─ **[HIGH RISK]** Exploit Configuration Misuse/Weaknesses **[CRITICAL NODE]**
│   ├───[OR]─ **[HIGH RISK]** `autoType` Enabled Unnecessarily **[CRITICAL NODE]**
│   │   └─── **[HIGH RISK]** Exploit `autoType` (as described in Deserialization RCE) **[CRITICAL NODE]**
│   │       └─── If `autoType` is enabled where user-controlled JSON is processed, exploit deserialization vulnerabilities.
│   └───[OR]─ **[HIGH RISK]** Developer Misuse Leading to Vulnerabilities **[CRITICAL NODE]**
│       ├─── **[HIGH RISK]** Blindly Deserializing User Input **[CRITICAL NODE]**
│       │   └─── Application directly deserializes user-provided JSON without proper validation or sanitization, making it vulnerable to deserialization attacks.
```

## Attack Tree Path: [1. Compromise Application via fastjson2 [CRITICAL NODE]](./attack_tree_paths/1__compromise_application_via_fastjson2__critical_node_.md)

*   **Attack Vector:** This is the root goal. An attacker aims to leverage vulnerabilities in fastjson2 to gain unauthorized access or control over the application.
*   **Risk:** Critical. Successful compromise can lead to data breaches, system downtime, reputational damage, and legal repercussions.

## Attack Tree Path: [2. Exploit Deserialization Vulnerabilities [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/2__exploit_deserialization_vulnerabilities__high_risk__critical_node_.md)

*   **Attack Vector:** Exploiting weaknesses in fastjson2's deserialization process, particularly when handling type information.
*   **Risk:** High. Deserialization vulnerabilities can lead to Remote Code Execution (RCE), Denial of Service (DoS), and Information Disclosure.

## Attack Tree Path: [3. Remote Code Execution (RCE) via Deserialization [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/3__remote_code_execution__rce__via_deserialization__high_risk__critical_node_.md)

*   **Attack Vector:**  Crafting malicious JSON payloads that, when deserialized by fastjson2, execute arbitrary code on the server. This is the most severe outcome of deserialization vulnerabilities.
*   **Risk:** Critical. RCE allows the attacker to gain complete control over the application server, potentially leading to data theft, malware installation, and further attacks on internal systems.

## Attack Tree Path: [4. Exploit Polymorphic Deserialization/`autoType` Feature [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/4__exploit_polymorphic_deserialization_autotype__feature__high_risk__critical_node_.md)

*   **Attack Vector:**  Abusing fastjson2's `autoType` feature, which allows specifying class types within the JSON payload. If enabled and not properly controlled, attackers can force the deserialization of malicious classes.
*   **Risk:** Critical. `autoType` is a primary enabler for deserialization RCE attacks in fastjson2.

## Attack Tree Path: [5. Leverage Known Gadget Classes [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/5__leverage_known_gadget_classes__high_risk__critical_node_.md)

*   **Attack Vector:** Utilizing publicly known "gadget classes" (vulnerable classes often found in common Java libraries) in malicious JSON payloads. These classes can be chained together to achieve RCE when deserialized.
*   **Risk:** Critical.  Gadget chains simplify RCE exploitation as attackers can reuse existing exploit techniques and don't need to find new vulnerabilities in fastjson2 itself.

## Attack Tree Path: [6. Craft Malicious JSON Payload [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/6__craft_malicious_json_payload__high_risk__critical_node_.md)

*   **Attack Vector:**  Constructing a JSON payload that includes the necessary directives (e.g., `@type` with a malicious class) and data to trigger the desired exploit (RCE in this high-risk path).
*   **Risk:** Critical. The malicious payload is the weapon used to exploit the deserialization vulnerability. Successful crafting of this payload is essential for RCE.

## Attack Tree Path: [7. Exploit Configuration Misuse/Weaknesses [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/7__exploit_configuration_misuseweaknesses__high_risk__critical_node_.md)

*   **Attack Vector:**  Taking advantage of insecure configurations or misconfigurations of fastjson2 in the application.
*   **Risk:** High. Misconfigurations, especially enabling `autoType` unnecessarily, significantly increase the attack surface and likelihood of successful exploitation.

## Attack Tree Path: [8. `autoType` Enabled Unnecessarily [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/8___autotype__enabled_unnecessarily__high_risk__critical_node_.md)

*   **Attack Vector:**  Identifying and exploiting scenarios where `autoType` is enabled in the application's fastjson2 configuration but is not actually required for legitimate functionality.
*   **Risk:** Critical. Unnecessary `autoType` enablement directly opens the door to deserialization RCE attacks.

## Attack Tree Path: [9. Exploit `autoType` (as described in Deserialization RCE) [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/9__exploit__autotype___as_described_in_deserialization_rce___high_risk__critical_node_.md)

*   **Attack Vector:**  Once `autoType` is confirmed to be enabled and processing user-controlled JSON, attackers can proceed with the deserialization RCE attack techniques described earlier (gadget classes, payload crafting).
*   **Risk:** Critical. This is the direct exploitation of the misconfiguration, leading to RCE.

## Attack Tree Path: [10. Developer Misuse Leading to Vulnerabilities [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/10__developer_misuse_leading_to_vulnerabilities__high_risk__critical_node_.md)

*   **Attack Vector:**  Exploiting coding errors or insecure practices by developers when using fastjson2.
*   **Risk:** High. Developer errors are a common source of vulnerabilities. Blindly deserializing user input is a prime example of such misuse.

## Attack Tree Path: [11. Blindly Deserializing User Input [HIGH RISK, CRITICAL NODE]](./attack_tree_paths/11__blindly_deserializing_user_input__high_risk__critical_node_.md)

*   **Attack Vector:**  Directly deserializing JSON data received from users without any validation or sanitization. This allows attackers to inject malicious payloads directly into the deserialization process.
*   **Risk:** Critical. This is a severe coding flaw that makes the application highly vulnerable to deserialization attacks, especially RCE.

