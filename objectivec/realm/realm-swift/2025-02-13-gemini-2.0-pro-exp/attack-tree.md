# Attack Tree Analysis for realm/realm-swift

Objective: Exfiltrate or modify sensitive data stored within the Realm database.

## Attack Tree Visualization

                                     +-----------------------------------------------------+
                                     | Exfiltrate/Modify Realm Data                        |
                                     +-----------------------------------------------------+
                                                  /                 |                 \
          ***---------------------------------***                  |                  -------------------
         |                                         |                                 |
+---------------------+       +---------------------+       +---------------------+
|  Unauthorized     |       |  Exploit Realm      |       |  Compromise         |
|  Local Access     |       |  Vulnerabilities   |       |  Encryption Keys    |
+---------------------+       +---------------------+       +---------------------+
         |             ***                  |                  ***                             
  -------|-------             --------|--------             --------|--------
 |               |           |                 |           |                 |
+-------+ +-------+         +-------+         +-------+ +-------+
|  App  |                   |  Code |         |  Key  | |  Key  |
| Sand- |                   | Injec-|         |  Hard-| |       |
| box   |                   |  tion |         |  cod- | |       |
| Esc.  |                   | [CRITI-|         |  ing  | |       |
| [CRITI-|                   |  CAL] |         | [CRITI-| |       |
|  CAL] |                   |   *** |         |  CAL] | |       |
+-------+                   +-------+         +-------+ +-------+

## Attack Tree Path: [High-Risk Path 1: Code Injection](./attack_tree_paths/high-risk_path_1_code_injection.md)

Goal: Exfiltrate or modify Realm data.
Main Branch: Exploit Realm Vulnerabilities.
Attack Step: Code Injection [CRITICAL].
Description:
The attacker exploits the application's failure to use parameterized queries when interacting with the Realm database.
The attacker crafts malicious input that, when concatenated with a Realm query string, alters the query's intended behavior.
This allows the attacker to execute arbitrary Realm queries, potentially retrieving, modifying, or deleting data they should not have access to.
Likelihood: High (if parameterized queries are not used).
Impact: High (data exfiltration, modification, deletion).
Effort: Low (if vulnerable).
Skill Level: Intermediate.
Detection Difficulty: Medium (requires code review and dynamic analysis).
Mitigation:
*Crucially*, always use Realm's built-in parameterized query mechanisms (predicates).
Never construct queries by concatenating strings with user-provided input.
Implement strict input validation and sanitization.

## Attack Tree Path: [High-Risk Path 2: Key Hardcoding](./attack_tree_paths/high-risk_path_2_key_hardcoding.md)

Goal: Exfiltrate or modify Realm data.
Main Branch: Compromise Encryption Keys.
Attack Step: Key Hardcoding [CRITICAL].
Description:
The Realm encryption key is directly embedded within the application's source code or a readily accessible configuration file.
The attacker can obtain the key through reverse engineering the application (e.g., decompiling the binary, inspecting resources).
With the key, the attacker can decrypt the entire Realm database.
Likelihood: High (common developer mistake).
Impact: Very High (complete database compromise).
Effort: Very Low.
Skill Level: Novice.
Detection Difficulty: Easy (through code review or reverse engineering).
Mitigation:
Never store encryption keys in the application's code or configuration files.
Use the platform's secure key storage mechanisms (iOS Keychain, Android Keystore).

## Attack Tree Path: [High-Risk Path 3: App Sandbox Escape](./attack_tree_paths/high-risk_path_3_app_sandbox_escape.md)

Goal: Exfiltrate or modify Realm data.
Main Branch: Unauthorized Local Access.
Attack Step: App Sandbox Escape [CRITICAL].
Description:
The attacker exploits a vulnerability in the application itself, another application on the device, or a library used by the application.
This vulnerability allows the attacker to bypass the operating system's sandboxing restrictions, which normally prevent applications from accessing files outside their designated containers.
Once the sandbox is breached, the attacker can directly access the Realm database file.
Likelihood: Medium.
Impact: High (direct access to the Realm file).
Effort: Medium.
Skill Level: Advanced.
Detection Difficulty: Hard (requires vulnerability analysis and exploit development).
Mitigation:
Keep all libraries and dependencies up-to-date.
Follow secure coding practices to prevent vulnerabilities that could lead to sandbox escapes.
Use memory-safe languages or features where possible.
Consider using OS-level security features like Data Protection (iOS) to encrypt the Realm file at rest.
Regularly conduct security audits and penetration testing.

