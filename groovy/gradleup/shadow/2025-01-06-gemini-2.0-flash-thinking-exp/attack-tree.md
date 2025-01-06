# Attack Tree Analysis for gradleup/shadow

Objective: To gain unauthorized control or access to the application by exploiting vulnerabilities introduced by the Gradle Shadow plugin during the creation of the fat JAR.

## Attack Tree Visualization

```
**Compromise Application via Shadow Plugin**
*   AND: Exploit Vulnerability Introduced by Shadow ***Critical Node***
    *   OR: Dependency Manipulation ***High-Risk Path***
        *   Exploit Class Name Collisions ***High-Risk Path***
            *   AND: Introduce Malicious Dependency with Conflicting Class Name
                *   Target Application Class Name
                *   Shadow Merges Malicious Class ***Critical Node***
        *   Overwrite Application Class with Malicious Dependency Class ***High-Risk Path***
            *   AND: Introduce Malicious Dependency with Same Qualified Name
                *   Target Critical Application Class
                *   Shadow Prioritizes Malicious Dependency Class ***Critical Node***
        *   Introduce Vulnerable Dependency Not Explicitly Declared ***High-Risk Path***
            *   AND: Shadow Includes Transitive Dependency
                *   Vulnerable Transitive Dependency Exists
                *   Application Code Uses Functionality Exposed by Vulnerable Dependency
    *   OR: Resource Manipulation
        *   Overwrite Application Resource with Malicious Dependency Resource ***High-Risk Path***
            *   AND: Introduce Malicious Dependency with Conflicting Resource Path
                *   Target Critical Application Resource (e.g., Configuration)
                *   Shadow Overwrites Application Resource ***Critical Node***
    *   OR: Manifest Manipulation
        *   Hijack Main Class Execution ***High-Risk Path***
            *   AND: Introduce Dependency with Malicious Main Class
                *   Shadow Configured to Use Dependency's Main Class (Accidentally or Intentionally)
                *   Malicious Code Executes on Application Startup ***Critical Node***
        *   Manipulate Service Loaders ***High-Risk Path***
            *   AND: Introduce Dependency with Malicious Service Provider Implementation
                *   Shadow Merges `META-INF/services` Files
                *   Application Uses Service Loader Mechanism to Load the Malicious Provider
    *   OR: Security Feature Removal/Weakening
        *   Strip Code Signatures from Dependencies ***High-Risk Path***
            *   AND: Shadow Configuration Removes Code Signatures
                *   Allows Introduction of Tampered Dependencies ***Critical Node***
                *   Application Trusts Unsigned Code
```


## Attack Tree Path: [Dependency Manipulation](./attack_tree_paths/dependency_manipulation.md)

*   **Exploit Class Name Collisions:**
    *   An attacker introduces a malicious dependency containing a class with the same fully qualified name as a critical class in the application.
    *   **Critical Node: Shadow Merges Malicious Class:** Shadow, by default, might pick the malicious class during the merge process, effectively replacing the legitimate application class.
*   **Overwrite Application Class with Malicious Dependency Class:**
    *   Similar to class name collisions, but the attacker specifically targets a critical application class, aiming to replace it entirely with a malicious version.
    *   **Critical Node: Shadow Prioritizes Malicious Dependency Class:** Shadow's merging logic results in the malicious dependency's class being used.
*   **Introduce Vulnerable Dependency Not Explicitly Declared:**
    *   Shadow includes transitive dependencies.
    *   An attacker leverages a vulnerability in a transitive dependency that the application isn't even directly aware of.
    *   Application code unknowingly uses functionality exposed by this vulnerable dependency, creating an attack surface.

## Attack Tree Path: [Resource Manipulation](./attack_tree_paths/resource_manipulation.md)

*   **Overwrite Application Resource with Malicious Dependency Resource:**
    *   A malicious dependency contains a resource file (e.g., configuration file, properties file) with the same path as a critical resource in the application.
    *   **Critical Node: Shadow Overwrites Application Resource:** Shadow's default merge strategy overwrites the application's legitimate resource with the malicious one.

## Attack Tree Path: [Manifest Manipulation](./attack_tree_paths/manifest_manipulation.md)

*   **Hijack Main Class Execution:**
    *   A malicious dependency declares a `Main-Class` in its manifest.
    *   Shadow is misconfigured or an attacker can influence the final JAR's manifest.
    *   **Critical Node: Malicious Code Executes on Application Startup:** The application starts with the malicious dependency's main class, allowing arbitrary code execution.
*   **Manipulate Service Loaders:**
    *   Attackers include malicious service provider implementations in a dependency.
    *   Shadow merges `META-INF/services` files.
    *   Application uses the Service Loader mechanism.
    *   The application loads the attacker's malicious provider, potentially leading to code execution or other malicious behavior.

## Attack Tree Path: [Security Feature Removal/Weakening](./attack_tree_paths/security_feature_removalweakening.md)

*   **Strip Code Signatures from Dependencies:**
    *   **Critical Node: Allows Introduction of Tampered Dependencies:** Shadow configuration removes code signatures from dependencies.
    *   This weakens security by allowing the inclusion of tampered dependencies without detection.
    *   The application trusts unsigned code, making it vulnerable to compromised dependencies.

## Attack Tree Path: [Critical Nodes](./attack_tree_paths/critical_nodes.md)

*   **Exploit Vulnerability Introduced by Shadow:** This is the top-level critical node, representing the point where Shadow's functionality is exploited.
*   **Shadow Merges Malicious Class:** The specific action of Shadow incorrectly prioritizing a malicious class.
*   **Shadow Prioritizes Malicious Dependency Class:** Similar to the above, highlighting the incorrect prioritization.
*   **Shadow Overwrites Application Resource:** The specific action of Shadow replacing a legitimate resource with a malicious one.
*   **Malicious Code Executes on Application Startup:** The point where the attacker achieves code execution.
*   **Allows Introduction of Tampered Dependencies:** The point where the security of dependency verification is bypassed.

