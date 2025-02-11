# Attack Surface Analysis for gradleup/shadow

## Attack Surface: [Class/Resource Name Collisions (Pre-Relocation)](./attack_surfaces/classresource_name_collisions__pre-relocation_.md)

*   **Description:** Malicious dependencies intentionally use the same class or resource names as legitimate libraries *before* Shadow's relocation process.
*   **Shadow Contribution:** Shadow's merging of multiple JARs creates the *opportunity* for these collisions.
*   **Example:** A malicious library includes a class named `com.example.security.Authenticator` (same as a legitimate library) with malicious code. If Shadow doesn't relocate this correctly, the malicious version might be loaded.
*   **Impact:**
    *   Arbitrary code execution.
    *   Bypass of security mechanisms.
    *   Data exfiltration.
    *   Privilege escalation.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Relocation Rules:** Define precise, unambiguous relocation rules. Avoid wildcards. Example: `relocate 'com.example.library', 'shadow.com.example.library'` (and test).
    *   **Dependency Vetting:** Thoroughly vet all dependencies (including transitive ones) *before* using Shadow. Use dependency scanning tools.
    *   **Code Review (of Generated JAR):** Manually inspect the final JAR (using a decompiler if needed) to confirm correct relocation.

## Attack Surface: [Class/Resource Name Collisions (Post-Relocation/Merging Bugs)](./attack_surfaces/classresource_name_collisions__post-relocationmerging_bugs_.md)

*   **Description:** Bugs in Shadow's relocation or merging logic allow malicious classes/resources to override legitimate ones, *even with* relocation rules.
*   **Shadow Contribution:** This is a direct vulnerability *within* the Shadow plugin itself.
*   **Example:** A bug in Shadow's relocation algorithm causes it to incorrectly handle an edge case, leading to a malicious class not being relocated.
*   **Impact:** (Same as above)
    *   Arbitrary code execution.
    *   Bypass of security mechanisms.
    *   Data exfiltration.
    *   Privilege escalation.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Update Shadow:** Keep the Shadow plugin updated to the latest stable version.
    *   **Monitor Advisories:** Subscribe to security advisories for Shadow and Gradle.
    *   **Report Bugs:** Responsibly disclose potential vulnerabilities to the maintainers.

## Attack Surface: [Resource Overrides (Non-Class Files)](./attack_surfaces/resource_overrides__non-class_files_.md)

*   **Description:** Malicious dependencies include resource files (configuration files, native libraries) that override legitimate resources.
*   **Shadow Contribution:** Shadow merges resources from multiple JARs, creating the potential for overrides.
*   **Example:** A malicious dependency includes a `log4j2.xml` that overrides the application's logging configuration, potentially enabling RCE (if a vulnerable Log4j version is present). Or, a malicious native library overrides a legitimate one.
*   **Impact:**
    *   Altered application behavior.
    *   Code execution (especially with native libraries or configuration files).
    *   Information disclosure.
*   **Risk Severity:** High to Critical (depending on the resource)
*   **Mitigation Strategies:**
    *   **Explicit Resource Merging/Filtering:** Use Shadow's `mergeServiceFiles()`, `exclude()`, `include()`, and `rename()` to control resource merging.
    *   **Resource Integrity Checks:** Implement runtime checks (e.g., checksums) for critical resources.
    *   **Unique Resource Naming:** Encourage unique resource names to minimize collisions.

## Attack Surface: [Manifest Manipulation](./attack_surfaces/manifest_manipulation.md)

*   **Description:** An attacker influences Shadow's modification of the JAR's manifest (META-INF/MANIFEST.MF).
*   **Shadow Contribution:** Shadow provides mechanisms to modify the manifest.
*   **Example:** An attacker changes the `Main-Class` attribute to point to a malicious class.
*   **Impact:**
    *   Arbitrary code execution (if the main class is changed).
    *   Altered application behavior.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Controlled Manifest Configuration:** Carefully configure Shadow's manifest modification.
    *   **Manifest Verification:** Verify the manifest contents after building.
    *   **JAR Signing:** Digitally sign the JAR to detect tampering.

## Attack Surface: [Misconfiguration of Shadow](./attack_surfaces/misconfiguration_of_shadow.md)

* **Description:** Incorrect configuration of the Shadow plugin itself leads to unintended behavior and potential vulnerabilities.
* **Shadow Contribution:** This is a direct result of how the user configures the Shadow plugin.
* **Example:** Accidentally disabling relocation entirely, or using overly broad include/exclude patterns that allow malicious code to slip through.
* **Impact:**
    * Varies greatly depending on the specific misconfiguration. Could lead to any of the other attack vectors listed above.
* **Risk Severity:** High to Critical (depending on the misconfiguration)
* **Mitigation Strategies:**
    * **Configuration Review:** Thoroughly review the Shadow configuration in your build script.
    * **Documentation:** Consult the official Shadow documentation.
    * **Testing:** Extensively test the build process and the resulting JAR. Use a "shift-left" approach, testing early and often.

