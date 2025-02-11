# Threat Model Analysis for gradleup/shadow

## Threat: [Dependency Conflict Exploitation (Shadow-Induced)](./threats/dependency_conflict_exploitation__shadow-induced_.md)

*   **Description:** Shadow's class merging process *incorrectly* resolves a conflict between two dependencies containing classes with the same name.  A vulnerable version of a class (e.g., one with a known deserialization flaw) is chosen over a patched version *because of Shadow's merging logic*. An attacker exploits this Shadow-introduced vulnerability.
    *   **Impact:**
        *   Remote Code Execution (RCE) on the application server.
        *   Data breach (sensitive data exfiltration).
        *   System compromise.
    *   **Affected Shadow Component:** The core merging logic of Shadow, specifically how it resolves class conflicts (the `mergeServiceFiles` and related configurations, and the order in which dependencies are processed). This is a *direct* consequence of Shadow's operation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Proactive Conflict Resolution (Relocation):** Use Shadow's `relocate` feature to rename packages of conflicting dependencies. This is the *primary* and most effective mitigation, as it directly addresses the root cause within Shadow.
        *   **Dependency Pinning:**  Explicitly define *exact* versions of all dependencies to reduce the *likelihood* of conflicts, but this doesn't *guarantee* prevention if Shadow's merging logic still makes an incorrect choice.
        *   **Dependency Analysis (Pre-Shading):** Use tools like `gradle dependencies` and OWASP Dependency-Check *before* shading to identify potential conflicts, allowing for proactive resolution.
        *   **Thorough Testing (Targeted):** Implement comprehensive integration and security tests that specifically target areas where conflicts are likely, focusing on the behavior of potentially conflicting classes.

## Threat: [Malicious Transitive Dependency Inclusion (Shadow-Enabled)](./threats/malicious_transitive_dependency_inclusion__shadow-enabled_.md)

*   **Description:** Shadow, due to its default behavior of including *all* transitive dependencies (unless explicitly excluded), pulls in a compromised, rarely used transitive dependency.  The attacker leverages this Shadow-included dependency to execute malicious code.  The *inclusion* is the direct result of Shadow's operation.
    *   **Impact:**
        *   Remote Code Execution (RCE).
        *   Backdoor installation.
        *   Data exfiltration.
    *   **Affected Shadow Component:** Shadow's default behavior of including all transitive dependencies. The `dependencies` block configuration in the build script, specifically the *lack* of precise filtering within the `shadowJar` task.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Dependency Filtering (Shadow-Specific):** Use Shadow's `include` and `exclude` filters *extensively* within the `shadowJar` configuration.  Only include the *absolute minimum* set of dependencies and classes required.  Prioritize `include` rules for a more restrictive, whitelist-based approach. This directly controls Shadow's inclusion behavior.
        *   **Dependency Whitelisting:** Maintain a whitelist of approved dependencies and versions. This is a general good practice, but it's Shadow's *lack* of filtering that makes it a direct threat.
        *   **Regular Dependency Audits:** Perform frequent security audits of *all* dependencies (including transitive ones).
        *   **SBOM Generation:** Create and maintain a Software Bill of Materials (SBOM) to track all included components.

## Threat: [Exploitation of Unintended Resource Inclusion (Shadow-Facilitated)](./threats/exploitation_of_unintended_resource_inclusion__shadow-facilitated_.md)

*   **Description:** Shadow, due to insufficiently restrictive `include`/`exclude` rules in the `shadowJar` configuration, includes sensitive configuration files, test resources, or development artifacts within the shaded JAR. An attacker extracts the shaded JAR and gains access to this sensitive information *because Shadow included it*.
    *   **Impact:**
        *   Disclosure of sensitive information (API keys, database credentials, internal network details).
        *   Facilitation of further attacks (using exposed credentials).
    *   **Affected Shadow Component:** Shadow's file inclusion mechanism, specifically the `include` and `exclude` patterns within the `shadowJar` configuration. The *lack* of precise filtering is the direct cause.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Precise File Filtering (Shadow-Specific):** Use *very specific* `include` and `exclude` patterns in the `shadowJar` configuration. Avoid broad wildcard patterns. This is the *direct* mitigation for Shadow's file inclusion behavior.
        *   **Separate Build Configurations:** Use separate Gradle build configurations for development, testing, and production. The production configuration's `shadowJar` task should be highly restrictive.
        *   **Resource Review (Post-Shading):** Manually review the *contents* of the shaded JAR *before* deployment to ensure no sensitive information is present. This is a verification step after Shadow has run.
        *   **Externalize Configuration:** Store sensitive configuration data *outside* the JAR (e.g., environment variables, secrets management service). This reduces the impact if Shadow accidentally includes something.

## Threat: [Delayed Vulnerability Patching (Shadow-Complicated)](./threats/delayed_vulnerability_patching__shadow-complicated_.md)

*   **Description:** A vulnerability is discovered in a dependency *within* a shaded JAR.  The merged nature of the shaded JAR, a *direct result of Shadow*, makes it more difficult and time-consuming to identify the specific vulnerable component and its version, delaying the patching process.
    *   **Impact:**
        *   Increased window of vulnerability to known exploits.
        *   Higher likelihood of successful attacks.
    *   **Affected Shadow Component:** The entire shaded JAR; the difficulty stems directly from the merged, monolithic nature of the artifact created by Shadow.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **SBOM and Dependency Tracking (Essential for Shadow):** Maintain a detailed and up-to-date SBOM that *explicitly* maps the contents of the shaded JAR back to the original dependencies and their versions. This is *crucial* because of Shadow's merging.
        *   **Automated Vulnerability Scanning (Shaded JAR Aware):** Use automated vulnerability scanning tools that are specifically capable of analyzing shaded JARs and identifying their constituent components.
        *   **Streamlined Update Process (Shadow-Specific):** Establish a clear and efficient process for updating dependencies, *rebuilding the shaded JAR*, and redeploying. This process must account for the Shadow-specific steps.
        *   **Monitoring for Vulnerability Announcements:** Actively monitor security advisories.

