# Threat Model Analysis for gradleup/shadow

## Threat: [Inclusion of Malicious Dependencies](./threats/inclusion_of_malicious_dependencies.md)

* **Threat:** Inclusion of Malicious Dependencies
    * **Description:**
        * **Attacker Action:** An attacker might compromise a legitimate dependency or create a malicious dependency with a similar name, hoping developers will unknowingly include it in their project.
        * **How:** If a project includes a malicious dependency, **Shadow will bundle it into the final JAR**, making its malicious code part of the application. Shadow's role is the direct mechanism for including this malicious code in the deployable artifact.
    * **Impact:**
        * The application becomes vulnerable to the malicious code within the dependency. This could lead to data breaches, remote code execution, or other security compromises.
    * **Affected Component:**
        * Dependency inclusion logic: **Shadow includes whatever dependencies are declared in the project's `build.gradle` file.**
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Dependency Scanning and Vulnerability Analysis:** Use tools like OWASP Dependency-Check or Snyk to scan dependencies for known vulnerabilities.
        * **Software Composition Analysis (SCA):** Implement SCA practices to track and manage open-source components and their associated risks.
        * **Secure Dependency Sources:** Use trusted and reputable artifact repositories. Consider using a private artifact repository to control the source of dependencies.
        * **Dependency Verification:** Verify the integrity and authenticity of dependencies using checksums or signatures.

## Threat: [Supply Chain Attack Targeting the Shadow Plugin Itself](./threats/supply_chain_attack_targeting_the_shadow_plugin_itself.md)

* **Threat:** Supply Chain Attack Targeting the Shadow Plugin Itself
    * **Description:**
        * **Attacker Action:** An attacker could compromise the **Shadow plugin's repository or distribution channels** to inject malicious code into the plugin itself.
        * **How:** If a compromised version of the **Shadow plugin is used**, the malicious code could be executed during the build process, potentially injecting backdoors or other malware into the generated `shadowJar`.
    * **Impact:**
        * The application built using the compromised plugin would be inherently compromised, potentially leading to severe security breaches.
    * **Affected Component:**
        * Gradle plugin resolution and execution: The process by which Gradle downloads and executes plugins, including **Shadow**.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Use Official and Trusted Sources:** Obtain the Shadow plugin from the official Gradle Plugin Portal or trusted repositories.
        * **Verify Plugin Integrity:** Verify the integrity of the plugin using checksums or signatures provided by the maintainers.
        * **Stay Updated:** Keep the Shadow plugin updated to the latest version to benefit from security patches.
        * **Dependency Verification for Plugins:** Explore and utilize mechanisms for verifying the integrity of Gradle plugins.

