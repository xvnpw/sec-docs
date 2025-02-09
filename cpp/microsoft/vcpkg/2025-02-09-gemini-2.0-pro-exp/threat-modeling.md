# Threat Model Analysis for microsoft/vcpkg

## Threat: [Dependency Confusion Attack](./threats/dependency_confusion_attack.md)

*   **Description:** An attacker publishes a malicious package to a public registry (e.g., GitHub's default vcpkg registry) with the same name as a private package used internally.  The attacker crafts the malicious package to have a higher version number.  vcpkg, during dependency resolution, prioritizes the higher version, pulling the malicious package from the public registry instead of the intended private package.
    *   **Impact:**
        *   Execution of arbitrary code on developer machines or build servers.
        *   Data exfiltration (source code, credentials, etc.).
        *   Compromise of the application.
        *   Potential lateral movement.
    *   **Affected vcpkg Component:**
        *   `vcpkg install` command and its dependency resolution logic.
        *   Interaction with configured registries (especially the default public registry).
        *   Manifest mode (`vcpkg.json`) dependency resolution.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Use a Private Registry:** Host *all* dependencies, especially those with internal names, on a private vcpkg registry. Configure vcpkg to *only* use this private registry.
        *   **Namespace Packages:** If using a public registry, use a unique namespace/prefix for all internal package names.
        *   **Version Pinning:** Specify the *exact* version of *every* dependency in `vcpkg.json`.
        *   **Binary Caching:** Use a secure binary caching solution.

## Threat: [Typosquatting Attack](./threats/typosquatting_attack.md)

*   **Description:** An attacker publishes a malicious package with a name very similar to a popular, legitimate vcpkg package. A developer makes a typo when specifying the dependency, accidentally installing the malicious package.
    *   **Impact:**
        *   Execution of arbitrary code.
        *   Data exfiltration.
        *   Application compromise.
    *   **Affected vcpkg Component:**
        *   `vcpkg install` command.
        *   Manifest mode (`vcpkg.json`) dependency resolution.
        *   Interaction with configured registries.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Careful Dependency Specification:** Double-check package names for typos.
        *   **Code Review:** Review changes to `vcpkg.json`, paying attention to dependency names.
        *   **Use a Private Registry:** Reduces the risk, as only approved packages are available.
        *   **Automated Dependency Analysis:** Use tools that can detect potential typosquatting.

## Threat: [Compromised Upstream Package (in vcpkg Registry)](./threats/compromised_upstream_package__in_vcpkg_registry_.md)

*   **Description:** A legitimate package within the vcpkg registry (or a dependency of a vcpkg package) is compromised. vcpkg unknowingly distributes the compromised version.
    *   **Impact:**
        *   Execution of arbitrary code.
        *   Data breaches.
        *   Application compromise.
        *   Supply chain compromise.
    *   **Affected vcpkg Component:**
        *   `vcpkg install` and `vcpkg update` commands.
        *   The entire vcpkg registry and its package distribution mechanism.
        *   Manifest mode (`vcpkg.json`) dependency resolution.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Version Pinning:** Pin all dependencies to specific versions.
        *   **Regular Dependency Auditing:** Use vulnerability scanners.
        *   **Use a Private Registry:** More control over package versions and security audits.
        *   **Binary Caching:** Use a secure binary caching solution.
        *   **Monitor Security Advisories:** Stay informed about security advisories.

## Threat: [Malicious Build Script (in `portfile.cmake`)](./threats/malicious_build_script__in__portfile_cmake__.md)

*   **Description:** A compromised or malicious package includes a `portfile.cmake` (or other build scripts) that contains malicious code. This code is executed during the vcpkg build process.
    *   **Impact:**
        *   Execution of arbitrary code on the build server or developer machine.
        *   Data exfiltration.
        *   Modification of build artifacts.
        *   Lateral movement.
    *   **Affected vcpkg Component:**
        *   `vcpkg install` command and its build process.
        *   The `portfile.cmake` execution environment.
        *   Any custom build scripts invoked by the portfile.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use a Private Registry:** Allows for thorough review of `portfile.cmake` scripts.
        *   **Sandboxing:** Run the vcpkg build process in a sandboxed environment.
        *   **Code Review:** Carefully review `portfile.cmake` scripts.
        *   **Binary Caching:** Avoid building packages from source.
        *   **Least Privilege:** Run vcpkg with minimum privileges.

## Threat: [Vulnerability in vcpkg Itself (e.g., Code Execution)](./threats/vulnerability_in_vcpkg_itself__e_g___code_execution_.md)

*   **Description:** vcpkg itself contains a vulnerability that can be exploited by an attacker. This could be triggered by a specially crafted package, a malicious registry, or a manipulated build environment.
    *   **Impact:**
        *   Execution of arbitrary code on the machine running vcpkg.
        *   Compromise of the build environment.
        *   Potential escalation of privileges.
    *   **Affected vcpkg Component:**
        *   Potentially any part of the vcpkg codebase:
            *   Package parsing logic.
            *   Registry interaction code.
            *   Build script execution.
            *   Command-line argument parsing.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Keep vcpkg Updated:** Regularly update vcpkg.
        *   **Monitor Security Advisories:** Stay informed.
        *   **Least Privilege:** Run vcpkg with minimum privileges.
        *   **Input Validation:** If contributing to vcpkg, ensure thorough input validation.

## Threat: [Cache Poisoning](./threats/cache_poisoning.md)

* **Description:** An attacker gains access to the local vcpkg cache directory and modifies or replaces cached package files with malicious versions.
    * **Impact:**
        *   Execution of arbitrary code during subsequent builds.
        *   Compromise of the application.
        *   Data exfiltration.
    * **Affected vcpkg Component:**
        *   The vcpkg cache directory.
        *   `vcpkg install` command (when using cached packages).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   **Secure the Cache Directory:** Ensure appropriate access controls.
        *   **Use a Dedicated Build User:** Run vcpkg builds under a dedicated user account.
        *   **Binary Caching:** Use a secure, centrally managed binary caching solution.
        *   **Regularly Clear the Cache:** Periodically clear the local vcpkg cache.
        *   **Integrity Checks (Future):** Ideally, vcpkg would provide built-in mechanisms for verifying cache integrity.

