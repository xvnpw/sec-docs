# Threat Model Analysis for prettier/prettier

## Threat: [Malicious Package Substitution (Dependency Confusion/Typosquatting)](./threats/malicious_package_substitution__dependency_confusiontyposquatting_.md)

*   **Description:** An attacker publishes a malicious package to a public registry (e.g., npm) with a name similar to `prettier` (e.g., `pretiier`, `prettier-pro`). A developer mistakenly installs this malicious package instead of the legitimate one. The malicious package mimics Prettier's functionality but also includes malicious code designed to execute during the formatting process.
    *   **Impact:**
        *   Code modification: The malicious package could subtly alter the codebase during formatting, introducing vulnerabilities or backdoors.
        *   Data exfiltration: The malicious package could steal sensitive information accessible during the build process (though ideally, secrets should not be present).
        *   System compromise: The malicious package could execute arbitrary code on the developer's machine or the build server, potentially leading to a full system compromise.
    *   **Affected Prettier Component:** The entire `prettier` package (the *imposter* package) is affected, impacting all modules and functions.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Package-lock Files:** Always use and commit `package-lock.json` (npm), `yarn.lock` (Yarn), or `pnpm-lock.yaml` (pnpm).
        *   **Manual Verification:** Carefully review the package name and version before installing.
        *   **Private Registry:** Use a private package registry to control the source of dependencies.
        *   **SCA Tools:** Employ Software Composition Analysis (SCA) tools.

## Threat: [Compromised Prettier Plugin](./threats/compromised_prettier_plugin.md)

*   **Description:** An attacker publishes a malicious Prettier plugin or compromises a legitimate, existing plugin.  This plugin, when used as part of the Prettier formatting process, executes malicious code.
    *   **Impact:**
        *   Code modification: The plugin could inject malicious code or subtly alter existing code during formatting.
        *   Data exfiltration: The plugin could steal sensitive information accessible during the build.
        *   System compromise: The plugin could execute arbitrary code with the privileges of the user running Prettier.
    *   **Affected Prettier Component:** The specific malicious plugin and any Prettier core functions that interact with the plugin API (`prettier.format`, plugin loading mechanisms).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Plugin Vetting:** Carefully review the source code, author, and community reputation of *any* Prettier plugin.
        *   **Limit Plugin Usage:** Minimize the number of plugins used.
        *   **Code Review:** Treat plugin code as part of your codebase.
        *   **Sandboxing (Advanced):** Consider running Prettier and its plugins in a sandboxed environment.

## Threat: [Post-Installation Tampering of Prettier Executable](./threats/post-installation_tampering_of_prettier_executable.md)

*   **Description:** After a legitimate installation of Prettier, an attacker gains access to the developer's machine or the build server and directly modifies the installed Prettier files within the `node_modules` directory, injecting malicious code.
    *   **Impact:**
        *   Code modification: The tampered Prettier executable could inject malicious code or alter existing code.
        *   Data exfiltration: The tampered executable could steal sensitive information.
        *   System compromise: The tampered executable could execute arbitrary code.
    *   **Affected Prettier Component:** Any of the core Prettier modules (e.g., `index.js`, parser files) within the `node_modules/prettier` directory.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **File Integrity Monitoring (FIM):** Use FIM to detect unauthorized modifications to the `node_modules` directory.
        *   **Regular Re-installation:** Regularly delete and re-install dependencies from a clean state (`rm -rf node_modules && npm install`).
        *   **Read-Only `node_modules` (Advanced):** Make the `node_modules` directory read-only after installation.
        *   **Strong Access Controls:** Implement strong access controls for developer machines and CI/CD pipelines.

