# Attack Tree Analysis for yarnpkg/berry

Objective: Compromise application using Yarn Berry by exploiting weaknesses or vulnerabilities within Yarn Berry's ecosystem or usage.

## Attack Tree Visualization

Attack Goal: **[CRITICAL NODE]** Compromise Application Using Yarn Berry **[CRITICAL NODE]**
├───[OR]─ **[HIGH-RISK PATH]** Supply Chain Attack (Dependency Manipulation) **[CRITICAL NODE]**
│   ├───[OR]─ **[HIGH-RISK PATH]** Lockfile Poisoning (yarn.lock Manipulation)
│   │   ├───[AND]─ **[CRITICAL NODE]** Gain access to repository (e.g., compromised CI/CD, developer machine, vulnerable Git server)
│   │   └───[AND]─ **[HIGH-RISK PATH]** Modify yarn.lock to point to malicious dependency versions **[CRITICAL NODE]**
│   ├───[OR]─ **[HIGH-RISK PATH]** Dependency Confusion Attack
│   │   └───[AND]─ **[HIGH-RISK PATH]** Application's Yarn configuration (e.g., misconfigured registries) prioritizes public registry over private, or no private registry configured. **[CRITICAL NODE]**
│   ├───[OR]─ **[HIGH-RISK PATH]** Compromised Upstream Dependency
│   │   └───[AND]─ Identify vulnerable or malicious upstream dependency used by the application (directly or transitively) **[CRITICAL NODE]**
│   └───[OR]─ Typosquatting Attack (This path is considered lower risk compared to others, but included as part of Supply Chain)
│       └───[AND]─ Developer makes a typo in `package.json` or during `yarn add`
├───[OR]─ **[HIGH-RISK PATH]** Configuration Exploitation (.yarnrc.yml Manipulation) **[CRITICAL NODE]**
│   ├───[AND]─ **[CRITICAL NODE]** Gain access to repository or deployment environment (e.g., compromised CI/CD, developer machine, vulnerable server)
│   ├───[AND]─ **[HIGH-RISK PATH]** Modify `.yarnrc.yml` to introduce malicious configurations **[CRITICAL NODE]**
│   │   ├───[OR]─ **[HIGH-RISK PATH]** Modify `npmRegistryServer` to point to a malicious registry **[CRITICAL NODE]**
│   │   ├───[OR]─ **[HIGH-RISK PATH]** Disable integrity checks (e.g., `checksumVerification: false`) **[CRITICAL NODE]**
├───[OR]─ **[HIGH-RISK PATH]** PnP (Plug'n'Play) Specific Attacks (.pnp.cjs Manipulation) **[CRITICAL NODE]**
│   ├───[AND]─ **[CRITICAL NODE]** Gain write access to `.pnp.cjs` file (e.g., compromised CI/CD, developer machine, vulnerable server)
│   ├───[AND]─ **[HIGH-RISK PATH]** Modify `.pnp.cjs` to redirect package resolutions to malicious code **[CRITICAL NODE]**
│   │   ├───[OR]─ **[HIGH-RISK PATH]** Replace legitimate package paths with paths to malicious packages **[CRITICAL NODE]**
├───[OR]─ **[HIGH-RISK PATH]** Script-Based Attacks (package.json scripts) **[CRITICAL NODE]**
│   ├───[AND]─ **[CRITICAL NODE]** Identify vulnerable or exploitable lifecycle scripts in `package.json` (e.g., `postinstall`, `preinstall`, `prepare`) of dependencies or application itself.
│   ├───[AND]─ Trigger script execution (e.g., during `yarn install`, `yarn add`, `yarn build`)
│   │   ├───[OR]─ **[HIGH-RISK PATH]** Dependency installation (malicious dependency with harmful scripts) **[CRITICAL NODE]**


## Attack Tree Path: [1. Supply Chain Attack (Dependency Manipulation) [CRITICAL NODE & HIGH-RISK PATH]](./attack_tree_paths/1__supply_chain_attack__dependency_manipulation___critical_node_&_high-risk_path_.md)

*   **Attack Vector:** Exploiting the trust relationship in the software supply chain to inject malicious code into the application's dependencies. This is a high-risk path because it targets a fundamental aspect of modern development and can have widespread impact.
*   **High-Risk because:**
    *   **Likelihood:** Medium to High - Supply chain attacks are increasingly common and automated tools can aid in their execution.
    *   **Impact:** High - Successful attacks can lead to full application compromise, data breaches, and long-term persistence.
*   **Critical Nodes within this path:**
    *   **Supply Chain Attack (Dependency Manipulation):** The overall category, representing a major attack surface.
    *   **Lockfile Poisoning (yarn.lock Manipulation):**  Directly manipulating the lockfile to control dependency versions.
    *   **Application's Yarn configuration (e.g., misconfigured registries) prioritizes public registry over private, or no private registry configured.:** Misconfiguration can enable dependency confusion attacks.
    *   **Compromised Upstream Dependency:**  Relying on vulnerable or malicious packages from upstream sources.
*   **Mitigation Strategies:**
    *   Implement robust lockfile integrity checks (`yarn install --check-files`).
    *   Regularly audit dependencies for vulnerabilities using `yarn audit` and SCA tools.
    *   Utilize private registries for internal packages and configure Yarn appropriately.
    *   Use scoped packages to manage package origins.
    *   Implement registry policies using `yarn policies` to restrict allowed sources.
    *   Pin dependency versions and rely on `yarn.lock`.
*   **Attacker Skill Level:** Low to Medium (depending on the specific attack type within supply chain).
*   **Attacker Effort:** Low to Medium (depending on the specific attack type within supply chain).
*   **Detection Difficulty:** Medium (requires proactive monitoring and security tools).

## Attack Tree Path: [2. Lockfile Poisoning (yarn.lock Manipulation) [HIGH-RISK PATH]](./attack_tree_paths/2__lockfile_poisoning__yarn_lock_manipulation___high-risk_path_.md)

*   **Attack Vector:** Gaining unauthorized access to the repository (or CI/CD pipeline) and modifying the `yarn.lock` file to point to malicious dependency versions.
*   **High-Risk because:**
    *   **Likelihood:** Medium - Requires repository access, but this can be achieved through various means (compromised credentials, vulnerable systems, insider threats).
    *   **Impact:** High - Malicious packages installed during `yarn install` can execute arbitrary code.
*   **Critical Nodes within this path:**
    *   **Gain access to repository (e.g., compromised CI/CD, developer machine, vulnerable Git server):**  The initial access point enabling the attack.
    *   **Modify yarn.lock to point to malicious dependency versions:** The direct action that leads to malicious code execution.
*   **Mitigation Strategies:**
    *   Strong access control for repositories and CI/CD pipelines.
    *   Multi-factor authentication for repository access.
    *   Code review of all `yarn.lock` changes.
    *   Automated lockfile integrity checks in CI/CD (`yarn install --check-files`).
    *   Secure CI/CD pipeline configurations.
*   **Attacker Skill Level:** Low to Medium (requires basic repository access and file manipulation).
*   **Attacker Effort:** Low to Medium (depending on the difficulty of gaining repository access).
*   **Detection Difficulty:** Medium (lockfile integrity checks are effective, manual review is harder).

## Attack Tree Path: [3. Dependency Confusion Attack [HIGH-RISK PATH]](./attack_tree_paths/3__dependency_confusion_attack__high-risk_path_.md)

*   **Attack Vector:** Exploiting misconfigurations in Yarn's registry resolution to trick it into installing malicious public packages instead of intended private packages with the same name.
*   **High-Risk because:**
    *   **Likelihood:** Medium - Relies on configuration errors, which are common, and automated tools can facilitate the attack.
    *   **Impact:** High - Installation of malicious public packages can lead to code execution and application compromise.
*   **Critical Nodes within this path:**
    *   **Application's Yarn configuration (e.g., misconfigured registries) prioritizes public registry over private, or no private registry configured.:** The vulnerable configuration that enables the attack.
*   **Mitigation Strategies:**
    *   Properly configure private registries in `.yarnrc.yml` and ensure they are prioritized.
    *   Use scoped packages for internal packages to avoid naming conflicts.
    *   Verify package origins during development and deployment.
    *   Consider using `yarn policies` to restrict allowed registries.
*   **Attacker Skill Level:** Low (requires basic understanding of package registries).
*   **Attacker Effort:** Low (publishing packages to public registries is easy).
*   **Detection Difficulty:** Medium (requires monitoring package installation sources and configurations).

## Attack Tree Path: [4. Configuration Exploitation (.yarnrc.yml Manipulation) [CRITICAL NODE & HIGH-RISK PATH]](./attack_tree_paths/4__configuration_exploitation___yarnrc_yml_manipulation___critical_node_&_high-risk_path_.md)

*   **Attack Vector:** Gaining unauthorized access to the repository or deployment environment and modifying the `.yarnrc.yml` file to introduce malicious configurations.
*   **High-Risk because:**
    *   **Likelihood:** Medium - Requires repository/environment access, but this is a common target for attackers.
    *   **Impact:** High - Modifying `.yarnrc.yml` can compromise the entire package installation process and application behavior.
*   **Critical Nodes within this path:**
    *   **.yarnrc.yml Manipulation:** The overall category, representing a critical configuration file.
    *   **Gain access to repository or deployment environment (e.g., compromised CI/CD, developer machine, vulnerable server):** The initial access point.
    *   **Modify `.yarnrc.yml` to introduce malicious configurations:** The action of altering the configuration.
    *   **Modify `npmRegistryServer` to point to a malicious registry:**  Directly controlling package sources.
    *   **Disable integrity checks (e.g., `checksumVerification: false`):**  Bypassing security measures.
*   **Mitigation Strategies:**
    *   Restrict write access to `.yarnrc.yml` to authorized personnel and processes.
    *   Code review all changes to `.yarnrc.yml`.
    *   Use environment variables for sensitive configurations instead of hardcoding in `.yarnrc.yml`.
    *   Implement configuration policies using `yarn policies` to enforce secure settings.
    *   Monitor `.yarnrc.yml` for unauthorized changes.
*   **Attacker Skill Level:** Low to Medium (requires basic file manipulation and understanding of `.yarnrc.yml`).
*   **Attacker Effort:** Low to Medium (depending on the difficulty of gaining repository/environment access).
*   **Detection Difficulty:** Medium (requires configuration monitoring and change management).

## Attack Tree Path: [5. PnP (Plug'n'Play) Specific Attacks (.pnp.cjs Manipulation) [CRITICAL NODE & HIGH-RISK PATH]](./attack_tree_paths/5__pnp__plug'n'play__specific_attacks___pnp_cjs_manipulation___critical_node_&_high-risk_path_.md)

*   **Attack Vector:** Exploiting the PnP feature by gaining write access to the `.pnp.cjs` file and modifying it to redirect module resolutions to malicious code.
*   **High-Risk because:**
    *   **Likelihood:** Medium - Requires write access to `.pnp.cjs`, which is often present in development and potentially in compromised deployment environments.
    *   **Impact:** High - Modifying `.pnp.cjs` can lead to code execution whenever modules are required by the application.
*   **Critical Nodes within this path:**
    *   **.pnp.cjs Manipulation:** The overall category, targeting the core PnP resolution mechanism.
    *   **Gain write access to `.pnp.cjs` file (e.g., compromised CI/CD, developer machine, vulnerable server):** The initial access point.
    *   **Modify `.pnp.cjs` to redirect package resolutions to malicious code:** The action of altering module resolution.
    *   **Replace legitimate package paths with paths to malicious packages:** A specific method of malicious modification.
*   **Mitigation Strategies:**
    *   File integrity monitoring for `.pnp.cjs` to detect unauthorized changes.
    *   Restrict write access to `.pnp.cjs` in production environments.
    *   Secure CI/CD pipelines to prevent modification during build processes.
    *   Consider immutable deployments to prevent runtime modifications.
*   **Attacker Skill Level:** Medium (requires understanding of PnP and file manipulation).
*   **Attacker Effort:** Medium (depending on the difficulty of gaining write access and understanding `.pnp.cjs` structure).
*   **Detection Difficulty:** High (`.pnp.cjs` is complex, manual review is very difficult, runtime behavior monitoring is crucial).

## Attack Tree Path: [6. Script-Based Attacks (package.json scripts) [CRITICAL NODE & HIGH-RISK PATH]](./attack_tree_paths/6__script-based_attacks__package_json_scripts___critical_node_&_high-risk_path_.md)

*   **Attack Vector:** Exploiting lifecycle scripts (e.g., `postinstall`, `preinstall`) in `package.json` of dependencies or the application itself to execute malicious code.
*   **High-Risk because:**
    *   **Likelihood:** Medium - Vulnerable scripts are common, especially in older or less maintained packages, and can be easily triggered during package installation.
    *   **Impact:** High - Script execution can lead to arbitrary code execution with the privileges of the user running `yarn install`.
*   **Critical Nodes within this path:**
    *   **Script-Based Attacks (package.json scripts):** The overall category, targeting a common feature of Node.js projects.
    *   **Identify vulnerable or exploitable lifecycle scripts in `package.json` (e.g., `postinstall`, `preinstall`, `prepare`) of dependencies or application itself.:**  Finding the vulnerable scripts.
    *   **Dependency installation (malicious dependency with harmful scripts):** A common scenario where malicious scripts are introduced.
*   **Mitigation Strategies:**
    *   Disable or restrict script execution using `yarn config set enableScripts false` (if feasible).
    *   Audit and review scripts in `package.json` of both application and dependencies.
    *   Use sandboxing or containerization to limit the impact of script execution.
    *   Implement Content Security Policy (CSP) for web applications to mitigate browser-based script attacks (though less relevant to Yarn itself, but important for web apps in general).
*   **Attacker Skill Level:** Low to Medium (requires basic scripting knowledge and understanding of lifecycle scripts).
*   **Attacker Effort:** Low to Medium (finding vulnerable scripts can be automated, creating malicious packages is easy).
*   **Detection Difficulty:** Medium (script analysis tools and runtime behavior monitoring can help).

