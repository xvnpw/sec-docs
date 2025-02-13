# Attack Tree Analysis for yarnpkg/berry

Objective: Execute Arbitrary Code via Yarn Berry

## Attack Tree Visualization

```
                                     [***Attacker's Goal: Execute Arbitrary Code via Yarn Berry***]
                                                    |
                                                    |
        =========================================================================================
        ||                                                                                      ||
[1. Compromise via Malicious Package]                                   [3. Leverage Misconfigurations/Poor Practices]
        ||                                                                                      ||
        ||---------------------------------                                             =================================
        ||                                                                                      ||
        ||
[***1.2 Typosquatting***]                                                     [***3.1 Unsafe .yarnrc.yml Settings***]
[***Attack:          ***]                                                     [***e.g., enableScripts: true***]
  [***Publish a         ***]
  [***package with      ***]
  [***a name similar    ***]
  [***to a popular      ***]
  [***package,          ***]
  [***hoping users      ***]
  [***will install it   ***]
  [***by mistake]       ***]
]
```

## Attack Tree Path: [1. Compromise via Malicious Package -> 1.2 Typosquatting](./attack_tree_paths/1__compromise_via_malicious_package_-_1_2_typosquatting.md)

*   **Description:** This attack vector relies on the attacker publishing a malicious package to a public registry (like npm) with a name that is intentionally very similar to a popular, legitimate package. The attacker hopes that users will make a typographical error when installing the package and accidentally install the malicious version.
*   **Critical Node:** The attack itself (publishing the typosquatting package) is the critical node. Success here directly leads to the potential for arbitrary code execution if a user installs the malicious package.
*   **Attack Steps:**
    1.  **Identify Target Package:** The attacker researches popular packages with high download counts.
    2.  **Choose a Similar Name:** The attacker creates a package name that is a slight variation of the target package name (e.g., `reacct` instead of `react`, `color-pickerjs` instead of `colorpickerjs`).
    3.  **Develop Malicious Payload:** The attacker crafts a malicious payload, often embedded within a `postinstall` script (if `enableScripts` is true) or other lifecycle scripts. This payload could do anything from stealing credentials to installing malware.
    4.  **Publish the Package:** The attacker publishes the malicious package to the public registry.
    5.  **Wait for Victims:** The attacker waits for users to accidentally install the malicious package due to a typo.
*   **Likelihood:** High. Creating and publishing a package is easy, and typos are common.
*   **Impact:** Very High. Arbitrary code execution on the developer's machine or build server.
*   **Effort:** Low. Minimal coding is required; the main effort is in choosing a convincing name.
*   **Skill Level:** Low. Basic package publishing knowledge is sufficient.
*   **Detection Difficulty:** Medium. Relies on developers noticing the incorrect package name or using tools that detect typosquatting. Can be high if the typo is very subtle.
*   **Mitigation:**
    *   **Careful Package Installation:** Double-check package names before installing.
    *   **Typosquatting Detection Tools:** Use tools that scan for potential typosquatting attempts.
    *   **Package Scopes:** Use scoped packages (@scope/package-name) to reduce the risk, although this doesn't eliminate it entirely.
    *   **Internal Registries:** Use private, internal registries for internal packages to prevent confusion with public packages.

## Attack Tree Path: [3. Leverage Misconfigurations/Poor Practices -> 3.1 Unsafe .yarnrc.yml Settings (e.g., enableScripts: true)](./attack_tree_paths/3__leverage_misconfigurationspoor_practices_-_3_1_unsafe__yarnrc_yml_settings__e_g___enablescripts_t_2cc9c7f9.md)

*   **Description:** This attack vector exploits a misconfiguration in Yarn Berry's `.yarnrc.yml` file. Specifically, setting `enableScripts: true` allows *any* package (including dependencies of dependencies) to execute arbitrary code during installation via lifecycle scripts (like `postinstall`). This is a *very* dangerous setting and should be avoided unless absolutely necessary.
*   **Critical Node:** The `enableScripts: true` setting itself is the critical node. It's the single point of failure that enables this attack.
*   **Attack Steps (from the attacker's perspective - they don't *do* anything, they just benefit):**
    1.  **(Attacker's Perspective):** Publish a malicious package (this could be a direct supply chain attack, typosquatting, or dependency confusion). The package contains a `postinstall` (or other lifecycle) script with malicious code.
    2.  **(Developer's Action - Misconfiguration):** A developer, unaware of the risks, sets `enableScripts: true` in their project's `.yarnrc.yml` file.
    3.  **(Developer's Action - Installation):** The developer installs a package (either directly or as a dependency) that, directly or indirectly, depends on the attacker's malicious package.
    4.  **(Automatic Execution):** Yarn Berry, due to the `enableScripts: true` setting, executes the malicious `postinstall` script.
    5.  **(Compromise):** The attacker's code is executed, achieving their goal.
*   **Likelihood:** High. This misconfiguration is unfortunately common.
*   **Impact:** Very High. Allows arbitrary code execution from *any* dependency.
*   **Effort:** Very Low (for the attacker). The attacker simply needs to publish a malicious package; they don't need to actively exploit anything.
*   **Skill Level:** Very Low (for the attacker).
*   **Detection Difficulty:** Low (if you check the `.yarnrc.yml` file). However, it requires proactive checking, and many developers are unaware of the risk.
*   **Mitigation:**
    *   **Disable `enableScripts`:** Set `enableScripts: false` in `.yarnrc.yml`. This is the primary and most effective mitigation.
    *   **If Scripts are Necessary:** If scripts *must* be enabled, use the `supportedArchitectures`, `supportedCPU`, and `supportedOS` settings to restrict the execution environment.  Also, *thoroughly* audit *every* package that uses lifecycle scripts. This is a very high-effort, high-risk approach.
    *   **Yarn Policies:** Use Yarn's policy features (if available and applicable) to enforce restrictions on script execution.
    * **Code Review:** Include `.yarnrc.yml` configuration in code reviews.

