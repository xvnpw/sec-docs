# Threat Model Analysis for progit/progit

## Threat: [Malicious Script Injection via Compromised Markdown Content](./threats/malicious_script_injection_via_compromised_markdown_content.md)

* **Threat:** Malicious Script Injection via Compromised Markdown Content
    * **Description:** An attacker gains control of the `progit/progit` repository and injects malicious JavaScript code within Markdown files. When the application renders this Markdown into HTML without proper sanitization, the malicious script executes in users' browsers.
    * **Impact:** Cross-Site Scripting (XSS) attacks, leading to session hijacking, cookie theft, redirection to malicious sites, or unauthorized actions on behalf of the user.
    * **Risk Severity:** High

## Threat: [Supply Chain Attack via Repository Maintainer Compromise](./threats/supply_chain_attack_via_repository_maintainer_compromise.md)

* **Threat:** Supply Chain Attack via Repository Maintainer Compromise
    * **Description:** An attacker compromises the accounts of legitimate maintainers of the `progit/progit` repository on GitHub and pushes malicious changes to the repository.
    * **Impact:** This can lead to any of the above threats (malicious script injection, malicious links, DoS), as the malicious changes would appear to come from a trusted source.
    * **Risk Severity:** High

