# Attack Surface Analysis for thoughtbot/bourbon

## Attack Surface: [Supply Chain Vulnerabilities](./attack_surfaces/supply_chain_vulnerabilities.md)

* **Description:** The Bourbon repository itself being compromised and malicious code being introduced.
    * **How Bourbon Contributes:** As a dependency, if the source is compromised, all applications using it are potentially at risk.
    * **Example:** A malicious actor gains access to the Bourbon GitHub repository and injects code into a new release.
    * **Impact:** Introduction of vulnerabilities (like indirect CSS injection or DoS) at scale to all applications using the compromised version.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Utilize package managers with integrity checks (e.g., `npm audit` with checksum verification).
        * Monitor the Bourbon repository for unusual activity or unauthorized changes.
        * Consider using dependency pinning or a private registry to control the source of dependencies.
        * Regularly review your project's dependencies and their sources.

