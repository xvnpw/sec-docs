# Attack Surface Analysis for microsoft/vcpkg

## Attack Surface: [Compromised Upstream Dependency](./attack_surfaces/compromised_upstream_dependency.md)

*   **Description:** A malicious actor gains control of an upstream repository (e.g., a GitHub repository) hosting a library used by your project. The attacker modifies the library's source code to include malicious functionality.
*   **How vcpkg Contributes:** `vcpkg` *directly* downloads and builds code from these upstream repositories, acting as the *primary* conduit for the compromised code to enter your application's build process.  This is the core of the supply chain risk.
*   **Example:** An attacker compromises the repository for a widely-used JSON parsing library and injects code that sends parsed data to an attacker-controlled server.  `vcpkg` downloads and builds this compromised library, integrating the malicious code into your application.
*   **Impact:** Code execution, data exfiltration, system compromise, privilege escalation. The impact is broad and depends on the nature of the injected code.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Dependency Vetting:** Rigorously research and select well-established, actively maintained libraries with a strong security history.  Prioritize libraries with frequent security audits.
    *   **Version Pinning (with Baselines):** Use specific version numbers (e.g., `library#1.2.3`) in your `vcpkg.json` (manifest mode).  Leverage `vcpkg`'s baselines feature for consistent and controlled versioning across your projects and teams.  This prevents automatic updates to potentially compromised versions.
    *   **Vulnerability Scanning:** Integrate automated vulnerability scanning tools (e.g., Snyk, Dependabot, OWASP Dependency-Check) into your CI/CD pipeline.  These tools can detect known vulnerabilities in your dependencies *before* they are deployed.
    *   **Monitor Security Advisories:** Actively monitor security mailing lists, vulnerability databases (e.g., CVE), and news sources related to your dependencies.  Be prepared to react quickly to newly discovered vulnerabilities.

## Attack Surface: [Typosquatting/Name Confusion](./attack_surfaces/typosquattingname_confusion.md)

*   **Description:** An attacker creates a malicious package with a name deceptively similar to a legitimate package, hoping developers will accidentally install the malicious one.
*   **How vcpkg Contributes:** `vcpkg`'s package search and installation mechanism, while convenient, can be exploited if a developer makes a typographical error or is misled by a similar name.  `vcpkg` is the *direct* tool used to install the malicious package.
*   **Example:** An attacker publishes a package named `libcur1` (note the `1` instead of `l`), mimicking the legitimate `libcurl` package. A developer mistyping the name during installation via `vcpkg install libcur1` would install the malicious package.
*   **Impact:** Code execution, data exfiltration, system compromise – the same broad impact as a compromised upstream dependency.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Careful Package Name Verification:**  Meticulously double-check package names *before* executing any `vcpkg install` command.  Pay extreme attention to spelling, capitalization, and special characters.
    *   **Use Manifest Mode (vcpkg.json):**  Always use `vcpkg.json` (manifest mode) to explicitly list your dependencies and their exact versions.  This eliminates the need to type package names during installation, significantly reducing the risk of typos.
    *   **Automated Checks (Pre-Commit Hooks):**  Consider implementing pre-commit hooks or other automated checks in your development workflow that analyze your `vcpkg.json` for potential typosquatting attempts (e.g., by comparing package names against a list of known legitimate packages).

## Attack Surface: [Malicious Portfile](./attack_surfaces/malicious_portfile.md)

*   **Description:** The `portfile.cmake` (and related files) within a `vcpkg` port contains malicious build instructions, designed to compromise the build process or the resulting binary.
*   **How vcpkg Contributes:** `vcpkg` *directly* executes the instructions contained within the portfile during the build process.  The portfile is the *mechanism* by which malicious code is introduced.
*   **Example:** A compromised portfile for a cryptography library could include a build step that downloads and executes a script from an attacker-controlled server, or it could subtly modify compiler flags to weaken the cryptographic algorithms.
*   **Impact:** Code execution on the build machine, system compromise, weakened security of the built library (potentially bypassing intended security features).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Sandboxing:** Run `vcpkg` build processes within a strictly isolated environment (e.g., a container with minimal privileges and network access). This contains the impact of a malicious portfile, preventing it from compromising the host system.
    *   **Rely on the vcpkg Community:** The `vcpkg` community and maintainers actively work to identify and remove malicious portfiles.  Prioritize using ports from the official `vcpkg` registry.
    *   **Report Suspicious Portfiles:** If you encounter a portfile that appears suspicious or exhibits unusual behavior, report it immediately to the `vcpkg` maintainers.

## Attack Surface: [Compromised Binary Cache](./attack_surfaces/compromised_binary_cache.md)

*   **Description:** An attacker gains unauthorized access to the `vcpkg` binary cache and replaces legitimate pre-built binaries with maliciously crafted versions.
*   **How vcpkg Contributes:** `vcpkg` *directly* uses the binary cache to retrieve and install pre-built binaries, making it the *direct* pathway for compromised binaries to be introduced.
*   **Example:** An attacker compromises a shared binary cache server and replaces the pre-built binary for a networking library with a version containing a backdoor that allows remote access.
*   **Impact:** Code execution, system compromise, data exfiltration – the same broad impact as a compromised upstream dependency.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Cache Location:** Use a *highly* secure and trusted location for your binary cache.  This should be a private server or a reputable cloud storage service with *strict* access controls.
    *   **Strong Authentication and Authorization:** Implement robust authentication and authorization mechanisms for your binary cache to prevent unauthorized access and modification.
    *   **Binary Verification (x-hashes):**  *Always* use `vcpkg`'s `x-hashes` feature to cryptographically verify the integrity of downloaded binaries.  This involves specifying the expected SHA-512 hash of the binary in the portfile or triplet file.  `vcpkg` will then verify the downloaded binary against this hash, ensuring it hasn't been tampered with. This is a *critical* mitigation.

