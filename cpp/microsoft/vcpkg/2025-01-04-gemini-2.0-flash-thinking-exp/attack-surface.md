# Attack Surface Analysis for microsoft/vcpkg

## Attack Surface: [Compromised Dependency Source](./attack_surfaces/compromised_dependency_source.md)

**Description:** Attackers compromise upstream dependency repositories (e.g., GitHub) to inject malicious code into the source code or build scripts of a library.

**How vcpkg contributes to the attack surface:** vcpkg fetches source code and build instructions directly from these repositories based on the information in the portfile. It trusts the integrity of the source at the defined location.

**Example:** An attacker gains access to the GitHub repository of a popular library and adds a backdoor. When vcpkg builds this library for your project, the backdoor is included in the final application.

**Impact:** Code execution within the application, data breaches, supply chain compromise affecting downstream users of your application.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Verify checksums/hashes of downloaded sources if provided and supported by vcpkg.
* Utilize dependency scanning tools that can identify known vulnerabilities in dependencies.
* Pin dependency versions in `vcpkg.json` to avoid automatically pulling in potentially compromised updates.
* Favor dependencies with strong security practices and active maintainership.
* Consider using a private, curated registry for dependencies if security is paramount.

## Attack Surface: [Malicious Portfile/Build Script](./attack_surfaces/malicious_portfilebuild_script.md)

**Description:** Attackers create or modify vcpkg portfiles to execute arbitrary code during the build process. This can include downloading additional malicious payloads, modifying build outputs, or exfiltrating data.

**How vcpkg contributes to the attack surface:** vcpkg executes the commands defined within the portfile to download, configure, build, and install the dependency. If a portfile is malicious, vcpkg will execute the harmful commands.

**Example:** A compromised portfile for a seemingly harmless library includes a command to download and execute a script that installs a backdoor on the build machine or modifies the compiled library with malicious code.

**Impact:** Compromise of the build environment, injection of malicious code into the application, exposure of build secrets.

**Risk Severity:** High

**Mitigation Strategies:**
* Carefully review portfiles, especially for less common or untrusted dependencies.
* Implement code review processes for changes to portfiles.
* Use a controlled and audited environment for building dependencies.
* Consider using a private, curated registry where portfiles are vetted.

## Attack Surface: [Vulnerabilities in vcpkg Itself](./attack_surfaces/vulnerabilities_in_vcpkg_itself.md)

**Description:** vcpkg, being a software tool, can have its own vulnerabilities that could be exploited by attackers.

**How vcpkg contributes to the attack surface:** Vulnerabilities in vcpkg could allow attackers to manipulate the dependency resolution process, inject malicious code, or gain access to the build environment through vcpkg's functionality.

**Example:** A vulnerability in vcpkg's handling of portfile parsing could be exploited by crafting a malicious portfile that triggers arbitrary code execution within the vcpkg process.

**Impact:** Compromise of the build environment, potential for injecting malicious code into built artifacts, denial of service.

**Risk Severity:** High

**Mitigation Strategies:**
* Keep vcpkg updated to the latest version to patch known vulnerabilities.
* Monitor security advisories related to vcpkg.
* Follow secure coding practices when contributing to or extending vcpkg.

