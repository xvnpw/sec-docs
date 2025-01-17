# Attack Surface Analysis for microsoft/vcpkg

## Attack Surface: [Compromised Dependency Sources](./attack_surfaces/compromised_dependency_sources.md)

**Description:**  The risk of downloading dependencies from malicious or compromised sources.

**How vcpkg Contributes:** vcpkg fetches dependency source code from URLs specified in portfiles. If these URLs point to compromised repositories or are intercepted, malicious code can be introduced. vcpkg also supports custom registries, which, if not properly secured, can be a source of compromised dependencies.

**Example:** An attacker compromises a GitHub repository listed as a source in a vcpkg portfile. When a developer runs `vcpkg install`, the malicious code is downloaded and potentially built.

**Impact:**  Code execution on developer machines, supply chain compromise leading to vulnerabilities in the final application, data breaches.

**Risk Severity:** **Critical**

**Mitigation Strategies:**
* Specify Trusted and Verified vcpkg Registries.
* Enforce HTTPS for Git Operations and Dependency Downloads.
* Implement Checksum Verification (where possible).
* Regularly Audit Dependency Sources.

## Attack Surface: [Malicious Portfile Content](./attack_surfaces/malicious_portfile_content.md)

**Description:** The risk of portfiles containing malicious code that is executed during the build process.

**How vcpkg Contributes:** vcpkg relies on portfiles to define how dependencies are downloaded, built, and installed. Attackers could inject malicious commands or scripts into these portfiles.

**Example:** A compromised portfile contains a command that downloads and executes a malicious script during the `vcpkg install` process.

**Impact:** Code execution on developer machines, modification of build artifacts, exfiltration of sensitive information from the build environment.

**Risk Severity:** **High**

**Mitigation Strategies:**
* Review Portfile Changes Carefully.
* Use Static Analysis Tools on Portfiles.
* Limit Permissions of the Build Environment.
* Pin Dependency Versions.

## Attack Surface: [Insecure Handling of Credentials for Private Registries](./attack_surfaces/insecure_handling_of_credentials_for_private_registries.md)

**Description:** The risk of exposing credentials used to access private vcpkg registries.

**How vcpkg Contributes:**  Accessing private registries often requires authentication. If these credentials are stored insecurely or exposed, attackers can gain access to the private dependencies.

**Example:** Credentials for a private vcpkg registry are stored in plain text in a configuration file or environment variable that is committed to version control.

**Impact:** Unauthorized access to private dependencies, potential compromise of internal code and intellectual property, ability to inject malicious dependencies into the private registry.

**Risk Severity:** **High**

**Mitigation Strategies:**
* Use Secure Credential Management.
* Implement Role-Based Access Control.
* Regularly Rotate Credentials.

