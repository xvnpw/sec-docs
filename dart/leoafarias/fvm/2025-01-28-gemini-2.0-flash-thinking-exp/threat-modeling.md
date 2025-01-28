# Threat Model Analysis for leoafarias/fvm

## Threat: [Compromised FVM Binary Download](./threats/compromised_fvm_binary_download.md)

Description: An attacker compromises the FVM distribution channel and replaces the legitimate FVM binary with a malicious one containing malware. Developers downloading FVM from the compromised source unknowingly install the malicious binary. Upon execution, the malware could steal credentials, inject code into projects, or compromise the developer's machine.
Impact: Full compromise of developer's machine, potential supply chain poisoning of applications, data breaches, reputational damage.
Affected FVM Component: FVM Installer/Binary Download Process
Risk Severity: Critical
Mitigation Strategies:
    * Verify the checksum of the downloaded FVM binary against the official checksum provided on the FVM GitHub repository.
    * Download FVM only from the official GitHub releases page: `https://github.com/leoafarias/fvm/releases`.
    * Use package managers with integrity verification features if available for FVM installation.
    * Consider using code signing verification if feasible to ensure binary authenticity.

## Threat: [Malicious Flutter SDK Download via FVM](./threats/malicious_flutter_sdk_download_via_fvm.md)

Description: An attacker compromises the source from which FVM downloads Flutter SDKs. FVM, instructed to download an SDK, retrieves a tampered SDK containing backdoors or malicious code. When developers build applications using this compromised SDK, the malware is incorporated into the final application.
Impact: Distribution of malware to end-users through applications, application vulnerabilities, reputational damage, legal liabilities, supply chain compromise.
Affected FVM Component: SDK Download Manager, SDK Version Handling
Risk Severity: High
Mitigation Strategies:
    * Ensure FVM is configured to download Flutter SDKs from official and trusted Google-controlled sources. Verify the download URLs used by FVM if possible.
    * Implement network monitoring to detect unusual network activity during SDK downloads by FVM.
    * Consider using a local, verified mirror of Flutter SDKs within a controlled environment if strict source control is necessary.
    * Regularly audit and verify the configured SDK download sources within FVM settings and configurations.

