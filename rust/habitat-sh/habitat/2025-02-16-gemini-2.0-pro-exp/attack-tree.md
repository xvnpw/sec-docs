# Attack Tree Analysis for habitat-sh/habitat

Objective: Gain Unauthorized Privileged Access/Disrupt Service (via Habitat-specific vulnerabilities)

## Attack Tree Visualization

```
                                     +-----------------------------------------------------+
                                     |  Gain Unauthorized Privileged Access/Disrupt Service |
                                     +-----------------------------------------------------+
                                                        |
          +-------------------------------------------------------------------------+
          |                                                |                        |
+-------------------------+                 +-----------------------------+
| Exploit Supervisor Vulns |                 |  Manipulate Package/Artifact |
+-------------------------+                 +-----------------------------+
          |                                                |
+---------+---------+                      +---------+---------+---------+
|  CVEs   |  Bugs   |                      |  Origin |  Channel|  Build  |
| (Known) | (0-day) |                      | Key Cmp |  Poison |  Script |
+---------+---------+                      +---------+---------+---------+
                            [CRITICAL]
```

## Attack Tree Path: [Exploit Supervisor Vulnerabilities (High-Risk Path)](./attack_tree_paths/exploit_supervisor_vulnerabilities__high-risk_path_.md)

   *   **Description:** The Habitat Supervisor is the core process managing the application's lifecycle. Vulnerabilities here are extremely impactful, potentially granting an attacker control over the application and potentially the host.

   *   **1.1 CVEs (Known Vulnerabilities) (High-Risk)**

      *   **Description:** Publicly disclosed vulnerabilities with assigned CVE identifiers. Attackers can search for known Habitat Supervisor CVEs and leverage existing exploits.
      *   **Likelihood:** Medium to High (Depends on patching frequency. Higher if patching is infrequent.)
      *   **Impact:** Very High (Supervisor compromise often leads to full system control.)
      *   **Effort:** Low to Medium (Exploits for known CVEs are often publicly available.)
      *   **Skill Level:** Novice to Intermediate (Script kiddies can use pre-made exploits.)
      *   **Detection Difficulty:** Medium to Hard (IDS/IPS *might* detect known exploit signatures, but sophisticated attackers can often bypass them. Log analysis is crucial.)
      *   **Mitigation:**
          *   Regularly update the Habitat Supervisor to the latest version.
          *   Monitor Habitat security advisories and CVE databases.
          *   Implement a robust patching process.
          *   Consider using a vulnerability scanner that specifically checks for Habitat vulnerabilities.

   *   **1.2 Bugs (0-day Vulnerabilities) (High-Risk)**

      *   **Description:** Undiscovered vulnerabilities that an attacker might find and exploit before the vendor or community is aware.
      *   **Likelihood:** Low to Medium (Finding 0-days requires significant skill or luck.)
      *   **Impact:** Very High (Same as CVEs – Supervisor compromise.)
      *   **Effort:** High to Very High (Requires vulnerability research or purchase from the black market.)
      *   **Skill Level:** Advanced to Expert (Requires deep understanding of Habitat Supervisor internals.)
      *   **Detection Difficulty:** Very Hard (By definition, 0-days are unknown. Relies on anomaly detection and behavioral analysis.)
      *   **Mitigation:**
          *   Run the Habitat Supervisor with the *absolute minimum* necessary privileges (not as root).
          *   Isolate the application and Supervisor using network segmentation.
          *   Deploy IDS/IPS to monitor for suspicious activity.
          *   Regularly audit the Supervisor's configuration and logs.
          *   Consider using RASP technologies.
          *   (If resources allow) Fuzz the Habitat Supervisor.

## Attack Tree Path: [Manipulate Package/Artifact (High-Risk Path)](./attack_tree_paths/manipulate_packageartifact__high-risk_path_.md)

   *   **Description:** Habitat packages (artifacts) are the core units of deployment. Compromising a package allows an attacker to inject malicious code that will be executed by the Supervisor.

   *   **2.1 Origin Key Compromise `[CRITICAL]` (High-Risk, Critical Node)**

      *   **Description:** Habitat uses cryptographic keys to sign packages. If an attacker gains control of an origin's private key, they can sign malicious packages that will be trusted by the Supervisor. This is a single point of failure.
      *   **Likelihood:** Low to Medium (Depends heavily on key management practices.)
      *   **Impact:** Very High (Attacker can sign and distribute malicious packages as if they were legitimate.)
      *   **Effort:** Medium to High (Requires gaining access to the key, which should be well-protected.)
      *   **Skill Level:** Intermediate to Advanced (Depends on security measures. Bypassing HSMs requires advanced skills.)
      *   **Detection Difficulty:** Hard to Very Hard (Requires monitoring key usage and detecting unauthorized signing. Compromise might not be immediately obvious.)
      *   **Mitigation:**
          *   Store origin keys in HSMs whenever possible.
          *   Use strong, unique passphrases.
          *   Regularly rotate origin keys.
          *   Strictly limit access to origin keys. Use multi-factor authentication.
          *   Perform package signing in an offline, air-gapped environment.
          *   Implement monitoring to detect unauthorized use of origin keys.

   *   **2.2 Channel Poisoning (High-Risk)**

      *   **Description:**  An attacker compromises a Habitat channel (e.g., by gaining access to the Builder service) and uploads malicious packages.
      *   **Likelihood:** Low to Medium (Depends on the security of the Habitat Builder and channel infrastructure.)
      *   **Impact:** High (Many users could download and run malicious packages.)
      *   **Effort:** Medium to High (Requires compromising the Builder or channel infrastructure.)
      *   **Skill Level:** Intermediate to Advanced (Requires understanding of Habitat Builder and potentially exploiting vulnerabilities in it.)
      *   **Detection Difficulty:** Medium to Hard (Requires monitoring channel contents and comparing checksums. Might be detected by users noticing unexpected package updates.)
      *   **Mitigation:**
          *   Pin your application to *specific* package versions.
          *   Harden the Habitat Builder extensively if you run your own.
          *   Implement monitoring to detect unexpected changes in channels.

   *   **2.3 Build Script Compromise (High-Risk)**

      *   **Description:** The `plan.sh` file within a Habitat package defines the build process. An attacker modifies this script to inject malicious code.
      *   **Likelihood:** Medium (Depends on source code repository security and code review practices.)
      *   **Impact:** High (Malicious code injected into the build process can compromise the resulting package.)
      *   **Effort:** Low to Medium (If source code repositories are poorly secured, this is relatively easy.)
      *   **Skill Level:** Intermediate (Requires understanding of Habitat build scripts and how to inject malicious code.)
      *   **Detection Difficulty:** Medium (Code reviews and static analysis *can* detect malicious code, but it's not foolproof.)
      *   **Mitigation:**
          *   Protect source code repositories with strong access controls and multi-factor authentication.
          *   Implement mandatory code reviews for all changes to `plan.sh` files.
          *   Run the Habitat build process in an isolated environment.
          *   Use static analysis tools to scan `plan.sh` files.

