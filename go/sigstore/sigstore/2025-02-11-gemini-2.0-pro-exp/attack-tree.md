# Attack Tree Analysis for sigstore/sigstore

Objective: To forge a valid signature for a malicious artifact (e.g., container image, software package, release binary) and have the application accept it as legitimate, leading to the execution of malicious code or the use of a compromised artifact.

## Attack Tree Visualization

                                     Forge Valid Signature for Malicious Artifact
                                                    |
        -------------------------------------------------------------------------
        |                                                                       |
  Compromise Fulcio (Root CA) [CRITICAL]                                Compromise Rekor (Transparency Log)
        |                                                                       |
-----------------------------                                       ---------------------------------------
|                           |                                       |                     |
Key Compromise [CRITICAL]   Issue  Malicious               ===>     Poison the Log     Tamper with
(Private Key Theft,          Certificate                               (Add entries for   Existing Entries
Hardware Failure, etc.)      (Social Eng.,                               malicious          (Modify/Delete
                             Exploit Fulcio)                             artifacts)          valid entries)
-----------------------------                                       ---------------------------------------
        |
  ---------------------
  |                   |
OSI/Supply Chain  Direct Access
Compromise        (Insider Threat,
(e.g., GitHub     Physical Access)
Actions, etc.)

## Attack Tree Path: [1. Compromise Fulcio (Root CA) [CRITICAL]](./attack_tree_paths/1__compromise_fulcio__root_ca___critical_.md)

*   **Description:** Gaining control over Fulcio, Sigstore's root certificate authority, allowing the attacker to issue certificates trusted by Sigstore. This is a critical node because it undermines the entire trust model.

   *   **1.a Key Compromise [CRITICAL]**
        *   **Description:** Obtaining Fulcio's private signing key. This is the most direct and impactful attack.
        *   **Methods:**
            *   **Private Key Theft:** Stealing the key from storage (e.g., server breach, compromised HSM).
            *   **Hardware Failure:** Exploiting a hardware failure in the key storage device.
            *   **Insider Threat:** A malicious insider with access to the key.
            *   **Cryptographic Weakness:** Exploiting a weakness in the key generation or storage algorithm (extremely unlikely with modern cryptography, but theoretically possible).
        *   **Likelihood:** Low
        *   **Impact:** Very High
        *   **Effort:** Very High
        *   **Skill Level:** Expert
        *   **Detection Difficulty:** Hard

   *   **1.b Issue Malicious Certificate**
        *   **Description:** Tricking Fulcio into issuing a certificate for an identity the attacker controls, without directly compromising the private key.
        *   **Methods:**
            *   **Social Engineering:** Tricking an authorized user or administrator into issuing a certificate for the attacker.
            *   **Exploit Fulcio:** Exploiting a vulnerability in Fulcio's issuance process (e.g., a code injection flaw, a bypass of authentication checks).
            *   **Compromise OIDC Provider:** If Fulcio relies on an OIDC provider for authentication, compromising the OIDC provider could allow the attacker to impersonate a legitimate user.
        *   **Likelihood:** Medium
        *   **Impact:** High
        *   **Effort:** Medium to High
        *   **Skill Level:** Advanced
        *   **Detection Difficulty:** Medium

   * **1.c OSI/Supply Chain Compromise (Fulcio)**
        * **Description:** Compromising the infrastructure or build process of Fulcio itself.
        * **Methods:**
            *   **Compromised GitHub Action:** Injecting malicious code into a GitHub Action used to build or deploy Fulcio.
            *   **Dependency Compromise:** Introducing a malicious dependency into Fulcio's codebase.
            *   **Compromised Build Server:** Gaining control of the server used to build Fulcio.
        *   **Likelihood:** Low
        *   **Impact:** Very High
        *   **Effort:** Very High
        *   **Skill Level:** Expert
        *   **Detection Difficulty:** Hard

   * **1.d Direct Access (Insider Threat, Physical Access) (Fulcio)**
        * **Description:** Gaining direct access to Fulcio's infrastructure.
        * **Methods:**
            *   **Insider Threat:** A malicious insider with physical or logical access to Fulcio's servers.
            *   **Physical Access:** Gaining physical access to Fulcio's servers and bypassing security controls.
        *   **Likelihood:** Very Low
        *   **Impact:** Very High
        *   **Effort:** Very High
        *   **Skill Level:** Expert
        *   **Detection Difficulty:** Very Hard

## Attack Tree Path: [2. Compromise Rekor (Transparency Log)](./attack_tree_paths/2__compromise_rekor__transparency_log_.md)

*   **Description:** Manipulating Rekor, Sigstore's transparency log, to make malicious artifacts appear legitimately signed or to hide evidence of malicious activity.

   *   **2.a Poison the Log**
        *   **Description:** Adding entries to Rekor that falsely claim a malicious artifact has been signed by a legitimate key.
        *   **Methods:**
            *   **Compromised Key:** Using a compromised key (obtained through other means, such as compromising a user's signing key) to sign the malicious artifact and then submit the signature to Rekor.
            *   **Exploit Rekor:** Exploiting a vulnerability in Rekor's entry submission process (e.g., a code injection flaw, a bypass of validation checks).
        *   **Likelihood:** Medium
        *   **Impact:** High
        *   **Effort:** Medium to High
        *   **Skill Level:** Advanced
        *   **Detection Difficulty:** Medium

   *   **2.b Tamper with Existing Entries**
        *   **Description:** Modifying or deleting existing, valid entries in Rekor. This could make legitimate artifacts appear untrustworthy.
        *   **Methods:**
             * **Exploiting Vulnerabilities:** Finding and exploiting vulnerabilities that allow for unauthorized modification or deletion of entries. This is highly unlikely given Rekor's design.
        *   **Likelihood:** Low
        *   **Impact:** High
        *   **Effort:** Very High
        *   **Skill Level:** Expert
        *   **Detection Difficulty:** Hard

