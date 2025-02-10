# Attack Tree Analysis for filosottile/mkcert

Objective: Impersonate Application Server (MitM, Data Exfiltration, Malicious Content)

## Attack Tree Visualization

Goal: Impersonate Application Server (MitM, Data Exfiltration, Malicious Content)

├── 1. Compromise the CA Certificate and Key (mkcert's root CA) [HIGH RISK]
│   ├── 1.1. Physical Access to Development Machine
│   │   └── 1.1.1. Unauthorized Physical Access (Theft, Unattended Workstation) [CRITICAL NODE]
│   │       └── Action: Copy CA files from known locations.
│   ├── 1.2. Remote Access to Development Machine [HIGH RISK]
│   │   ├── 1.2.2. Credential Stuffing / Brute-Force Developer Credentials [CRITICAL NODE]
│   │   │   └── Action: Gain access to developer account, then copy CA files.
│   │   ├── 1.2.3. Phishing / Social Engineering Targeting Developer [HIGH RISK] [CRITICAL NODE]
│   │   │   └── Action: Trick developer into revealing credentials or installing malware.
│   └── 1.4.  Accidental Exposure of CA Files [HIGH RISK]
│       ├── 1.4.1.  Accidental Commit to Public Repository (e.g., GitHub) [CRITICAL NODE]
│       │   └── Action:  Monitor public repositories for leaked CA files.
│       ├── 1.4.2.  Inclusion in Docker Image/Container [CRITICAL NODE]
│       │   └── Action:  Extract CA files from publicly available or compromised container images.

├── 2.  Tricking the Client into Trusting a Rogue CA (If CA *not* compromised)
│   ├── 2.1.  Social Engineering / Phishing [HIGH RISK] [CRITICAL NODE]
│   │   └── Action:  Convince user to install a rogue CA certificate.
│   └── 2.3.  DNS Spoofing / Hijacking + Rogue CA
│       └── 2.3.2.  ARP Spoofing (Local Network) [CRITICAL NODE]
│           └── Action:  Redirect traffic to attacker-controlled server on the local network.

## Attack Tree Path: [1. Compromise the CA Certificate and Key (mkcert's root CA) [HIGH RISK]](./attack_tree_paths/1__compromise_the_ca_certificate_and_key__mkcert's_root_ca___high_risk_.md)

*   **1.1.1. Unauthorized Physical Access (Theft, Unattended Workstation) [CRITICAL NODE]**
    *   **Description:** An attacker gains physical access to the machine where the `mkcert` CA files are stored. This could involve stealing the device, accessing an unlocked and unattended workstation, or gaining unauthorized entry to a secure area.
    *   **Action:** The attacker copies the CA certificate and private key files from their known storage location (typically a directory like `~/.local/share/mkcert` or a similar path).
    *   **Likelihood:** Low
    *   **Impact:** Very High (Complete MitM capability)
    *   **Effort:** Low (If physical access is obtained)
    *   **Skill Level:** Novice
    *   **Detection Difficulty:** Medium (Physical intrusion might be noticed; file access is less likely to be immediately detected without specific monitoring.)

*   **1.2.2. Credential Stuffing / Brute-Force Developer Credentials [CRITICAL NODE]**
    *   **Description:** The attacker uses automated tools to try a large number of username/password combinations, often obtained from data breaches (credential stuffing) or systematically generated (brute-force), to gain access to the developer's account on the development machine.
    *   **Action:** Once the attacker gains access to the developer's account, they navigate to the CA file location and copy the files.
    *   **Likelihood:** Medium (Depends on password strength and reuse)
    *   **Impact:** Very High (Complete MitM capability)
    *   **Effort:** Low to Medium (Automated tools are readily available)
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium (Failed login attempts might be logged, but successful logins may blend in with normal activity.)

*   **1.2.3. Phishing / Social Engineering Targeting Developer [HIGH RISK] [CRITICAL NODE]**
    *   **Description:** The attacker crafts a deceptive email, message, or phone call designed to trick the developer into revealing their credentials, installing malware, or taking other actions that compromise the development machine.
    *   **Action:** The attacker uses the obtained credentials to access the machine and copy the CA files, or the installed malware provides remote access for the same purpose.
    *   **Likelihood:** High (Phishing is a very common and often successful attack vector)
    *   **Impact:** Very High (Complete MitM capability)
    *   **Effort:** Low to Medium (Crafting a convincing phishing email)
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium (Depends on user awareness, email filtering, and endpoint protection)

*   **1.4.1. Accidental Commit to Public Repository (e.g., GitHub) [CRITICAL NODE]**
    *   **Description:** The developer accidentally includes the `mkcert` CA files in a code commit that is pushed to a public code repository.
    *   **Action:** Attackers constantly monitor public repositories for leaked secrets, including CA certificates. They can easily download the exposed files.
    *   **Likelihood:** Low (Requires a developer mistake, but it does happen)
    *   **Impact:** Very High (Complete MitM capability, publicly exposed)
    *   **Effort:** Very Low (Automated scanning tools exist)
    *   **Skill Level:** Novice
    *   **Detection Difficulty:** Easy (Once exposed, it's public knowledge)

*   **1.4.2. Inclusion in Docker Image/Container [CRITICAL NODE]**
    *   **Description:** The developer mistakenly includes the `mkcert` CA files within a Docker image or container that is then made publicly available or becomes compromised.
    *   **Action:** Attackers can download the container image and extract the CA files using standard tools.
    *   **Likelihood:** Low (Requires a developer mistake)
    *   **Impact:** Very High (Complete MitM capability)
    *   **Effort:** Low (Tools exist to extract files from container images)
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Easy (If the image is public)

## Attack Tree Path: [2. Tricking the Client into Trusting a Rogue CA (If CA *not* compromised)](./attack_tree_paths/2__tricking_the_client_into_trusting_a_rogue_ca__if_ca_not_compromised_.md)

*   **2.1. Social Engineering / Phishing [HIGH RISK] [CRITICAL NODE]**
    *   **Description:** The attacker uses deceptive techniques (email, websites, messages) to convince a user to manually install a rogue CA certificate into their system's trust store.
    *   **Action:** Once the rogue CA is trusted, the attacker can issue certificates for any domain, and the user's browser will not show any warnings.
    *   **Likelihood:** High (Phishing is very common and effective)
    *   **Impact:** High (MitM on the targeted user/machine)
    *   **Effort:** Low to Medium (Crafting a convincing phishing campaign)
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium (Depends on user awareness and security software)

*   **2.3.2. ARP Spoofing (Local Network) [CRITICAL NODE]**
    *   **Description:** The attacker, present on the same local network as the target, sends forged ARP (Address Resolution Protocol) messages.  These messages associate the attacker's MAC address with the IP address of the legitimate server (or gateway).
    *   **Action:** Client traffic intended for the legitimate server is redirected to the attacker's machine. The attacker, having previously generated a certificate signed by their rogue CA, presents this certificate to the client.
    *   **Likelihood:** Medium (Requires local network access)
    *   **Impact:** High (MitM on users on the same local network)
    *   **Effort:** Low (Tools like `arpspoof` are readily available)
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium (Network intrusion detection systems can detect ARP spoofing, but it can be subtle if done carefully)

