# Attack Tree Analysis for goharbor/harbor

Objective: Compromise the application utilizing Harbor by exploiting Harbor's weaknesses.

## Attack Tree Visualization

```
Compromise Application via Harbor
├── *** HIGH-RISK PATH: Malicious Image Injection Leading to Application Compromise ***
│   ├── AND [CRITICAL NODE: Gain Access to Push Images]
│   │   ├── OR
│   │   │   ├── Compromise Developer/CI Credentials
│   │   │   ├── Exploit Harbor Authentication/Authorization Vulnerability
│   │   │   ├── Supply Chain Attack on Base Image/Dependencies
│   │   ├── [CRITICAL NODE: Inject Malicious Payload into Image]
│   │   └── [CRITICAL NODE: Application Pulls and Executes Malicious Image]
├── HIGH-RISK PATH: Exploiting Known Harbor Vulnerabilities for Direct Compromise
│   ├── OR
│   │   ├── [CRITICAL NODE: Exploit Known Harbor Vulnerabilities (CVEs)]
├── HIGH-RISK PATH: Exploiting Misconfiguration in Harbor Leading to Control
│   ├── OR
│   │   ├── [CRITICAL NODE: Weak Access Control Policies]
│   │   ├── [CRITICAL NODE: Exposed Admin Interface]
│   │   ├── [CRITICAL NODE: Insecure Storage of Secrets/Credentials]
├── HIGH-RISK PATH: API Exploitation for Resource Manipulation
│   ├── AND [CRITICAL NODE: Gain Unauthorized Access to Harbor API]
│   ├── OR
│   │   ├── [CRITICAL NODE: Modify Image Tags/Manifests via API]
│   │   ├── [CRITICAL NODE: Delete Critical Images/Repositories via API]
├── HIGH-RISK PATH: Exploiting Weak Integrations for Harbor Access
│   ├── AND [CRITICAL NODE: Identify Weaknesses in Integrated Systems (e.g., Authentication Providers, Storage Backends)]
│   │   └── [CRITICAL NODE: Leverage Compromised Integration to Access/Manipulate Harbor]
```


## Attack Tree Path: [Malicious Image Injection Leading to Application Compromise](./attack_tree_paths/malicious_image_injection_leading_to_application_compromise.md)

**Goal:** Inject a malicious container image into Harbor that the target application will pull and execute.
*   **Critical Node: Gain Access to Push Images:**
    *   **Attack Vector:** Compromise Developer/CI Credentials
        *   Attackers steal credentials used to push images to Harbor, allowing them to upload malicious images. This can be through phishing, malware, or exploiting vulnerabilities in developer workstations or CI/CD pipelines.
    *   **Attack Vector:** Exploit Harbor Authentication/Authorization Vulnerability
        *   A vulnerability in Harbor's authentication or authorization mechanisms could allow an attacker to bypass security and push images without proper credentials.
    *   **Attack Vector:** Supply Chain Attack on Base Image/Dependencies
        *   Attackers compromise base images or dependencies used in the application's container images. When developers build their images, the malicious code is unknowingly included.
*   **Critical Node: Inject Malicious Payload into Image:**
    *   **Attack Vector:** Once access to push images is gained, attackers modify an existing image or create a new one containing malicious code, backdoors, or exploits.
*   **Critical Node: Application Pulls and Executes Malicious Image:**
    *   **Attack Vector:** The application, configured to pull images from Harbor, retrieves and runs the compromised image, leading to the execution of the attacker's payload within the container environment.

## Attack Tree Path: [Exploiting Known Harbor Vulnerabilities for Direct Compromise](./attack_tree_paths/exploiting_known_harbor_vulnerabilities_for_direct_compromise.md)

**Goal:** Directly compromise the Harbor instance itself to gain control over the registry and its resources.
*   **Critical Node: Exploit Known Harbor Vulnerabilities (CVEs):**
    *   **Attack Vector:** Attackers actively scan for and exploit publicly known vulnerabilities (CVEs) in specific versions of Harbor that have not been patched.

## Attack Tree Path: [Exploiting Misconfiguration in Harbor Leading to Control](./attack_tree_paths/exploiting_misconfiguration_in_harbor_leading_to_control.md)

**Goal:** Leverage insecure configurations in Harbor to gain unauthorized access and control.
*   **Critical Node: Weak Access Control Policies:**
    *   **Attack Vector:** Insufficiently configured access controls allow unauthorized users to perform actions like pushing, pulling, or deleting images, or accessing sensitive information.
*   **Critical Node: Exposed Admin Interface:**
    *   **Attack Vector:** The Harbor administrative interface is publicly accessible or protected by weak credentials, allowing attackers to gain full control over the registry.
*   **Critical Node: Insecure Storage of Secrets/Credentials:**
    *   **Attack Vector:** Harbor stores sensitive information like database credentials or API keys in plaintext or easily reversible formats, allowing attackers to retrieve and misuse them.

## Attack Tree Path: [API Exploitation for Resource Manipulation](./attack_tree_paths/api_exploitation_for_resource_manipulation.md)

**Goal:** Leverage Harbor's API to manipulate resources or gain unauthorized access.
*   **Critical Node: Gain Unauthorized Access to Harbor API:**
    *   **Attack Vector:** Compromise API Keys/Tokens
        *   Attackers steal API keys or tokens used to interact with the Harbor API, allowing them to perform actions on behalf of legitimate users or services.
*   **Critical Node: Modify Image Tags/Manifests via API:**
    *   **Attack Vector:** Attackers with API access alter image tags to point to malicious images or modify image manifests to inject malicious layers, potentially tricking applications into pulling compromised images.
*   **Critical Node: Delete Critical Images/Repositories via API:**
    *   **Attack Vector:** Attackers with API access delete important images or repositories, causing disruption to the application deployment process and potentially impacting application availability.

## Attack Tree Path: [Exploiting Weak Integrations for Harbor Access](./attack_tree_paths/exploiting_weak_integrations_for_harbor_access.md)

**Goal:** Leverage vulnerabilities in systems integrated with Harbor to compromise Harbor or the application.
*   **Critical Node: Identify Weaknesses in Integrated Systems (e.g., Authentication Providers, Storage Backends):**
    *   **Attack Vector:** Attackers identify and exploit vulnerabilities in systems that Harbor integrates with, such as LDAP servers, OAuth providers, or object storage backends.
*   **Critical Node: Leverage Compromised Integration to Access/Manipulate Harbor:**
    *   **Attack Vector:** Once an integrated system is compromised, attackers use the established trust or access mechanisms to gain unauthorized access to Harbor or manipulate its resources.

