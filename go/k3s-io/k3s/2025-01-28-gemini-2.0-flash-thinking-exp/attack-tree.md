# Attack Tree Analysis for k3s-io/k3s

Objective: Compromise application running on K3s by exploiting K3s weaknesses.

## Attack Tree Visualization

* **Attacker Goal: Compromise Application via K3s Weaknesses [CRITICAL NODE]**
    * **Initial Access to K3s Cluster [CRITICAL NODE]**
        * **Exploit Publicly Exposed K3s Components [HIGH RISK PATH]**
            * **Exploit Kube-API Server Vulnerabilities [CRITICAL NODE]**
                * **Known CVEs in Kube-API Server [HIGH RISK PATH]**
        * **Compromise K3s Node Infrastructure [CRITICAL NODE, HIGH RISK PATH]**
            * **Exploit Host OS Vulnerabilities [HIGH RISK PATH]**
                * **Known CVEs in Host OS [HIGH RISK PATH]**
                * **Misconfiguration of Host OS [HIGH RISK PATH]**
            * **Network Scanning and Exploitation [HIGH RISK PATH]**
        * **Insider Threat/Compromised Credentials [HIGH RISK PATH]**
            * **Malicious Insider Access [HIGH RISK PATH]**
            * **Compromised Administrator Credentials [HIGH RISK PATH]**
    * **Privilege Escalation within K3s Cluster [CRITICAL NODE, HIGH RISK PATH]**
        * **RBAC Misconfiguration [HIGH RISK PATH]**
            * **Overly Permissive RBAC Roles [HIGH RISK PATH]**
        * **Service Account Token Exploitation [HIGH RISK PATH]**
            * **Unsecured Service Account Tokens [HIGH RISK PATH]**
        * **Container Escape [CRITICAL NODE, HIGH RISK PATH]**
            * **Container Runtime Vulnerabilities (revisited) [HIGH RISK PATH]**
            * **Kernel Vulnerabilities [HIGH RISK PATH]**
            * **Misconfigured Container Security Context [HIGH RISK PATH]**
        * **Abuse of K3s Features for Privilege Escalation [HIGH RISK PATH]**
            * **HostPath Volume Mount Exploitation [HIGH RISK PATH]**
    * **Application Compromise [CRITICAL NODE]**
        * **Access Application Secrets [CRITICAL NODE, HIGH RISK PATH]**
            * **Exploiting Insecure Secret Storage in K3s [HIGH RISK PATH]**
            * **Accessing Secrets from Compromised Pods/Nodes [HIGH RISK PATH]**
                * **Reading Secrets from Environment Variables [HIGH RISK PATH]**
        * **Modify Application Configuration [HIGH RISK PATH]**
            * **Compromise ConfigMaps [HIGH RISK PATH]**
            * **Modify Deployments/StatefulSets [CRITICAL NODE, HIGH RISK PATH]**
        * **Disrupt Application Availability [HIGH RISK PATH]**
            * **Resource Exhaustion Attacks [HIGH RISK PATH]**

## Attack Tree Path: [Attacker Goal: Compromise Application via K3s Weaknesses [CRITICAL NODE]](./attack_tree_paths/attacker_goal_compromise_application_via_k3s_weaknesses__critical_node_.md)

**1. Attacker Goal: Compromise Application via K3s Weaknesses [CRITICAL NODE]**
    * **Attack Vector:** This is the overarching objective. Success means the attacker achieves unauthorized access and control over the application and its data.
    * **Why High-Risk:** Represents the ultimate failure from a security perspective.

## Attack Tree Path: [Initial Access to K3s Cluster [CRITICAL NODE]](./attack_tree_paths/initial_access_to_k3s_cluster__critical_node_.md)

**2. Initial Access to K3s Cluster [CRITICAL NODE]**
    * **Attack Vector:** Gaining initial foothold within the K3s cluster is the prerequisite for most subsequent attacks.
    * **Why High-Risk:** Without initial access, attackers are limited to external attacks (which are considered out of scope for *K3s specific* threats in this model).

## Attack Tree Path: [Exploit Publicly Exposed K3s Components [HIGH RISK PATH]](./attack_tree_paths/exploit_publicly_exposed_k3s_components__high_risk_path_.md)

**3. Exploit Publicly Exposed K3s Components [HIGH RISK PATH]**
    * **Attack Vector:** Directly targeting K3s components like the API server, kubelet, or containerd that are exposed to the public internet.
    * **Why High-Risk:** Public exposure drastically increases the attack surface. Vulnerabilities in these components can lead to immediate and widespread compromise.
        * **Exploit Kube-API Server Vulnerabilities [CRITICAL NODE]**
            * **Attack Vector:** Exploiting vulnerabilities in the Kube-API server, the central control plane component of Kubernetes.
            * **Why High-Risk:** API server compromise grants cluster-wide administrative control, allowing attackers to manipulate any resource, including applications, secrets, and nodes.
                * **Known CVEs in Kube-API Server [HIGH RISK PATH]**
                    * **Attack Vector:** Exploiting publicly known vulnerabilities (CVEs) in the Kube-API server.
                    * **Why High-Risk:** Known CVEs are well-documented, and exploits are often readily available, making this a relatively easy and high-impact attack path if systems are not promptly patched.

## Attack Tree Path: [Compromise K3s Node Infrastructure [CRITICAL NODE, HIGH RISK PATH]](./attack_tree_paths/compromise_k3s_node_infrastructure__critical_node__high_risk_path_.md)

**4. Compromise K3s Node Infrastructure [CRITICAL NODE, HIGH RISK PATH]**
    * **Attack Vector:** Targeting the underlying infrastructure of K3s nodes, including the host operating system and network.
    * **Why High-Risk:** Node compromise provides direct access to the host system, bypassing containerization and K3s security boundaries. It can lead to container escape, data theft, and cluster-wide impact.
        * **Exploit Host OS Vulnerabilities [HIGH RISK PATH]**
            * **Attack Vector:** Exploiting vulnerabilities in the operating system running on K3s nodes.
            * **Why High-Risk:** OS vulnerabilities are common, and successful exploitation grants root-level access to the node.
                * **Known CVEs in Host OS [HIGH RISK PATH]**
                    * **Attack Vector:** Exploiting publicly known vulnerabilities (CVEs) in the host OS.
                    * **Why High-Risk:** Similar to API server CVEs, known OS CVEs are easily exploitable if systems are not patched.
                * **Misconfiguration of Host OS [HIGH RISK PATH]**
                    * **Attack Vector:** Exploiting insecure configurations in the host OS, such as weak passwords, open ports, or insecure services.
                    * **Why High-Risk:** Misconfigurations are common, especially in complex systems, and can provide easy entry points for attackers.
        * **Network Scanning and Exploitation [HIGH RISK PATH]**
            * **Attack Vector:** Scanning the network for open ports and vulnerable services on K3s nodes and exploiting them.
            * **Why High-Risk:** Network scanning is a standard reconnaissance technique, and exposed services on nodes can be vulnerable to exploitation, leading to node compromise.

## Attack Tree Path: [Insider Threat/Compromised Credentials [HIGH RISK PATH]](./attack_tree_paths/insider_threatcompromised_credentials__high_risk_path_.md)

**5. Insider Threat/Compromised Credentials [HIGH RISK PATH]**
    * **Attack Vector:** Leveraging malicious insiders or compromised administrator credentials to gain access to and exploit K3s.
    * **Why High-Risk:** Insider access or compromised credentials bypass many external security controls, providing direct access to sensitive systems and resources.
        * **Malicious Insider Access [HIGH RISK PATH]**
            * **Attack Vector:** A trusted insider intentionally abuses their legitimate access to harm the system.
            * **Why High-Risk:** Insiders often have deep knowledge of systems and can be difficult to detect.
        * **Compromised Administrator Credentials [HIGH RISK PATH]**
            * **Attack Vector:** Attackers obtain and use legitimate administrator credentials through phishing, credential stuffing, or other means.
            * **Why High-Risk:** Administrator credentials grant extensive privileges, allowing attackers to take full control of the K3s cluster.

## Attack Tree Path: [Privilege Escalation within K3s Cluster [CRITICAL NODE, HIGH RISK PATH]](./attack_tree_paths/privilege_escalation_within_k3s_cluster__critical_node__high_risk_path_.md)

**6. Privilege Escalation within K3s Cluster [CRITICAL NODE, HIGH RISK PATH]**
    * **Attack Vector:** After gaining initial limited access, attackers attempt to escalate their privileges within the K3s cluster to gain broader control.
    * **Why High-Risk:** Privilege escalation allows attackers to move from a limited foothold to a position of significant power, enabling them to access sensitive resources and achieve their goals.
        * **RBAC Misconfiguration [HIGH RISK PATH]**
            * **Attack Vector:** Exploiting misconfigurations in Kubernetes Role-Based Access Control (RBAC) to gain unauthorized privileges.
            * **Why High-Risk:** RBAC misconfigurations are common, especially in complex setups, and can easily lead to privilege escalation.
                * **Overly Permissive RBAC Roles [HIGH RISK PATH]**
                    * **Attack Vector:** Identifying and exploiting overly permissive RBAC roles granted to users or service accounts.
                    * **Why High-Risk:** Overly permissive roles grant more access than necessary, creating opportunities for attackers to escalate privileges.
        * **Service Account Token Exploitation [HIGH RISK PATH]**
            * **Attack Vector:** Exploiting service account tokens to gain unauthorized access and potentially escalate privileges.
            * **Why High-Risk:** Service account tokens are often overlooked and can be accidentally exposed or mismanaged, providing an easy target for attackers.
                * **Unsecured Service Account Tokens [HIGH RISK PATH]**
                    * **Attack Vector:** Discovering and exploiting exposed or leaked service account tokens.
                    * **Why High-Risk:** Unsecured tokens can be easily obtained and used to impersonate the service account, gaining its privileges.
        * **Container Escape [CRITICAL NODE, HIGH RISK PATH]**
            * **Attack Vector:** Escaping the container environment to gain access to the underlying host system.
            * **Why High-Risk:** Container escape breaks the isolation provided by containers and grants access to the node, leading to significant compromise.
                * **Container Runtime Vulnerabilities (revisited) [HIGH RISK PATH]**
                    * **Attack Vector:** Exploiting vulnerabilities in the container runtime (containerd) to escape to the host.
                    * **Why High-Risk:** Container runtime vulnerabilities are critical and can directly lead to node compromise.
                * **Kernel Vulnerabilities [HIGH RISK PATH]**
                    * **Attack Vector:** Exploiting vulnerabilities in the host OS kernel from within a container to escape to the host.
                    * **Why High-Risk:** Kernel vulnerabilities are powerful and can be exploited for container escape.
                * **Misconfigured Container Security Context [HIGH RISK PATH]**
                    * **Attack Vector:** Exploiting misconfigurations in container security context, such as running privileged containers or disabling security features.
                    * **Why High-Risk:** Misconfigured security contexts can make container escape trivial.
        * **Abuse of K3s Features for Privilege Escalation [HIGH RISK PATH]**
            * **Attack Vector:** Misusing legitimate K3s features to gain elevated privileges.
            * **Why High-Risk:** Legitimate features, when misused, can bypass intended security boundaries.
                * **HostPath Volume Mount Exploitation [HIGH RISK PATH]**
                    * **Attack Vector:** Mounting `hostPath` volumes to gain access to the host filesystem from within a container.
                    * **Why High-Risk:** `hostPath` volumes break container isolation and can be used to access and manipulate sensitive host files, leading to node compromise.

## Attack Tree Path: [Application Compromise [CRITICAL NODE]](./attack_tree_paths/application_compromise__critical_node_.md)

**7. Application Compromise [CRITICAL NODE]**
    * **Attack Vector:** Once K3s is compromised, attackers target the applications running within the cluster to achieve their ultimate goal.
    * **Why High-Risk:** Application compromise is the final stage where attackers directly impact the target application and its data.
        * **Access Application Secrets [CRITICAL NODE, HIGH RISK PATH]**
            * **Attack Vector:** Gaining access to sensitive application secrets, such as API keys, database credentials, or encryption keys.
            * **Why High-Risk:** Secrets are critical for application security. Compromising secrets can lead to data breaches, unauthorized access, and complete application takeover.
                * **Exploiting Insecure Secret Storage in K3s [HIGH RISK PATH]**
                    * **Attack Vector:** Exploiting weaknesses in how K3s stores secrets, such as default storage vulnerabilities or misconfigured encryption.
                    * **Why High-Risk:** Insecure secret storage can expose all secrets within the cluster if compromised.
                * **Accessing Secrets from Compromised Pods/Nodes [HIGH RISK PATH]**
                    * **Attack Vector:** Accessing secrets from compromised pods or nodes where applications are running.
                    * **Why High-Risk:** If pods or nodes are compromised, secrets stored within them become vulnerable.
                        * **Reading Secrets from Environment Variables [HIGH RISK PATH]**
                            * **Attack Vector:** Accessing secrets that are mistakenly exposed as environment variables within compromised pods.
                            * **Why High-Risk:** Exposing secrets as environment variables is a common and easily exploitable mistake.
        * **Modify Application Configuration [HIGH RISK PATH]**
            * **Attack Vector:** Modifying application configurations to alter application behavior or inject malicious code.
            * **Why High-Risk:** Modifying application configurations can lead to application malfunction, data manipulation, and persistent compromise.
                * **Compromise ConfigMaps [HIGH RISK PATH]**
                    * **Attack Vector:** Compromising ConfigMaps to alter application behavior or inject malicious configurations.
                    * **Why High-Risk:** ConfigMaps control application behavior, and their compromise can have significant impact.
                * **Modify Deployments/StatefulSets [CRITICAL NODE, HIGH RISK PATH]**
                    * **Attack Vector:** Modifying application deployments or statefulsets to inject malicious containers or alter application logic.
                    * **Why High-Risk:** Modifying deployments allows for persistent compromise by injecting malicious code directly into the application deployment.
        * **Disrupt Application Availability [HIGH RISK PATH]**
            * **Attack Vector:** Launching attacks to disrupt the availability of the application, leading to denial of service.
            * **Why High-Risk:** Application downtime can have significant business impact and reputational damage.
                * **Resource Exhaustion Attacks [HIGH RISK PATH]**
                    * **Attack Vector:** Launching resource exhaustion attacks (e.g., CPU, memory, storage) to cause application denial of service.
                    * **Why High-Risk:** Resource exhaustion attacks are relatively easy to launch in Kubernetes and can quickly disrupt application availability.

