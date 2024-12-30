## Threat Model: Compromising Application via Helm - High-Risk Paths and Critical Nodes

**Attacker's Goal:** To gain unauthorized access to or control over the application deployed using Helm, by exploiting vulnerabilities or weaknesses introduced by Helm itself.

**Sub-Tree of High-Risk Paths and Critical Nodes:**

* Compromise Application via Helm
    * **[HIGH-RISK PATH, CRITICAL NODE]** Exploit Vulnerabilities in Helm Client
        * **[CRITICAL NODE]** Compromise Local Helm Configuration
            * **[HIGH-RISK PATH]** Access and Modify `kubeconfig` File
    * **[HIGH-RISK PATH, CRITICAL NODE]** Exploit Vulnerabilities in Helm Charts
        * **[HIGH-RISK PATH, CRITICAL NODE]** Introduce Malicious Code in Chart Templates
        * **[HIGH-RISK PATH]** Leverage Insecure Default Configurations in Charts
        * **[HIGH-RISK PATH, CRITICAL NODE]** Embed Secrets Directly in Charts
    * **[CRITICAL NODE]** Exploit Vulnerabilities in Helm Repository
        * **[CRITICAL NODE]** Compromise Chart Repository Infrastructure
    * **[HIGH-RISK PATH, CRITICAL NODE]** Exploit Vulnerabilities in the Helm Release Process (Focus on Helm v2 - Tiller)
        * **[HIGH-RISK PATH, CRITICAL NODE]** Exploit Tiller's Broad Cluster Permissions (Helm v2)
    * **[HIGH-RISK PATH, CRITICAL NODE]** Exploit Post-Deployment Vulnerabilities Introduced by Helm
        * **[HIGH-RISK PATH, CRITICAL NODE]** Modify Deployed Resources via Helm

**Detailed Breakdown of Attack Vectors for High-Risk Paths and Critical Nodes:**

* **Exploit Vulnerabilities in Helm Client:**
    * **Compromise Local Helm Configuration (Critical Node):**
        * An attacker targets the local machine where the Helm client is configured.
        * This often involves social engineering, malware, or exploiting vulnerabilities in other software on the user's machine.
        * The goal is to gain access to sensitive files and settings used by the Helm client.
    * **Access and Modify `kubeconfig` File (High-Risk Path):**
        * Once local access is gained, the attacker specifically targets the `kubeconfig` file.
        * This file contains credentials that allow the Helm client to authenticate and interact with the Kubernetes cluster.
        * Modifying this file can allow the attacker to redirect Helm operations to a malicious cluster or gain full control over the legitimate cluster.

* **Exploit Vulnerabilities in Helm Charts:**
    * **Introduce Malicious Code in Chart Templates (High-Risk Path, Critical Node):**
        * Attackers create or modify Helm charts to include malicious code within the template files.
        * This code can be injected into Kubernetes manifests (e.g., Deployments, Services) using Helm's templating language.
        * When the chart is deployed, this malicious code is executed within the containers of the application, potentially leading to remote code execution, data exfiltration, or other compromises.
    * **Leverage Insecure Default Configurations in Charts (High-Risk Path):**
        * Many Helm charts come with default configurations that might not be secure.
        * Attackers can exploit these insecure defaults, such as overly permissive resource requests/limits, insecure `securityContext` settings, or exposed ports.
        * This can lead to privilege escalation within the Kubernetes cluster, allowing the attacker to access resources they shouldn't or compromise other applications.
    * **Embed Secrets Directly in Charts (High-Risk Path, Critical Node):**
        * Developers sometimes mistakenly embed sensitive information like passwords, API keys, or database credentials directly within the chart files (e.g., in `values.yaml` or template files).
        * Attackers who gain access to these charts (e.g., through a compromised repository or by inspecting publicly available charts) can easily extract these secrets and use them to access the application's resources or external services.

* **Exploit Vulnerabilities in Helm Repository:**
    * **Compromise Chart Repository Infrastructure (Critical Node):**
        * Attackers target the infrastructure hosting the Helm chart repository.
        * This could involve exploiting vulnerabilities in the repository software, gaining access through compromised credentials, or exploiting misconfigurations.
        * Once inside, attackers can modify or replace legitimate charts with malicious versions. When users download these compromised charts, they unknowingly deploy malicious applications.

* **Exploit Vulnerabilities in the Helm Release Process (Focus on Helm v2 - Tiller):**
    * **Exploit Tiller's Broad Cluster Permissions (Helm v2) (High-Risk Path, Critical Node):**
        * In Helm v2, Tiller runs within the Kubernetes cluster with broad permissions to manage deployments.
        * If an attacker can compromise Tiller's service account or the Tiller deployment itself (e.g., through a vulnerability in Tiller or by exploiting weak RBAC configurations), they gain cluster-wide control.
        * This allows them to deploy, modify, or delete any application within the cluster.

* **Exploit Post-Deployment Vulnerabilities Introduced by Helm:**
    * **Modify Deployed Resources via Helm (High-Risk Path, Critical Node):**
        * Even after a successful and secure initial deployment, an attacker with sufficient permissions can use Helm to update an existing release with malicious changes.
        * This could involve modifying container images, environment variables, or other deployment configurations to introduce vulnerabilities or backdoors into the running application. This requires compromised credentials or access to the Helm deployment process.