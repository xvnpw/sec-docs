# Attack Tree Analysis for helm/helm

Objective: Gain Unauthorized Control over Kubernetes Cluster via Helm [CRITICAL NODE]

## Attack Tree Visualization

```
                                     Gain Unauthorized Control over Kubernetes Cluster via Helm [CRITICAL NODE]
                                                    /                               \
                                                   /                                 \
                      ---------------------------------------------------      ----------------------------------------
                      |  HIGH-RISK PATH                             |      |  HIGH-RISK PATH                        |
                      V                                                 V      V                                        |
   1. Compromise Helm Client/Environment          2. Exploit Helm Chart Vulnerabilities   3. Abuse Helm/Kubernetes RBAC Misconfigurations [CRITICAL NODE]
                      |                                                 |      |                                        |
      -------------------------------                 ---------------------------------      ----------------------------------------
      |               |                               |       |       |                 |       |       |
      V               V                               V       V       V                 V       V       V
  1.1             1.3                             2.1     2.2     2.3           3.1     3.2     3.3
  Stolen          Compromised                      Malicious  Unsafe  Image         Overly  Service  K8s
  Helm            CI/CD                           Chart   Defaults  Pulling      Permissive Account  RBAC
  Creds           Pipeline                        Source  in Chart  from         Helm     with     Mis-
 [CRITICAL]       [HIGH RISK]                     [HIGH RISK] Config  Untrusted     Release  Cluster- config.
  NODE                                                       [HIGH RISK] Source      Privs    Admin  [HIGH RISK]
                                                                        [HIGH RISK]   [CRITICAL] [CRITICAL]
                                                                                      NODE      NODE
```

## Attack Tree Path: [1. Compromise Helm Client/Environment](./attack_tree_paths/1__compromise_helm_clientenvironment.md)

**1. Compromise Helm Client/Environment:**

*   **1.1 Stolen Helm Credentials [CRITICAL NODE]:**
    *   **Description:** An attacker obtains credentials (kubeconfig, service account token) used to authenticate with the Kubernetes cluster. This could be through phishing, malware, social engineering, or physical access to a compromised machine.
    *   **Likelihood:** Medium
    *   **Impact:** High (Full cluster access)
    *   **Effort:** Low to Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

*   **1.3 Compromised CI/CD Pipeline [HIGH RISK]:**
    *   **Description:** An attacker gains access to the CI/CD pipeline responsible for deploying Helm charts. They can modify the pipeline to inject malicious charts, alter configurations, or steal secrets.
    *   **Likelihood:** Medium
    *   **Impact:** High (Ability to deploy malicious charts)
    *   **Effort:** Medium to High
    *   **Skill Level:** Intermediate to Advanced
    *   **Detection Difficulty:** Medium to Hard

## Attack Tree Path: [2. Exploit Helm Chart Vulnerabilities](./attack_tree_paths/2__exploit_helm_chart_vulnerabilities.md)

**2. Exploit Helm Chart Vulnerabilities:**

*   **2.1 Malicious Chart Source [HIGH RISK]:**
    *   **Description:** The Helm chart itself contains malicious code or configurations. This could be a compromised Docker image referenced by the chart, a deployment that creates a backdoor, or any other malicious Kubernetes resource definition. The chart is sourced from an untrusted or compromised location.
    *   **Likelihood:** Medium
    *   **Impact:** Medium to High
    *   **Effort:** Low
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

*   **2.2 Unsafe Defaults in Chart Config [HIGH RISK]:**
    *   **Description:** The Helm chart uses insecure default values in its `values.yaml` file (e.g., weak passwords, exposed ports, overly permissive permissions). These defaults are not overridden by the user during deployment.
    *   **Likelihood:** Medium
    *   **Impact:** Low to Medium
    *   **Effort:** Very Low
    *   **Skill Level:** Beginner to Intermediate
    *   **Detection Difficulty:** Easy to Medium

*   **2.3 Image Pulling from Untrusted Source [HIGH RISK]:**
    *   **Description:** The Helm chart specifies a Docker image to be pulled from an untrusted or compromised container registry. The image itself may contain vulnerabilities or malicious code.
    *   **Likelihood:** Medium
    *   **Impact:** High
    *   **Effort:** Low
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

## Attack Tree Path: [3. Abuse Helm/Kubernetes RBAC Misconfigurations [CRITICAL NODE]](./attack_tree_paths/3__abuse_helmkubernetes_rbac_misconfigurations__critical_node_.md)

**3. Abuse Helm/Kubernetes RBAC Misconfigurations [CRITICAL NODE]:**

*   **3.1 Overly Permissive Helm Release Privileges [CRITICAL NODE]:**
    *   **Description:** The service account used by Helm (or the user executing Helm commands) has excessive permissions within the Kubernetes cluster. This often includes permissions beyond what is necessary for deploying and managing the specific application.  It might even include `cluster-admin` privileges.
    *   **Likelihood:** Medium
    *   **Impact:** High
    *   **Effort:** Very Low
    *   **Skill Level:** Beginner
    *   **Detection Difficulty:** Easy

*   **3.2 Service Account with Cluster-Admin [CRITICAL NODE]:**
    *   **Description:** A service account *within* a deployed application (defined in the Helm chart) is granted `cluster-admin` privileges. This is an extremely dangerous misconfiguration, giving the application (and any attacker who compromises it) complete control over the cluster.
    *   **Likelihood:** Low
    *   **Impact:** Very High
    *   **Effort:** Very Low
    *   **Skill Level:** Beginner
    *   **Detection Difficulty:** Easy

*   **3.3 Kubernetes RBAC Misconfiguration [HIGH RISK]:**
    *   **Description:** General misconfigurations in Kubernetes RBAC (not directly caused by Helm, but exploitable through Helm deployments) that allow for privilege escalation or unauthorized access. This could include overly permissive roles, role bindings, or cluster roles.
    *   **Likelihood:** Medium
    *   **Impact:** Low to High
    *   **Effort:** Low to Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

