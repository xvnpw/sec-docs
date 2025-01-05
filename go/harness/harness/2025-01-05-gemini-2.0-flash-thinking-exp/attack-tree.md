# Attack Tree Analysis for harness/harness

Objective: Attacker's Goal: To compromise the application utilizing Harness by exploiting weaknesses or vulnerabilities within the Harness platform itself.

## Attack Tree Visualization

```
Compromise Application via Harness [ROOT GOAL]
├── OR
│   ├── Exploit Vulnerabilities in Harness Platform Itself [CRITICAL NODE]
│   │   └── AND
│   │       └── Gain Unauthorized Access to Harness Control Plane [CRITICAL NODE]
│   │           └── Modify Deployment Pipelines/Configurations [HIGH-RISK PATH] [CRITICAL NODE]
│   │           └── Access Sensitive Data within Harness (e.g., secrets, API keys) [HIGH-RISK PATH] [CRITICAL NODE]
│   ├── Exploit Misconfigurations in Harness Setup [CRITICAL NODE]
│   │   ├── Weak Access Controls [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   └── AND
│   │   │       └── Use Compromised Credentials to Access Harness
│   │   │           ├── Modify Deployment Pipelines [HIGH-RISK PATH]
│   │   │           └── Access Secrets Management [HIGH-RISK PATH]
│   │   ├── Insecure Secret Management Practices [HIGH-RISK PATH] [CRITICAL NODE]
│   │   │   └── AND
│   │   │       └── Exploit Secret Management Weakness
│   │   │           ├── Retrieve Secrets Used in Deployment [HIGH-RISK PATH]
│   │   │           └── Used in Subsequent Deployments [HIGH-RISK PATH]
│   │   └── Vulnerable Integrations [HIGH-RISK PATH] [CRITICAL NODE]
│   │       └── AND
│   │           └── Exploit Integration Vulnerability
│   │               ├── Compromise Git Repository Connected to Harness [HIGH-RISK PATH]
│   │               └── Compromise Artifact Registry Connected to Harness [HIGH-RISK PATH]
│   └── Abuse of Harness Features for Malicious Purposes
│       └── Malicious Pipeline as Code [HIGH-RISK PATH]
│       └── Abuse of Custom Shell Steps [HIGH-RISK PATH]
```


## Attack Tree Path: [Exploit Vulnerabilities in Harness Platform Itself](./attack_tree_paths/exploit_vulnerabilities_in_harness_platform_itself.md)

* Represents a fundamental weakness in the Harness platform. Exploitation grants significant control.
    * Opens pathways to directly manipulate deployments or steal sensitive information.

## Attack Tree Path: [Gain Unauthorized Access to Harness Control Plane](./attack_tree_paths/gain_unauthorized_access_to_harness_control_plane.md)

* A pivotal point allowing attackers to directly interact with and control the Harness system.
    * Enables manipulation of pipelines, access to secrets, and other high-impact actions.

## Attack Tree Path: [Modify Deployment Pipelines/Configurations](./attack_tree_paths/modify_deployment_pipelinesconfigurations.md)

* Directly impacts the application deployment process.
    * Allows injection of malicious code or configurations that will be deployed to the application.

## Attack Tree Path: [Access Sensitive Data within Harness (e.g., secrets, API keys)](./attack_tree_paths/access_sensitive_data_within_harness__e_g___secrets__api_keys_.md)

* Provides attackers with credentials and keys necessary to directly access and compromise the application's infrastructure and data.

## Attack Tree Path: [Exploit Misconfigurations in Harness Setup](./attack_tree_paths/exploit_misconfigurations_in_harness_setup.md)

* Represents a class of vulnerabilities stemming from improper setup and management of Harness.
    * Encompasses weak access controls, insecure secret management, and vulnerable integrations.

## Attack Tree Path: [Weak Access Controls](./attack_tree_paths/weak_access_controls.md)

* Allows attackers with compromised or overly privileged accounts to perform unauthorized actions.
    * Directly leads to the ability to modify pipelines and access secrets.

## Attack Tree Path: [Insecure Secret Management Practices](./attack_tree_paths/insecure_secret_management_practices.md)

* Exposes sensitive credentials used in deployments.
    * Allows attackers to retrieve secrets or inject malicious ones, leading to application compromise.

## Attack Tree Path: [Vulnerable Integrations](./attack_tree_paths/vulnerable_integrations.md)

* Harness relies on integrations with external systems.
    * Exploiting vulnerabilities in these integrations allows attackers to inject malicious code or artifacts into the deployment process.

## Attack Tree Path: [Modify Deployment Pipelines/Configurations](./attack_tree_paths/modify_deployment_pipelinesconfigurations.md)

* Attackers gain access to the Harness control plane and alter pipeline definitions or configurations.
    * This allows them to inject malicious code, scripts, or configurations that will be executed during the deployment process, directly compromising the application.

## Attack Tree Path: [Access Sensitive Data within Harness (e.g., secrets, API keys)](./attack_tree_paths/access_sensitive_data_within_harness__e_g___secrets__api_keys_.md)

* Attackers gain unauthorized access to sensitive information stored within Harness, such as deployment credentials, API keys, and database passwords.
    * This stolen data can be used to directly attack the application's infrastructure, access sensitive data, or pivot to other systems.

## Attack Tree Path: [Weak Access Controls](./attack_tree_paths/weak_access_controls.md)

* Attackers exploit misconfigured user roles and permissions within Harness.
    * This allows them to compromise user accounts (through phishing, credential stuffing, etc.) and use those accounts to perform malicious actions, such as modifying deployment pipelines or accessing secrets.

## Attack Tree Path: [Modify Deployment Pipelines (via Weak Access Controls)](./attack_tree_paths/modify_deployment_pipelines__via_weak_access_controls_.md)

* A consequence of weak access controls. Attackers with compromised credentials modify deployment pipelines.
    * Allows injection of malicious stages, steps, or scripts into the deployment process.

## Attack Tree Path: [Access Secrets Management (via Weak Access Controls)](./attack_tree_paths/access_secrets_management__via_weak_access_controls_.md)

* Another consequence of weak access controls. Attackers with compromised credentials access the secret management functionality.
    * Enables retrieval of sensitive deployment credentials or injection of malicious secrets.

## Attack Tree Path: [Insecure Secret Management Practices](./attack_tree_paths/insecure_secret_management_practices.md)

* Attackers exploit weaknesses in how Harness manages secrets (e.g., default encryption, insufficient access control).
    * This allows them to directly retrieve sensitive secrets used in deployments or inject malicious secrets for later use.

## Attack Tree Path: [Retrieve Secrets Used in Deployment (via Insecure Secret Management)](./attack_tree_paths/retrieve_secrets_used_in_deployment__via_insecure_secret_management_.md)

* Attackers successfully exploit insecure secret management practices to obtain legitimate deployment credentials.
    * These credentials can then be used to directly access and compromise the application's infrastructure.

## Attack Tree Path: [Used in Subsequent Deployments (via Injected Malicious Secrets)](./attack_tree_paths/used_in_subsequent_deployments__via_injected_malicious_secrets_.md)

* Attackers inject malicious secrets into Harness's secret management.
    * These malicious secrets are then used in subsequent deployments, leading to application compromise.

## Attack Tree Path: [Vulnerable Integrations](./attack_tree_paths/vulnerable_integrations.md)

* Attackers target vulnerabilities or misconfigurations in systems integrated with Harness, such as Git repositories or artifact registries.
    * This allows them to inject malicious code or artifacts into the deployment pipeline.

## Attack Tree Path: [Compromise Git Repository Connected to Harness (via Vulnerable Integrations)](./attack_tree_paths/compromise_git_repository_connected_to_harness__via_vulnerable_integrations_.md)

* Attackers compromise a Git repository that Harness uses as a source code provider.
    * They can then inject malicious code into branches used by Harness, which will be included in subsequent builds and deployments.

## Attack Tree Path: [Compromise Artifact Registry Connected to Harness (via Vulnerable Integrations)](./attack_tree_paths/compromise_artifact_registry_connected_to_harness__via_vulnerable_integrations_.md)

* Attackers compromise an artifact registry from which Harness pulls deployment artifacts.
    * They can replace legitimate application artifacts with malicious ones, leading to the deployment of compromised software.

## Attack Tree Path: [Malicious Pipeline as Code](./attack_tree_paths/malicious_pipeline_as_code.md)

* Attackers with sufficient permissions directly inject malicious code or configurations into Harness pipeline definitions (Pipeline as Code).
    * This malicious code is then executed as part of the deployment process.

## Attack Tree Path: [Abuse of Custom Shell Steps](./attack_tree_paths/abuse_of_custom_shell_steps.md)

* Attackers with sufficient permissions modify pipeline definitions to include malicious commands within custom shell steps.
    * These commands are executed on the deployment target during the deployment process, allowing for arbitrary code execution and potential application compromise.

