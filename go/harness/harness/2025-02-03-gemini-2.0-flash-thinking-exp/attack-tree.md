# Attack Tree Analysis for harness/harness

Objective: Compromise Application via Harness CI/CD Exploitation (Focused on High-Risk Areas)

## Attack Tree Visualization

```
Root Goal: Compromise Application via Harness Exploitation
├───[OR]─ 1. Compromise Deployment Pipeline [HIGH RISK PATH]
│   ├───[OR]─ 1.1. Pipeline Configuration Manipulation [HIGH RISK PATH]
│   │   ├───[OR]─ 1.1.1. Unauthorized Access to Harness Project/Pipeline Settings [CRITICAL NODE]
│   │   │   ├───[AND]─ 1.1.1.1. Weak Harness User Credentials [CRITICAL NODE]
│   │   │   ├───[AND]─ 1.1.1.2. Lack of Multi-Factor Authentication (MFA) on Harness Accounts [CRITICAL NODE]
│   │   │   ├───[AND]─ 1.1.1.3. Insufficient Role-Based Access Control (RBAC) in Harness [CRITICAL NODE]
│   │   ├───[OR]─ 1.1.2. Pipeline Definition Injection [HIGH RISK PATH]
│   │   │   ├───[AND]─ 1.1.2.1. Insecure Pipeline Definition Storage (e.g., Git without proper access control) [CRITICAL NODE]
│   │   │   ├───[AND]─ 1.1.2.2. Lack of Input Validation in Pipeline Definition Processing by Harness [CRITICAL NODE]
│   ├───[OR]─ 1.2. Compromise Artifacts Deployed by Harness [HIGH RISK PATH]
│   │   ├───[OR]─ 1.2.1. Supply Chain Attack on Build Process (Pre-Harness) [HIGH RISK PATH]
│   │   ├───[OR]─ 1.2.2. Artifact Manipulation during Harness Deployment
│   │   │   ├───[AND]─ 1.2.2.1. Insecure Artifact Storage/Retrieval by Harness [CRITICAL NODE]
│   ├───[OR]─ 1.3. Man-in-the-Middle (MITM) on Deployment Communication
│   │   ├───[AND]─ 1.3.1.2. Compromised Harness Delegate Infrastructure [CRITICAL NODE]
├───[OR]─ 2. Exploit Harness Secrets Management [HIGH RISK PATH]
│   ├───[OR]─ 2.1.2. Insider Threat/Compromised Harness Administrator Account [CRITICAL NODE]
│   ├───[OR]─ 2.2. Indirect Secret Exposure via Pipeline Execution [HIGH RISK PATH]
│   │   ├───[AND]─ 2.2.1. Secrets Logged or Exposed during Pipeline Execution [CRITICAL NODE]
│   │   ├───[AND]─ 2.2.2. Secrets Used Insecurely in Deployment Scripts [CRITICAL NODE]
├───[OR]─ 3. Abuse Harness Integrations
│   ├───[OR]─ 3.1. Compromise Integrated Source Code Repository (e.g., Git) [HIGH RISK PATH]
│   ├───[OR]─ 3.2. Abuse Cloud Provider Integrations [HIGH RISK PATH]
│   │   ├───[AND]─ 3.2.1. Stolen or Weak Cloud Provider Credentials in Harness [CRITICAL NODE]
│   │   ├───[AND]─ 3.2.2. Overly Permissive Cloud Provider Permissions Granted to Harness [CRITICAL NODE]
└───[OR]─ 5. Social Engineering/Insider Threat Targeting Harness Users [HIGH RISK PATH]
    ├───[OR]─ 5.1. Phishing Harness Users for Credentials [HIGH RISK PATH, CRITICAL NODE]
    ├───[OR]─ 5.2. Malicious Insider with Harness Access [HIGH RISK PATH, CRITICAL NODE]
```

## Attack Tree Path: [1. Compromise Deployment Pipeline [HIGH RISK PATH]](./attack_tree_paths/1__compromise_deployment_pipeline__high_risk_path_.md)

*   **Attack Vector:**  Targeting the deployment pipeline itself to inject malicious code or manipulate the deployment process. This is a high-impact path as it directly controls what gets deployed to the application.
*   **Exploitation:** Attackers aim to gain control over the pipeline configuration or execution flow. This can be achieved through various means detailed below in sub-nodes.
*   **Impact:** Critical - Full control over application deployments, leading to code tampering, data breaches, service disruption, or infrastructure compromise.
*   **Mitigation:** Secure Harness user access, implement RBAC, secure pipeline definitions, use version control, input validation, and regular auditing.

    *   **1.1. Pipeline Configuration Manipulation [HIGH RISK PATH]:**
        *   **Attack Vector:** Altering the pipeline configuration to introduce malicious steps, change deployment targets, or modify deployment scripts.
        *   **Exploitation:**  Requires unauthorized access to Harness project/pipeline settings (see critical nodes below). Once accessed, attackers can modify pipeline stages, steps, parameters, and scripts.
        *   **Impact:** High - Ability to deploy malicious code or disrupt deployments.
        *   **Mitigation:** Strong authentication, MFA, RBAC, pipeline configuration as code, version control, and change auditing.

            *   **1.1.1. Unauthorized Access to Harness Project/Pipeline Settings [CRITICAL NODE]:**
                *   **Attack Vector:** Gaining unauthorized access to the Harness platform's project and pipeline configuration settings. This is a gateway node to pipeline manipulation.
                *   **Exploitation:** Exploiting weak user credentials, lack of MFA, insufficient RBAC, or vulnerabilities in the Harness UI/API.
                *   **Impact:** High - Enables pipeline configuration manipulation and further attacks.
                *   **Mitigation:** Strong passwords, MFA, RBAC, regular user access audits, and patching Harness platform vulnerabilities.

                *   **1.1.1.1. Weak Harness User Credentials [CRITICAL NODE]:**
                    *   **Attack Vector:** Using easily guessable or compromised usernames and passwords to gain access to Harness accounts.
                    *   **Exploitation:** Brute-force attacks, credential stuffing, or password guessing.
                    *   **Impact:** High - Account takeover leading to unauthorized access to Harness.
                    *   **Mitigation:** Enforce strong password policies, password complexity requirements, and account lockout mechanisms.

                *   **1.1.1.2. Lack of Multi-Factor Authentication (MFA) on Harness Accounts [CRITICAL NODE]:**
                    *   **Attack Vector:** Bypassing single-factor authentication (username/password only) to gain unauthorized access.
                    *   **Exploitation:** Credential theft via phishing, malware, or social engineering becomes much more effective without MFA.
                    *   **Impact:** High - Increased risk of account takeover.
                    *   **Mitigation:** Mandate MFA for all Harness user accounts, especially administrators and users with pipeline modification permissions.

                *   **1.1.1.3. Insufficient Role-Based Access Control (RBAC) in Harness [CRITICAL NODE]:**
                    *   **Attack Vector:** Exploiting overly permissive user roles to gain access to functionalities or resources beyond what is necessary for a user's role, including pipeline modification.
                    *   **Exploitation:** Users with inappropriately broad permissions can modify pipelines, even if they shouldn't have direct pipeline administration roles.
                    *   **Impact:** High - Privilege escalation and unauthorized pipeline modification.
                    *   **Mitigation:** Implement granular RBAC, adhere to the principle of least privilege, and regularly review and refine RBAC policies.

        *   **1.1.2. Pipeline Definition Injection [HIGH RISK PATH]:**
            *   **Attack Vector:** Injecting malicious code or commands into pipeline definitions, often through manipulating external sources or exploiting lack of input validation.
            *   **Exploitation:**  Compromising Git repositories where pipeline definitions are stored or exploiting vulnerabilities in how Harness processes pipeline definitions (lack of input sanitization).
            *   **Impact:** High - Direct injection of malicious code into the deployment pipeline.
            *   **Mitigation:** Secure pipeline definition storage (Git), implement input validation and sanitization in pipeline definitions, and use secure coding practices.

            *   **1.1.2.1. Insecure Pipeline Definition Storage (e.g., Git without proper access control) [CRITICAL NODE]:**
                *   **Attack Vector:** Directly modifying pipeline definitions stored in an insecure repository, like a Git repository with weak access controls.
                *   **Exploitation:** Gaining unauthorized access to the Git repository and directly altering pipeline YAML or script files.
                *   **Impact:** Critical - Complete control over pipeline definitions and deployed code.
                *   **Mitigation:** Secure Git repositories with strong access controls, use branch protection, and implement code review processes for pipeline definition changes.

            *   **1.1.2.2. Lack of Input Validation in Pipeline Definition Processing by Harness [CRITICAL NODE]:**
                *   **Attack Vector:** Injecting malicious commands or code within pipeline parameters or scripts that are not properly validated and sanitized by Harness during pipeline execution.
                *   **Exploitation:** Providing malicious input through pipeline triggers, parameters, or external data sources that are incorporated into pipeline commands without proper sanitization.
                *   **Impact:** High - Command injection vulnerabilities leading to arbitrary code execution during deployment.
                *   **Mitigation:** Implement robust input validation and sanitization for all pipeline parameters and external inputs used in pipeline steps.

    *   **1.2. Compromise Artifacts Deployed by Harness [HIGH RISK PATH]:**
        *   **Attack Vector:** Manipulating the build artifacts that Harness deploys, ensuring malicious code is included in the deployed application.
        *   **Exploitation:** Supply chain attacks targeting the build process *before* Harness, or manipulating artifacts during Harness deployment if storage or retrieval is insecure.
        *   **Impact:** Critical - Deployment of compromised application code.
        *   **Mitigation:** Secure build environments, implement supply chain security measures, secure artifact storage, and implement artifact integrity verification.

        *   **1.2.1. Supply Chain Attack on Build Process (Pre-Harness) [HIGH RISK PATH]:**
            *   **Attack Vector:** Compromising components of the software supply chain *before* artifacts reach Harness, such as build environments, dependencies, or code repositories used in the build process.
            *   **Exploitation:** Injecting malicious code into dependencies, build scripts, or the build environment itself, resulting in compromised artifacts being produced.
            *   **Impact:** Critical - Deployment of applications containing pre-built malicious code.
            *   **Mitigation:** Secure build environments, use dependency scanning and management tools, verify dependency integrity, and implement code signing.

        *   **1.2.2. Artifact Manipulation during Harness Deployment:**
            *   **1.2.2.1. Insecure Artifact Storage/Retrieval by Harness [CRITICAL NODE]:**
                *   **Attack Vector:** Exploiting insecure storage or retrieval mechanisms used by Harness to access build artifacts.
                *   **Exploitation:** If Harness retrieves artifacts from insecure locations (e.g., public S3 buckets without authentication), attackers can replace legitimate artifacts with malicious versions before deployment.
                *   **Impact:** Critical - Deployment of malicious artifacts.
                *   **Mitigation:** Use secure and private artifact repositories with strong authentication, ensure Harness uses secure protocols (HTTPS) for artifact retrieval, and implement artifact integrity checks.

    *   **1.3. Man-in-the-Middle (MITM) on Deployment Communication:**
        *   **1.3.1.2. Compromised Harness Delegate Infrastructure [CRITICAL NODE]:**
            *   **Attack Vector:** Compromising the infrastructure hosting Harness Delegates (agents) that facilitate communication between Harness and deployment targets.
            *   **Exploitation:** If Delegates are compromised, attackers can intercept and manipulate deployment traffic passing through them, potentially altering deployment commands or artifacts in transit.
            *   **Impact:** Critical - Ability to manipulate deployment traffic and potentially inject malicious code or disrupt deployments.
            *   **Mitigation:** Harden Delegate infrastructure, implement network segmentation, monitor Delegate activity, and ensure secure communication channels between Harness and Delegates.

## Attack Tree Path: [2. Exploit Harness Secrets Management [HIGH RISK PATH]](./attack_tree_paths/2__exploit_harness_secrets_management__high_risk_path_.md)

*   **Attack Vector:** Targeting Harness's secrets management to extract sensitive credentials and use them to compromise the application or related infrastructure.
*   **Exploitation:** Exploiting vulnerabilities in secret store access control, insider threats, or indirect exposure of secrets during pipeline execution.
*   **Impact:** Critical - Exposure of sensitive credentials (API keys, passwords) leading to wider compromise.
*   **Mitigation:** Secure Harness secret store access, implement RBAC for secrets, avoid insecure secret usage in pipelines, and regularly audit secret access.

    *   **2.1.2. Insider Threat/Compromised Harness Administrator Account [CRITICAL NODE]:**
        *   **Attack Vector:** Malicious insiders with legitimate Harness access or attackers who have compromised an administrator account directly accessing and exfiltrating secrets stored in Harness.
        *   **Exploitation:** Abusing administrative privileges to view, export, or misuse secrets stored within Harness.
        *   **Impact:** Critical - Direct access to all secrets managed by Harness.
        *   **Mitigation:** Implement strong background checks for personnel with admin access, enforce the principle of least privilege even for administrators, implement robust audit logging of admin actions, and monitor for suspicious secret access patterns.

    *   **2.2. Indirect Secret Exposure via Pipeline Execution [HIGH RISK PATH]:**
        *   **Attack Vector:** Secrets being unintentionally or intentionally exposed during pipeline execution, making them accessible to attackers.
        *   **Exploitation:** Secrets being logged to console output, stored in insecure files created during pipeline execution, or displayed in pipeline execution logs.
        *   **Impact:** Medium to High - Exposure of secrets, potentially leading to unauthorized access.
        *   **Mitigation:** Avoid logging secrets, implement secret scanning in logs, educate developers on secure secret handling, and use Harness secret variables correctly.

        *   **2.2.1. Secrets Logged or Exposed during Pipeline Execution [CRITICAL NODE]:**
            *   **Attack Vector:** Pipeline steps or scripts inadvertently or maliciously logging secrets to accessible logs or outputs during deployment.
            *   **Exploitation:** Poorly written pipeline steps that echo secrets to standard output, or malicious pipelines designed to expose secrets through logging.
            *   **Impact:** Medium to High - Secrets become visible in pipeline execution logs, potentially accessible to unauthorized users.
            *   **Mitigation:** Implement strict policies against logging secrets, use secret masking in logs, and regularly review pipeline logs for accidental secret exposure.

        *   **2.2.2. Secrets Used Insecurely in Deployment Scripts [CRITICAL NODE]:**
            *   **Attack Vector:** Developers using secrets insecurely within deployment scripts, making them vulnerable to exposure.
            *   **Exploitation:**  Secrets being echoed to console in scripts, stored in temporary files that are not properly secured, or passed as command-line arguments that are logged.
            *   **Impact:** Medium to High - Secrets become exposed during script execution, potentially leading to unauthorized access.
            *   **Mitigation:** Educate developers on secure secret handling, enforce secure scripting practices, and use Harness secret variables correctly to avoid direct secret manipulation in scripts.

## Attack Tree Path: [3. Abuse Harness Integrations](./attack_tree_paths/3__abuse_harness_integrations.md)

*   **3.1. Compromise Integrated Source Code Repository (e.g., Git) [HIGH RISK PATH]:**
    *   **Attack Vector:** Compromising the source code repository (like Git) that is integrated with Harness. While not directly a Harness vulnerability, it's a critical indirect attack vector.
    *   **Exploitation:** Gaining unauthorized access to the Git repository and injecting malicious code into the application codebase. Harness will then deploy this compromised code.
    *   **Impact:** Critical - Deployment of applications with malicious code injected at the source.
    *   **Mitigation:** Secure Git repositories with strong access controls, use branch protection, implement code review processes, and monitor for unauthorized code changes.

*   **3.2. Abuse Cloud Provider Integrations [HIGH RISK PATH]:**
    *   **Attack Vector:** Exploiting Harness's integrations with cloud providers (AWS, Azure, GCP) to gain access to and control cloud resources hosting the application.
    *   **Exploitation:** Stealing or compromising cloud provider credentials stored in Harness, or leveraging overly permissive cloud provider permissions granted to Harness.
    *   **Impact:** Critical - Cloud infrastructure compromise, data breaches, and service disruption.
    *   **Mitigation:** Secure cloud provider credentials in Harness, implement the principle of least privilege for cloud provider permissions granted to Harness, and regularly audit cloud provider integration configurations.

        *   **3.2.1. Stolen or Weak Cloud Provider Credentials in Harness [CRITICAL NODE]:**
            *   **Attack Vector:** Compromising cloud provider credentials (API keys, access keys) that are stored within Harness for integration purposes.
            *   **Exploitation:** Stealing credentials through Harness vulnerabilities, insider threats, or weak Harness security practices.
            *   **Impact:** Critical - Unauthorized access to cloud resources.
            *   **Mitigation:** Securely store cloud provider credentials using Harness secrets management, implement RBAC for secret access, and regularly rotate cloud provider credentials.

        *   **3.2.2. Overly Permissive Cloud Provider Permissions Granted to Harness [CRITICAL NODE]:**
            *   **Attack Vector:** Harness being granted excessively broad permissions to cloud resources during integration setup.
            *   **Exploitation:** If Harness is compromised, attackers can leverage these overly permissive permissions to escalate privileges and access cloud resources beyond what is necessary for CI/CD operations.
            *   **Impact:** Critical - Cloud infrastructure compromise and privilege escalation.
            *   **Mitigation:** Adhere to the principle of least privilege when granting cloud provider permissions to Harness, regularly review and refine IAM policies, and monitor Harness's cloud API access.

## Attack Tree Path: [5. Social Engineering/Insider Threat Targeting Harness Users [HIGH RISK PATH]](./attack_tree_paths/5__social_engineeringinsider_threat_targeting_harness_users__high_risk_path_.md)

*   **Attack Vector:** Targeting human users of Harness through social engineering or exploiting malicious insiders to gain access to the platform or compromise pipelines.
*   **Exploitation:** Phishing attacks to steal user credentials, or malicious actions by insiders with legitimate Harness access.
*   **Impact:** High to Critical - Account compromise, pipeline manipulation, secret theft, and application compromise.
*   **Mitigation:** Security awareness training, phishing simulations, insider threat programs, robust logging and monitoring, and background checks for privileged users.

    *   **5.1. Phishing Harness Users for Credentials [HIGH RISK PATH, CRITICAL NODE]:**
        *   **Attack Vector:** Using phishing techniques to trick Harness users into revealing their login credentials.
        *   **Exploitation:** Sending deceptive emails or messages that mimic legitimate Harness login pages to steal usernames and passwords.
        *   **Impact:** High - Account takeover and unauthorized access to Harness.
        *   **Mitigation:** Security awareness training on phishing, email security measures, and encouraging users to report suspicious emails.

    *   **5.2. Malicious Insider with Harness Access [HIGH RISK PATH, CRITICAL NODE]:**
        *   **Attack Vector:** A trusted insider with legitimate Harness access intentionally abusing their privileges to compromise pipelines, secrets, or the application.
        *   **Exploitation:**  Insiders with malicious intent can directly modify pipelines, exfiltrate secrets, or introduce malicious code through their legitimate access.
        *   **Impact:** Critical - Significant damage potential due to insider trust and access.
        *   **Mitigation:** Implement strong background checks, enforce the principle of least privilege, implement robust audit logging and monitoring of user activity, and foster a security-conscious culture.

