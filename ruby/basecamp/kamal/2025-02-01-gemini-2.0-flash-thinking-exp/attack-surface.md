# Attack Surface Analysis for basecamp/kamal

## Attack Surface: [Exposed Kamal Agent Port](./attack_surfaces/exposed_kamal_agent_port.md)

*   **Description:** The Kamal Agent listens on a network port (default 9292/tcp) to receive commands from the Kamal client.
*   **Kamal Contribution:** Kamal *requires* this port to be open for agent communication and deployment orchestration. This is a fundamental aspect of Kamal's architecture.
*   **Example:** An attacker scans public IP ranges, identifies an open port 9292, and attempts to communicate with the Kamal Agent without proper authentication. If the shared secret is weak or compromised, they could gain control.
*   **Impact:** Remote code execution on the target server, service disruption, data breaches, unauthorized access to infrastructure.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Network Segmentation:** Restrict access to the agent port using firewalls or security groups. Only allow connections from trusted networks (e.g., CI/CD pipeline, developer VPN).
    *   **Strong Shared Secret:** Use a strong, randomly generated shared secret for agent authentication.
    *   **Secret Rotation:** Regularly rotate the shared secret.
    *   **VPN/Bastion Host:** Access the agent port through a VPN or bastion host for an added layer of security.

## Attack Surface: [Compromised Kamal Shared Secret](./attack_surfaces/compromised_kamal_shared_secret.md)

*   **Description:** The shared secret (`secret` in `deploy.yml`) is used to authenticate communication between the Kamal client and agent.
*   **Kamal Contribution:** Kamal *directly relies* on this shared secret for its authentication mechanism. The security of Kamal deployments is fundamentally tied to the secrecy of this key.
*   **Example:** The shared secret is accidentally committed to a public repository, leaked in logs, or obtained through social engineering. An attacker uses this secret with the Kamal client to send malicious commands to the agent.
*   **Impact:** Unauthorized control over deployed applications and infrastructure, service disruption, data breaches, remote code execution.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Secure Secret Management:** Store the shared secret securely using dedicated secret management solutions (e.g., HashiCorp Vault, AWS Secrets Manager).
    *   **Avoid Storing in Version Control:** Never commit the shared secret directly to version control.
    *   **Environment Variables/Secret Files:**  Use environment variables or securely managed files to provide the secret to the Kamal client.
    *   **Access Control:** Restrict access to the `deploy.yml` file and any systems where the secret is stored.

## Attack Surface: [Insecure Secret Management during Deployment (Kamal Orchestrated)](./attack_surfaces/insecure_secret_management_during_deployment__kamal_orchestrated_.md)

*   **Description:**  Secrets (database credentials, API keys) need to be securely transferred and managed within deployed containers during the Kamal orchestrated deployment process.
*   **Kamal Contribution:** Kamal *orchestrates* the deployment process, and how secrets are handled during this process is directly influenced by Kamal's configuration and features (or lack thereof if insecure methods are chosen).
*   **Example:** Secrets are passed as plain text environment variables during container deployment *because the user chose an insecure method within Kamal's deployment configuration*, making them visible in process listings or container inspection.
*   **Impact:** Exposure of sensitive application secrets, leading to unauthorized access to databases, APIs, and other services.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Docker Secrets:** Utilize Docker Secrets for managing sensitive data within containers. *Kamal supports using Docker Secrets and this should be the preferred method.*
    *   **Environment Variables (Securely Managed):** Use environment variables, but ensure they are managed securely and not exposed in insecure ways (e.g., avoid logging them). *If using environment variables, ensure Kamal's configuration doesn't expose them insecurely.*
    *   **External Secret Management Systems:** Integrate with external secret management systems (e.g., Vault, Secrets Manager) to inject secrets into containers at runtime. *If Kamal is extended to support this, it would be a more secure approach.*
    *   **Minimize Secrets in Images:** Avoid baking secrets directly into Docker images. *This is a general best practice, but relevant in the context of Kamal deployed images.*

## Attack Surface: [Vulnerabilities in Kamal Agent or Client Software](./attack_surfaces/vulnerabilities_in_kamal_agent_or_client_software.md)

*   **Description:**  Vulnerabilities in the Kamal Agent or CLI code itself, or their dependencies.
*   **Kamal Contribution:** Kamal *introduces* its own codebase and dependencies into the deployment process. These are specific components that are part of the attack surface *because* Kamal is used.
*   **Example:** A zero-day vulnerability is discovered in the Kamal Agent. An attacker exploits this vulnerability through the exposed agent port to gain remote code execution on the server.
*   **Impact:** Remote code execution, privilege escalation, denial of service on target servers or developer machines.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Keep Kamal Updated:** Regularly update Kamal Agent and CLI to the latest versions to patch known vulnerabilities.
    *   **Vulnerability Monitoring:** Monitor security advisories and release notes for Kamal and its dependencies.
    *   **Dependency Scanning:**  Scan Kamal Agent and CLI dependencies for vulnerabilities.
    *   **Security Audits:** Conduct security audits of the Kamal codebase and deployment processes.

## Attack Surface: [Compromised SSH Keys for Server Access (Used by Kamal)](./attack_surfaces/compromised_ssh_keys_for_server_access__used_by_kamal_.md)

*   **Description:** SSH keys *used by Kamal* to access target servers are compromised.
*   **Kamal Contribution:** Kamal *relies* on SSH for communication and command execution on target servers. The security of SSH access is critical for Kamal's operation.
*   **Example:** A developer's private SSH key *used for Kamal deployments* is stolen from their machine. An attacker uses this key to SSH into the target servers and bypass Kamal's intended deployment process, gaining direct access.
*   **Impact:** Unauthorized access to target servers, ability to modify or disrupt applications and infrastructure.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Secure SSH Key Management:** Securely store and manage SSH private keys *used for Kamal*. Use strong passphrases.
    *   **Key Rotation:** Regularly rotate SSH keys *used for Kamal*.
    *   **Restrict Key Access:** Limit access to private keys *used for Kamal* to authorized personnel and systems.
    *   **SSH Key Agents:** Utilize SSH key agents to avoid storing private keys directly on disk.
    *   **Disable Password Authentication:** Disable password-based SSH authentication on target servers and rely solely on key-based authentication. *This is a general SSH hardening, but crucial for Kamal's secure operation.*

