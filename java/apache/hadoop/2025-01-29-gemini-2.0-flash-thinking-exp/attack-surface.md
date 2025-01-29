# Attack Surface Analysis for apache/hadoop

## Attack Surface: [Weak or Missing Authentication](./attack_surfaces/weak_or_missing_authentication.md)

- **Description:** Lack of proper authentication allows unauthorized access to Hadoop services and data.
- **Hadoop Contribution:** Hadoop defaults often have authentication disabled or use simple mechanisms, making it inherently vulnerable.
- **Example:** Anonymous access to NameNode allows listing HDFS files and potentially reading data without credentials.
- **Impact:** Data breaches, unauthorized data modification, denial of service, cluster takeover.
- **Risk Severity:** Critical
- **Mitigation Strategies:**
    - Enable Kerberos authentication for all Hadoop components.
    - Disable anonymous access to all Hadoop services.
    - Enforce strong password policies if using password-based authentication (discouraged).

## Attack Surface: [Insufficient Authorization and Access Control](./attack_surfaces/insufficient_authorization_and_access_control.md)

- **Description:** Inadequate authorization allows users to access resources beyond their intended permissions within Hadoop.
- **Hadoop Contribution:** Misconfigured HDFS and YARN ACLs, overly permissive default permissions in Hadoop components.
- **Example:** A user with access to one HDFS directory can, due to misconfigured ACLs, read data in another restricted directory.
- **Impact:** Data breaches, unauthorized data modification, privilege escalation.
- **Risk Severity:** High
- **Mitigation Strategies:**
    - Implement fine-grained ACLs in HDFS and YARN based on the principle of least privilege.
    - Regularly review and audit ACL configurations.
    - Utilize centralized authorization management tools like Apache Ranger or Sentry.

## Attack Surface: [Data-at-Rest Encryption Not Enabled](./attack_surfaces/data-at-rest_encryption_not_enabled.md)

- **Description:** Sensitive data in HDFS is not encrypted when stored, making it vulnerable to physical storage compromise.
- **Hadoop Contribution:** Hadoop does not enable data-at-rest encryption by default, requiring explicit configuration.
- **Example:** A stolen hard drive from a DataNode exposes unencrypted sensitive data stored in HDFS.
- **Impact:** Data breaches, compliance violations.
- **Risk Severity:** High
- **Mitigation Strategies:**
    - Enable HDFS Transparent Encryption or encryption zones.
    - Encrypt data at the application level before storing in HDFS.
    - Securely manage encryption keys using a dedicated key management system.

## Attack Surface: [Data-in-Transit Encryption Not Enforced](./attack_surfaces/data-in-transit_encryption_not_enforced.md)

- **Description:** Unencrypted communication between Hadoop components and clients exposes data during network transmission.
- **Hadoop Contribution:** Hadoop RPC and web UIs may use unencrypted protocols by default.
- **Example:** Network traffic between DataNodes and NameNode containing data blocks is intercepted and read.
- **Impact:** Data breaches, man-in-the-middle attacks, data manipulation.
- **Risk Severity:** High
- **Mitigation Strategies:**
    - Enable RPC encryption using Kerberos or SASL for Hadoop inter-component communication.
    - Configure HTTPS for all Hadoop web UIs.
    - Utilize network segmentation to isolate Hadoop traffic.

## Attack Surface: [Component-Specific Vulnerabilities (HDFS, YARN)](./attack_surfaces/component-specific_vulnerabilities__hdfs__yarn_.md)

- **Description:** Exploitable vulnerabilities within Hadoop core components like NameNode, DataNode, ResourceManager, NodeManager.
- **Hadoop Contribution:** Complexity of Hadoop components can lead to exploitable vulnerabilities in their code.
- **Example:** A vulnerability in NameNode allows remote code execution, leading to cluster takeover.
- **Impact:** Data breaches, data corruption, denial of service, cluster instability, complete cluster compromise.
- **Risk Severity:** High to Critical (depending on the specific vulnerability)
- **Mitigation Strategies:**
    - Keep Hadoop up-to-date with the latest security patches and versions.
    - Monitor Hadoop security advisories and apply patches promptly.
    - Implement intrusion detection and prevention systems.
    - Regularly perform vulnerability scanning of Hadoop components.

## Attack Surface: [Code Injection in Jobs (MapReduce, Spark on Hadoop)](./attack_surfaces/code_injection_in_jobs__mapreduce__spark_on_hadoop_.md)

- **Description:** User-provided code in Hadoop jobs can be exploited for code injection, allowing malicious code execution on the cluster.
- **Hadoop Contribution:** Hadoop's architecture executes user-submitted code in jobs, creating a potential code injection vector.
- **Example:** A malicious MapReduce job injects code to execute system commands on NodeManagers, gaining unauthorized access.
- **Impact:** Arbitrary code execution, privilege escalation, data breaches, cluster compromise.
- **Risk Severity:** High to Critical
- **Mitigation Strategies:**
    - Implement strict input validation and sanitization for user-provided code in jobs.
    - Enforce secure coding practices for job development.
    - Utilize containerization and sandboxing to isolate job execution.
    - Implement resource limits and monitoring for jobs.

## Attack Surface: [Insecure Default Configurations & Critical Misconfigurations](./attack_surfaces/insecure_default_configurations_&_critical_misconfigurations.md)

- **Description:** Hadoop's default configurations are often insecure, and critical misconfigurations can create severe vulnerabilities.
- **Hadoop Contribution:** Hadoop defaults prioritize ease of setup over security, and complex configurations are prone to errors.
- **Example:** Leaving default passwords unchanged or misconfiguring security settings during Hadoop deployment.
- **Impact:** Unauthorized access, data breaches, denial of service, cluster compromise.
- **Risk Severity:** High to Critical (depending on the misconfiguration)
- **Mitigation Strategies:**
    - Harden Hadoop configurations based on security best practices and hardening guides.
    - Change all default passwords and credentials.
    - Regularly audit and review Hadoop configurations for security weaknesses.
    - Use configuration management tools to enforce secure configurations.

