# Attack Surface Analysis for robb/cartography

## Attack Surface: [Compromised Cloud Provider Credentials](./attack_surfaces/compromised_cloud_provider_credentials.md)

**Description:** Attackers gain access to the credentials used by Cartography to access cloud providers (AWS, GCP, Azure, etc.).

**How Cartography Contributes:** Cartography requires these credentials to enumerate and collect data about cloud resources. If these credentials are compromised, the attacker inherits Cartography's access.

**Example:** An attacker finds hardcoded AWS access keys in the application's configuration files used by Cartography.

**Impact:** Full access to the organization's cloud infrastructure, potentially leading to data breaches, resource manipulation, and financial loss.

**Risk Severity:** Critical

**Mitigation Strategies:**

* **Never store credentials directly in code or configuration files.**
* **Utilize secure secrets management services (e.g., AWS Secrets Manager, HashiCorp Vault).**
* **Employ the principle of least privilege when granting permissions to the credentials used by Cartography.**  Grant only the necessary read-only permissions for the resources Cartography needs to analyze.
* **Implement robust access controls for the secrets management service.**
* **Regularly rotate cloud provider credentials.**
* **Monitor for unauthorized API calls using the Cartography credentials.

## Attack Surface: [Exposure of Internal Infrastructure Details via Cartography Data Store](./attack_surfaces/exposure_of_internal_infrastructure_details_via_cartography_data_store.md)

**Description:** Sensitive information about the organization's infrastructure, collected and stored by Cartography, is exposed to unauthorized individuals.

**How Cartography Contributes:** Cartography's primary function is to gather and store detailed information about infrastructure. This data, if exposed, reveals valuable attack vectors.

**Example:** The Neo4j database used by Cartography is publicly accessible with default credentials.

**Impact:** Attackers gain a comprehensive understanding of the organization's infrastructure, facilitating targeted attacks, identification of vulnerabilities, and lateral movement.

**Risk Severity:** High

**Mitigation Strategies:**

* **Secure the Cartography data store (e.g., Neo4j) with strong, unique credentials.**
* **Implement network segmentation and firewalls to restrict access to the data store.**
* **Enforce access controls within the data store to limit who can view and manipulate the data.**
* **Consider encrypting the data at rest within the data store.**
* **Regularly back up the Cartography data store and secure the backups.

## Attack Surface: [Vulnerabilities in Cartography Dependencies](./attack_surfaces/vulnerabilities_in_cartography_dependencies.md)

**Description:** Security vulnerabilities exist in the third-party libraries and dependencies used by Cartography.

**How Cartography Contributes:** By relying on these dependencies, Cartography inherits any vulnerabilities present in them.

**Example:** A known vulnerability in a Python library used by Cartography allows for remote code execution.

**Impact:** Potential for remote code execution on the server running Cartography, data breaches, and denial of service.

**Risk Severity:** High

**Mitigation Strategies:**

* **Regularly update Cartography and all its dependencies to the latest versions.**
* **Implement a vulnerability scanning process for dependencies.**
* **Utilize dependency management tools that can identify and alert on known vulnerabilities.**
* **Consider using a software composition analysis (SCA) tool.

