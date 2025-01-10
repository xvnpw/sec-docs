# Threat Model Analysis for airflow-helm/charts

## Threat: [Default Database Credentials Exploitation](./threats/default_database_credentials_exploitation.md)

**Description:** The `airflow-helm/charts` deploy the database (e.g., PostgreSQL) without enforcing or guiding users to change the default credentials. An attacker can exploit these well-known default credentials to gain full access to the Airflow metadata database. This allows them to read, modify, or delete sensitive information, including connection details, DAG definitions, and execution logs, potentially leading to complete compromise of the Airflow installation.

**Impact:** Full compromise of the Airflow installation, potential data breaches by accessing sensitive connection details, manipulation of workflows leading to incorrect data processing or malicious actions, and denial of service by deleting critical data.

**Affected Component:** PostgreSQL deployment managed by the chart (specifically the initial setup and lack of enforced secure configuration).

**Risk Severity:** Critical

**Mitigation Strategies:**
* The Helm chart MUST enforce or provide clear and prominent guidance to change all default database credentials during or immediately after the initial deployment.
* The chart should offer mechanisms (e.g., using `values.yaml`) to easily configure secure, unique passwords for the database.
* Leverage Kubernetes Secrets for managing database credentials, ensuring the chart's templates are designed to use these secrets.

## Threat: [Exposed Internal Services due to Lack of Network Policies](./threats/exposed_internal_services_due_to_lack_of_network_policies.md)

**Description:** The `airflow-helm/charts` create Kubernetes Services for internal components like the database or Redis, potentially without deploying or strongly recommending the use of Kubernetes Network Policies. This exposes these services within the Kubernetes cluster, allowing unauthorized access from other pods or namespaces. An attacker compromising another application within the cluster could then directly access these critical Airflow dependencies and exploit vulnerabilities or access sensitive data.

**Impact:** Data breaches by accessing the database or Redis, potential for remote code execution if vulnerabilities exist in these services, and denial of service by overwhelming the services. This can lead to the complete failure of the Airflow deployment.

**Affected Component:** Kubernetes Service definitions for PostgreSQL, Redis, and potentially other internal components created by the chart, and the lack of accompanying NetworkPolicy definitions.

**Risk Severity:** High

**Mitigation Strategies:**
* The Helm chart MUST either deploy default restrictive Kubernetes Network Policies or provide clear and prominent instructions on how to implement them.
* The chart should offer configuration options within `values.yaml` to easily define and deploy Network Policies.
* Emphasize the importance of network segmentation and the principle of least privilege for internal communication within the cluster.

## Threat: [Insecurely Managed Secrets via Default Chart Configuration](./threats/insecurely_managed_secrets_via_default_chart_configuration.md)

**Description:** The `airflow-helm/charts` might, by default or through easily configurable options, store sensitive information like database passwords, API keys, or other credentials as Kubernetes Secrets without ensuring proper encryption at rest or with overly permissive access controls. An attacker gaining access to the Kubernetes API or a compromised node can easily retrieve these secrets due to the chart's default configurations or lack of secure secret management enforcement.

**Impact:** Exposure of sensitive credentials leading to further compromise of connected systems, data breaches, and unauthorized access to external services. This can have cascading effects beyond the Airflow deployment itself.

**Affected Component:** Kubernetes Secret resources created by the chart and the chart's mechanisms for handling and storing sensitive information.

**Risk Severity:** High

**Mitigation Strategies:**
* The Helm chart MUST guide users towards secure secret management practices, such as using Kubernetes Secrets with encryption at rest (cluster-level configuration) or recommending tools like HashiCorp Vault or Sealed Secrets.
* The chart's templates should be designed to facilitate the use of external secret management solutions.
* Avoid storing sensitive information directly within the chart's `values.yaml` or ConfigMaps without proper encryption.

## Threat: [Overly Permissive RBAC Roles Created by the Chart](./threats/overly_permissive_rbac_roles_created_by_the_chart.md)

**Description:** The `airflow-helm/charts` might create Kubernetes RoleBindings or ClusterRoleBindings that grant excessive permissions to the Airflow components' ServiceAccounts by default or through easily enabled configurations. A compromised Airflow component could then perform actions beyond its intended scope within the Kubernetes cluster, such as creating or deleting resources, accessing secrets it shouldn't, or even escalating privileges, due to the chart's overly permissive default RBAC settings.

**Impact:** Lateral movement within the Kubernetes cluster, potential for infrastructure compromise, and exfiltration of sensitive information from other namespaces or resources. This can significantly broaden the impact of a compromise within the Airflow deployment.

**Affected Component:** Kubernetes Role, ClusterRole, RoleBinding, and ClusterRoleBinding resources created by the chart.

**Risk Severity:** High

**Mitigation Strategies:**
* The Helm chart MUST adhere to the principle of least privilege when defining default RBAC rules.
* Provide granular control over the permissions granted to Airflow components through configurable options in `values.yaml`.
* Clearly document the default RBAC settings and guide users on how to restrict permissions further based on their specific needs.

## Threat: [Insecure Ingress Configuration Enabled by the Chart](./threats/insecure_ingress_configuration_enabled_by_the_chart.md)

**Description:** If the `airflow-helm/charts` deploy an Ingress resource for accessing the Airflow webserver by default or through simple configuration, it might introduce security vulnerabilities if not configured correctly. This includes missing TLS configuration, weak cipher suites, or lack of rate limiting. Attackers can exploit these misconfigurations to intercept traffic, perform man-in-the-middle attacks, or overwhelm the service with requests, directly due to the chart's Ingress deployment choices.

**Impact:** Exposure of user credentials and sensitive data transmitted to the webserver, potential for session hijacking, and denial of service, making the Airflow web interface unavailable.

**Affected Component:** Kubernetes Ingress resource definition managed by the chart.

**Risk Severity:** High

**Mitigation Strategies:**
* The Helm chart MUST enforce or strongly recommend TLS configuration for the Ingress, potentially leveraging cert-manager integration.
* Provide options within `values.yaml` to configure TLS settings, including specifying secure cipher suites.
* Recommend or provide options for implementing rate limiting and other security measures at the Ingress level.

