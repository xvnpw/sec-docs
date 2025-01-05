# Attack Surface Analysis for openfaas/faas

## Attack Surface: [Malicious Function Deployment](./attack_surfaces/malicious_function_deployment.md)

**Description:** An attacker deploys a function containing malicious code.

**How FaaS Contributes:** OpenFaaS's core functionality of allowing users to deploy arbitrary container images as functions provides a direct pathway for introducing malicious code into the environment.

**Example:** An attacker deploys a function designed to exfiltrate data from other functions or the underlying infrastructure.

**Impact:** Data breach, compromise of internal systems, denial of service, resource hijacking.

**Risk Severity:** Critical

**Mitigation Strategies:**

* Implement strict access control for function deployment (e.g., using RBAC in Kubernetes and OpenFaaS).
* Enforce code review and security scanning of function code and dependencies before deployment.
* Utilize trusted and verified base images and regularly update them.
* Implement network segmentation to limit the potential impact of compromised functions.

## Attack Surface: [Unauthenticated Function Invocation](./attack_surfaces/unauthenticated_function_invocation.md)

**Description:** Functions can be invoked without proper authentication.

**How FaaS Contributes:**  The OpenFaaS gateway is responsible for enforcing authentication. Misconfiguration or lack of authentication setup directly exposes functions.

**Example:** An attacker directly calls a function that modifies critical system configurations or accesses sensitive data without authorization.

**Impact:** Unauthorized access to sensitive data or functionality, data manipulation, service disruption, potential for privilege escalation if functions interact with other systems.

**Risk Severity:** Critical

**Mitigation Strategies:**

* **Mandatory** configuration of authentication on the OpenFaaS gateway (e.g., using API keys, OAuth 2.0).
* Implement authorization checks within functions to verify the identity and permissions of the caller, even if gateway authentication is in place.
* Secure the gateway's service definition and ingress configuration to prevent bypassing authentication mechanisms.

## Attack Surface: [OpenFaaS Gateway Vulnerabilities](./attack_surfaces/openfaas_gateway_vulnerabilities.md)

**Description:** Security vulnerabilities within the OpenFaaS gateway component itself.

**How FaaS Contributes:** The gateway is a core component of OpenFaaS, acting as the central point of entry for function invocations. Vulnerabilities here directly impact the security of the entire FaaS platform.

**Example:** A vulnerability in the gateway's routing logic allows an attacker to bypass authentication or access internal functions without proper authorization.

**Impact:** Complete compromise of the OpenFaaS deployment, unauthorized access to functions and data, denial of service, potential for taking control of the underlying infrastructure.

**Risk Severity:** Critical

**Mitigation Strategies:**

* Keep the OpenFaaS gateway components (e.g., `faas`, `nats-streaming`, `prometheus` if exposed) updated to the latest stable and secure versions.
* Follow security best practices for the underlying infrastructure hosting the gateway (e.g., secure OS configuration, firewall rules, network segmentation).
* Regularly review the gateway's configuration for potential security misconfigurations.

## Attack Surface: [Insecure Secrets Management](./attack_surfaces/insecure_secrets_management.md)

**Description:** Sensitive information (like API keys, database credentials) used by functions is not managed securely within OpenFaaS.

**How FaaS Contributes:** OpenFaaS provides mechanisms for injecting secrets into functions. Improper usage of these mechanisms or reliance on insecure methods exposes secrets.

**Example:** Secrets are stored as plain text environment variables within the function container definition in OpenFaaS, making them easily accessible if the container is compromised or through introspection of the OpenFaaS deployment.

**Impact:** Exposure of sensitive credentials, leading to unauthorized access to other systems, data breaches, and potential lateral movement within the infrastructure.

**Risk Severity:** High

**Mitigation Strategies:**

* **Mandatory** utilization of OpenFaaS secrets management features backed by secure storage (e.g., Kubernetes Secrets with encryption at rest).
* Avoid hardcoding secrets in function code or directly in environment variables within function deployments.
* Implement strict access control for accessing and managing secrets within the OpenFaaS platform.
* Consider using a dedicated secrets management solution integrated with OpenFaaS for enhanced security and auditing.

## Attack Surface: [Resource Exhaustion Attacks](./attack_surfaces/resource_exhaustion_attacks.md)

**Description:** Attackers send excessive requests to functions, consuming resources and causing denial of service of the OpenFaaS platform or individual functions.

**How FaaS Contributes:** The ease of deploying and invoking functions in OpenFaaS can be exploited if proper resource limits and rate limiting are not in place.

**Example:** An attacker floods a specific function endpoint with requests, overwhelming the function's resources and potentially impacting other functions sharing the same infrastructure.

**Impact:** Service disruption, impacting the availability of functions and potentially the entire application relying on those functions.

**Risk Severity:** High

**Mitigation Strategies:**

* Implement rate limiting on the OpenFaaS gateway to restrict the number of requests from a single source or to specific functions.
* Set appropriate resource limits (CPU, memory) for functions to prevent individual functions from consuming excessive resources.
* Implement monitoring of function resource usage and configure auto-scaling to handle legitimate traffic spikes while mitigating malicious overload.
* Consider implementing request queuing or circuit breakers to protect against cascading failures.

