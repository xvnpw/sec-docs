# Threat Model Analysis for containers/podman

## Threat: [Exploiting Unprotected Podman Socket](./threats/exploiting_unprotected_podman_socket.md)

**Description:** If the Podman socket (used for the Podman API) is not properly secured with appropriate permissions, a malicious user or process on the host system could connect to it and issue commands to manage containers. This could lead to unauthorized container creation, deletion, or modification, potentially disrupting the application or compromising data.

**Impact:** Unauthorized container management, data manipulation, denial of service.

**Affected Podman Component:** Podman API, Podman Socket.

**Risk Severity:** High

**Mitigation Strategies:**
- Ensure the Podman socket has restricted permissions, allowing only authorized users or groups to access it.
- Consider using a dedicated user for running Podman and restrict access to that user.
- If remote access to the Podman API is required, use secure transport mechanisms like TLS and implement strong authentication.

## Threat: [Resource Exhaustion Leading to Denial of Service](./threats/resource_exhaustion_leading_to_denial_of_service.md)

**Description:** A malicious or compromised container could be designed to consume excessive resources (CPU, memory, disk I/O) on the host system. This could starve other containers or the host itself of resources, leading to a denial of service for the application or even the entire system.

**Impact:** Application downtime, system instability, performance degradation.

**Affected Podman Component:** Resource Management (cgroups).

**Risk Severity:** High

**Mitigation Strategies:**
- Implement resource limits (CPU, memory, disk I/O) for containers using Podman's resource management features.
- Monitor container resource usage and set up alerts for abnormal consumption.
- Implement mechanisms to automatically restart or isolate containers exhibiting excessive resource usage.

## Threat: [Privilege Escalation via Capabilities Misconfiguration](./threats/privilege_escalation_via_capabilities_misconfiguration.md)

**Description:** Granting unnecessary Linux capabilities to a container (e.g., `CAP_SYS_ADMIN`) can provide avenues for an attacker within the container to escalate their privileges and potentially gain root access on the host system.

**Impact:** Container compromise, potential host compromise, ability to control other containers or the host infrastructure.

**Affected Podman Component:** Container Configuration, Capability Management.

**Risk Severity:** High

**Mitigation Strategies:**
- Follow the principle of least privilege and only grant necessary capabilities to containers.
- Carefully review the capabilities required by the application running in the container.
- Utilize security profiles like SELinux or AppArmor to further restrict container capabilities beyond standard capabilities.

## Threat: [Vulnerabilities in Podman API](./threats/vulnerabilities_in_podman_api.md)

**Description:** Vulnerabilities in the Podman API itself could be exploited by attackers to perform unauthorized actions, such as creating, deleting, or modifying containers. This could be achieved through local access to the socket or, if the API is exposed remotely, through network attacks.

**Impact:** Unauthorized container management, data manipulation, denial of service.

**Affected Podman Component:** Podman API.

**Risk Severity:** High

**Mitigation Strategies:**
- Keep Podman updated to the latest version to patch known vulnerabilities.
- If exposing the Podman API remotely, use strong authentication and authorization mechanisms (e.g., TLS client certificates).
- Restrict network access to the Podman API to only trusted sources.

