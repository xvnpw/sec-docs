# Attack Surface Analysis for containerd/containerd

## Attack Surface: [Unauthorized API Access](./attack_surfaces/unauthorized_api_access.md)

*Description:* Gaining unauthorized control over the containerd gRPC API, allowing manipulation of containers and potentially the host.
*How containerd contributes:* containerd's core functionality is controlled via this API, making it a central point of attack. The API's design and implementation are directly attributable to containerd.
*Example:* An attacker exploits a misconfigured service to gain access to the containerd socket file (`/run/containerd/containerd.sock`).
*Impact:* Complete compromise of all containers managed by containerd, potential host compromise, data exfiltration, denial of service.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Socket Permissions:** Ensure the containerd socket file has the most restrictive permissions possible (e.g., `0600`, owned by the user running containerd and the appropriate group).
    *   **User/Group Management:** Use a dedicated system user and group for containerd.
    *   **Network Exposure (Avoid if Possible):** *Strongly* discourage exposing the containerd API over a network. If necessary, use mutual TLS (mTLS) and strict network access controls.
    *   **Auditing:** Enable audit logging for the containerd socket.
    *   **API Authentication/Authorization (Future):** Monitor for future containerd releases with built-in API security features.

## Attack Surface: [Malicious Container Images (Pulling and Verification)](./attack_surfaces/malicious_container_images__pulling_and_verification_.md)

*Description:* Running container images containing malware, vulnerabilities, or backdoors, specifically focusing on containerd's role in pulling and verifying these images.
*How containerd contributes:* containerd is *directly* responsible for pulling images from registries and (optionally) verifying their signatures. Its configuration determines which registries are trusted and whether signature verification is enforced.
*Example:* containerd is configured to pull images from a public registry without signature verification, and an attacker publishes a malicious image.
*Impact:* Code execution within the container, potential container escape, data breaches.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Trusted Registries Only:** Configure containerd to *only* pull images from trusted registries.
    *   **Image Signing and Verification:** Implement image signing (e.g., Notary, cosign) and configure containerd to *require* signature verification before running images. This is a *direct* configuration of containerd.
    *   **Image Scanning (Integration):** While scanning itself isn't solely containerd's responsibility, integrate the results into containerd's image pull policies (e.g., through admission controllers in Kubernetes, which interact with containerd).

## Attack Surface: [Shim Vulnerabilities (e.g., containerd-shim-runc-v2)](./attack_surfaces/shim_vulnerabilities__e_g___containerd-shim-runc-v2_.md)

*Description:* Exploiting vulnerabilities in the containerd shim process, which is responsible for managing the container's lifecycle.
*How containerd Contributes:* The shim is a core, *integral* component of containerd's architecture. Vulnerabilities in the shim are directly attributable to containerd's design and implementation.
*Example:* An attacker exploits a race condition in containerd-shim-runc-v2 to gain elevated privileges or escape the container.
*Impact:* Container escape, privilege escalation, denial of service.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Keep Containerd Updated:** The primary mitigation is to keep containerd (and thus its shims) updated to the latest stable release. This is a *direct* action related to containerd.
    *   **Monitor CVEs:** Actively monitor for CVEs related to containerd and its shims.
    *   **Security Profiles (Indirect):** While seccomp/AppArmor/SELinux are OS-level, their effective use *limits the impact* of a shim vulnerability.

