# Attack Surface Analysis for containers/podman

## Attack Surface: [Unauthorized Access to Podman Socket (`podman.sock`)](./attack_surfaces/unauthorized_access_to_podman_socket___podman_sock__.md)

*   **Description:** The `podman.sock` file provides a local interface to control the Podman daemon. If its permissions are too permissive, unauthorized users or processes on the host can execute arbitrary Podman commands.
    *   **How Podman Contributes:** Podman uses this socket as its primary local communication channel, making its security paramount for preventing local privilege escalation.
    *   **Example:** A compromised web server process running on the same host as Podman, with write access to the `podman.sock`, could create a privileged container to take over the system.
    *   **Impact:** Full control over Podman, leading to container creation, execution, and potential host system compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Ensure the `podman.sock` file has restrictive permissions (e.g., `0700` or `0600`) limiting access to the intended user or group.
        *   Avoid running unnecessary services with the same user as the Podman daemon.
        *   Consider using rootless Podman to mitigate the impact of a compromised socket (though rootless has its own considerations).

## Attack Surface: [Podman Remote API Exposure (if enabled)](./attack_surfaces/podman_remote_api_exposure__if_enabled_.md)

*   **Description:** If the Podman API is exposed over a network (using TCP or other methods), it becomes a target for remote attackers.
    *   **How Podman Contributes:** Podman offers the functionality to expose its API remotely for management purposes.
    *   **Example:** An attacker gains access to the network where the Podman API is exposed and, without proper authentication, can create and run malicious containers on the host.
    *   **Impact:** Remote code execution, data exfiltration, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Avoid exposing the Podman API over the network unless absolutely necessary.
        *   Implement strong authentication and authorization mechanisms (e.g., TLS client certificates) for the remote API.
        *   Use network segmentation and firewalls to restrict access to the API.

## Attack Surface: [Vulnerabilities in Podman Extensions/Plugins](./attack_surfaces/vulnerabilities_in_podman_extensionsplugins.md)

*   **Description:** If using Podman extensions or plugins, vulnerabilities within these third-party components can introduce new attack vectors directly into the Podman ecosystem.
    *   **How Podman Contributes:** Podman's architecture allows for the integration of extensions and plugins, making it reliant on their security.
    *   **Example:** A malicious Podman extension is installed that grants unauthorized access to the Podman daemon or the host system through a flaw in the extension's code or the Podman extension API.
    *   **Impact:** Depends on the privileges and functionality of the vulnerable extension, potentially leading to full system compromise.
    *   **Risk Severity:** High (when extensions have significant privileges or expose critical functionality)
    *   **Mitigation Strategies:**
        *   Only install trusted and well-vetted Podman extensions.
        *   Keep extensions updated to the latest versions to patch known vulnerabilities.
        *   Regularly review the installed extensions and their permissions.
        *   Consider the principle of least privilege for extensions, limiting their access to Podman functionalities.

