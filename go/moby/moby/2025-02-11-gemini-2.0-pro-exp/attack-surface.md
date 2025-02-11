# Attack Surface Analysis for moby/moby

## Attack Surface: [1. Unauthenticated/Unauthorized Docker API Access](./attack_surfaces/1__unauthenticatedunauthorized_docker_api_access.md)

*   **Description:**  Direct access to the Docker API without proper authentication or authorization controls.
    *   **Moby Contribution:** Moby exposes the Docker API, which is the primary control interface for the engine.  Its default configuration (historically) and potential misconfigurations can leave it exposed.
    *   **Example:** An attacker finds a Docker daemon listening on `tcp://0.0.0.0:2375` (unencrypted) without authentication.  They use `curl` or the Docker CLI to create a privileged container that mounts the host's root filesystem.
    *   **Impact:** Complete host compromise.  The attacker gains root-level access to the host operating system and all its data.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Enable TLS:**  Always use TLS encryption for the Docker API (both client and server certificates).  This prevents eavesdropping and MitM attacks.
        *   **Strong Authentication:** Implement robust authentication mechanisms.  Avoid default credentials.  Consider using mutual TLS authentication.
        *   **Network Segmentation:**  Restrict access to the Docker API to trusted networks/hosts using firewalls or network policies.  Do *not* expose it to the public internet unless absolutely necessary and with extreme caution.
        *   **Authorization Plugins:** Use authorization plugins to implement fine-grained access control (e.g., limiting which users/roles can perform specific API actions).
        *   **Regular Auditing:**  Monitor API access logs for suspicious activity.

## Attack Surface: [2. Container Escape (Runtime Vulnerability)](./attack_surfaces/2__container_escape__runtime_vulnerability_.md)

*   **Description:**  A vulnerability in the container runtime (containerd/runc) or the kernel that allows a process inside a container to break out and gain access to the host.
    *   **Moby Contribution:** Moby relies on containerd and runc for container execution and isolation.  Vulnerabilities in these components directly impact Moby's security.
    *   **Example:** A zero-day vulnerability in runc allows a specially crafted container image to overwrite the host's runc binary upon container startup, granting the attacker root access. (CVE-2019-5736 is a real-world example).
    *   **Impact:** Host compromise.  The attacker gains control of the host operating system.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Keep Runtime Updated:**  Apply security updates for containerd, runc, and the host kernel *immediately* when they become available.  This is the most crucial mitigation.
        *   **Seccomp Profiles:** Use seccomp profiles to restrict the system calls that a container can make.  This limits the potential attack surface for kernel exploits.
        *   **AppArmor/SELinux:**  Enable and configure AppArmor or SELinux to enforce mandatory access control policies on containers.
        *   **User Namespaces:**  Use user namespaces to map container UIDs to unprivileged UIDs on the host.  This reduces the impact of a successful escape.
        *   **Read-Only Root Filesystem:**  Run containers with a read-only root filesystem whenever possible.  This prevents attackers from modifying system files.
        *   **Limit Capabilities:**  Drop unnecessary Linux capabilities from containers (e.g., `CAP_SYS_ADMIN`).  Follow the principle of least privilege.
        *   **Consider gVisor/Kata:** Explore using alternative container runtimes like gVisor or Kata Containers, which provide stronger isolation through sandboxing or lightweight VMs.

## Attack Surface: [3. Image Poisoning/Spoofing](./attack_surfaces/3__image_poisoningspoofing.md)

*   **Description:**  An attacker tricks a user or system into pulling and running a malicious container image.
    *   **Moby Contribution:** Moby's image pulling and management mechanisms are susceptible to these attacks if not properly secured.
    *   **Example:** An attacker publishes an image named `ubuntu:latest` on a public registry that contains a backdoor.  An unsuspecting user pulls and runs this image.  Alternatively, an attacker compromises a private registry and replaces a legitimate image with a malicious one.
    *   **Impact:**  Varies depending on the malicious image's payload.  Could range from data exfiltration to complete container or host compromise.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use Trusted Registries:**  Pull images only from trusted registries (e.g., Docker Hub's official images, a private registry with strong security controls).
        *   **Docker Content Trust (Notary):**  Enable Docker Content Trust to verify the integrity and publisher of images using digital signatures.
        *   **Image Scanning:**  Use image vulnerability scanners (e.g., Clair, Trivy, Anchore) to identify known vulnerabilities in image layers *before* running them.
        *   **Short-Lived Images:**  Regularly rebuild images from trusted base images to incorporate the latest security patches.
        *   **Restrict Image Pulls:** Configure the Docker daemon to only allow pulling images from specific registries or with specific signatures.

## Attack Surface: [4. Docker Socket Exposure (Local Privilege Escalation)](./attack_surfaces/4__docker_socket_exposure__local_privilege_escalation_.md)

*   **Description:**  A local user on the host gains unauthorized access to the Docker daemon through the Unix socket (`/var/run/docker.sock`).
    *   **Moby Contribution:** Moby uses the Unix socket as the default communication channel for the Docker CLI and other local tools.
    *   **Example:** A user with write access to `/var/run/docker.sock` (often by being a member of the `docker` group) can create a privileged container that mounts the host's root filesystem, effectively gaining root access.
    *   **Impact:**  Local privilege escalation to root on the host.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Restrict Socket Access:**  Ensure the socket has correct permissions (typically `root:docker` with `660` permissions).
        *   **Avoid `docker` Group for Untrusted Users:**  Do *not* add untrusted users to the `docker` group.  This group grants near-root privileges.
        *   **Use Docker Contexts:**  Use Docker contexts to manage connections to different Docker daemons (including remote ones) securely.
        *   **Consider Rootless Mode:** Explore using Docker in rootless mode, which runs the daemon and containers without root privileges. This significantly reduces the attack surface.

## Attack Surface: [5. Build-Time Vulnerabilities (Malicious Dockerfile)](./attack_surfaces/5__build-time_vulnerabilities__malicious_dockerfile_.md)

* **Description:** Introduction of vulnerabilities during the image building process, often through a compromised or poorly written Dockerfile.
    * **Moby Contribution:** Moby's build system (BuildKit) executes the instructions in the Dockerfile.
    * **Example:** A Dockerfile uses `ADD` to copy a malicious script from an untrusted URL into the image, or it installs a vulnerable version of a package.
    * **Impact:** Compromised container image, leading to potential container or host compromise when the image is run.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Multi-Stage Builds:** Use multi-stage builds to separate build dependencies from the final runtime image, reducing the attack surface.
        * **Trusted Base Images:** Start from minimal, trusted base images (e.g., official images from Docker Hub, or images from a well-maintained private registry).
        * **Avoid `ADD` with URLs:** Prefer `COPY` for local files. If using `ADD` with a URL, verify the source's integrity.
        * **Pin Package Versions:** Specify precise versions for all packages installed in the Dockerfile to avoid accidentally pulling in vulnerable versions.
        * **Dockerfile Linters:** Use Dockerfile linters (e.g., hadolint) to identify potential security issues and best practice violations.
        * **Scan Dockerfiles:** Use tools that can scan Dockerfiles for vulnerabilities and security misconfigurations.
        * **Don't Run as Root:** Avoid running processes inside the container as root. Create a dedicated user and group.
        * **Build Secrets Management:** Use secure mechanisms for handling build-time secrets (e.g., Docker's `--secret` flag, environment variables). Do *not* embed secrets directly in the Dockerfile.

