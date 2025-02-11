# Mitigation Strategies Analysis for moby/moby

## Mitigation Strategy: [Run Containers as Non-Root Users](./mitigation_strategies/run_containers_as_non-root_users.md)

*   **1. Run Containers as Non-Root Users**

    *   **Description:**
        1.  **`Dockerfile` `USER` Instruction:**  Within your `Dockerfile`, use the `USER` instruction to specify a non-root user.  Create this user and group beforehand using `RUN groupadd` and `RUN useradd`.
        2.  **`Dockerfile` `chown`:** Use `RUN chown` within the `Dockerfile` to set appropriate ownership of files and directories to the non-root user.
        3.  **Verification:** After building and running, use `docker exec -it <container_id> whoami` to confirm the process runs as the non-root user.

    *   **Threats Mitigated:**
        *   **Privilege Escalation (Severity: High):** Limits attacker privileges within the container.
        *   **Container Breakout (Severity: Critical):** Reduces the effectiveness of some breakout exploits.
        *   **Filesystem Modification (Severity: Medium):** Limits write access within the container.

    *   **Impact:**
        *   **Privilege Escalation:** Risk significantly reduced.
        *   **Container Breakout:** Risk reduced.
        *   **Filesystem Modification:** Risk reduced.

    *   **Currently Implemented:** Partially. Implemented in `Dockerfile` for `web-server`, but not `database`.

    *   **Missing Implementation:** `database` service `Dockerfile`.

## Mitigation Strategy: [Drop Unnecessary Linux Capabilities](./mitigation_strategies/drop_unnecessary_linux_capabilities.md)

*   **2. Drop Unnecessary Linux Capabilities**

    *   **Description:**
        1.  **`docker run` or Compose:** Use `--cap-drop=all` in your `docker run` command (or the `cap_drop` directive in `docker-compose.yml`) to drop all capabilities.
        2.  **`docker run` or Compose:** Use `--cap-add=<capability>` (or `cap_add` in `docker-compose.yml`) to add back *only* the essential capabilities.
        3.  **Testing:** Thoroughly test the application after modifying capabilities.

    *   **Threats Mitigated:**
        *   **Container Breakout (Severity: Critical):** Removes capabilities often used in breakout exploits.
        *   **Kernel Exploitation (Severity: High):** Limits interaction with the kernel.

    *   **Impact:**
        *   **Container Breakout:** Risk significantly reduced.
        *   **Kernel Exploitation:** Risk reduced.

    *   **Currently Implemented:** No.

    *   **Missing Implementation:** `docker-compose.yml` (or equivalent) for all services.

## Mitigation Strategy: [Mount Root Filesystem as Read-Only](./mitigation_strategies/mount_root_filesystem_as_read-only.md)

*   **3. Mount Root Filesystem as Read-Only**

    *   **Description:**
        1.  **`docker run` or Compose:** Use the `--read-only` flag in `docker run` (or `read_only: true` in `docker-compose.yml`).
        2.  **`docker run` or Compose:** Use volumes (`-v` in `docker run` or `volumes` in `docker-compose.yml`) to mount writable directories.
        3.  **`docker run` or Compose:** Consider `--tmpfs` for temporary, non-persistent writable areas.

    *   **Threats Mitigated:**
        *   **Malware Installation (Severity: High):** Prevents modification of the container's base image.
        *   **Persistent Threats (Severity: Medium):** Hinders persistence within the container.
        *   **Configuration Tampering (Severity: Medium):** Protects container configuration files.

    *   **Impact:**
        *   **Malware Installation:** Risk significantly reduced.
        *   **Persistent Threats:** Risk significantly reduced.
        *   **Configuration Tampering:** Risk significantly reduced.

    *   **Currently Implemented:** Partially. Implemented for `web-server`, not `database` or `message-queue`.

    *   **Missing Implementation:** `database` and `message-queue` services.

## Mitigation Strategy: [Set CPU and Memory Limits](./mitigation_strategies/set_cpu_and_memory_limits.md)

*   **4. Set CPU and Memory Limits**

    *   **Description:**
        1.  **`docker run` or Compose:** Use `--cpus` and `--memory` in `docker run` (or `cpus` and `mem_limit` in `docker-compose.yml`).
        2.  **`docker run` or Compose:** Consider `--memory-swap`.
        3.  **Monitoring:** Use `docker stats` to monitor resource usage.

    *   **Threats Mitigated:**
        *   **Denial of Service (DoS) (Severity: Medium):** Prevents resource exhaustion.
        *   **Resource Exhaustion Attacks (Severity: Medium):** Limits attacker's ability to consume resources.

    *   **Impact:**
        *   **Denial of Service (DoS):** Risk significantly reduced.
        *   **Resource Exhaustion Attacks:** Risk significantly reduced.

    *   **Currently Implemented:** Yes. In `docker-compose.yml` for all services.

    *   **Missing Implementation:** None (but regular review is needed).

## Mitigation Strategy: [Limit Number of Processes with `--pids-limit`](./mitigation_strategies/limit_number_of_processes_with__--pids-limit_.md)

*   **5. Limit Number of Processes with `--pids-limit`**

    *   **Description:**
        1.  **`docker run` or Compose:** Use the `--pids-limit` flag in `docker run` (or the `pids_limit` directive in `docker-compose.yml`).
        2. **Monitoring:** Monitor process count during normal operation.

    *   **Threats Mitigated:**
        *   **Fork Bombs (Severity: High):** Prevents fork bomb attacks.
        *   **Resource Exhaustion (Severity: Medium):** Contributes to resource control.

    *   **Impact:**
        *   **Fork Bombs:** Risk significantly reduced.
        *   **Resource Exhaustion:** Risk reduced.

    *   **Currently Implemented:** No.

    *   **Missing Implementation:** Needs to be added to `docker-compose.yml` (or equivalent).

## Mitigation Strategy: [Use Minimal Base Images](./mitigation_strategies/use_minimal_base_images.md)

*   **6. Use Minimal Base Images**

    *   **Description:**
        1.  **`Dockerfile` `FROM`:** In your `Dockerfile`, use the `FROM` instruction to specify a minimal base image (e.g., `alpine`, `scratch`, or a distroless image).
        2.  **`Dockerfile` Multi-Stage Builds:** Use multi-stage builds to create a smaller final image.

    *   **Threats Mitigated:**
        *   **Vulnerable Packages (Severity: Medium to High):** Fewer packages mean fewer potential vulnerabilities.
        *   **Attack Surface Reduction (Severity: Medium):** Smaller image, smaller attack surface.

    *   **Impact:**
        *   **Vulnerable Packages:** Risk reduced.
        *   **Attack Surface Reduction:** Risk reduced.

    *   **Currently Implemented:** Partially. `web-server` uses `alpine`. `database` uses a full `postgres` image.

    *   **Missing Implementation:** `database` service `Dockerfile`.

## Mitigation Strategy: [Regularly Scan Images for Vulnerabilities](./mitigation_strategies/regularly_scan_images_for_vulnerabilities.md)

*   **7. Regularly Scan Images for Vulnerabilities**

    *   **Description:**
        1.  **Tool Selection:** Choose a container image scanning tool (e.g., Trivy, Clair, Anchore).
        2.  **CI/CD Integration:** Integrate the scanner into your CI/CD pipeline to scan images *after* building with `docker build` and *before* pushing with `docker push`.
        3.  **Remediation:** Address identified vulnerabilities.

    *   **Threats Mitigated:**
        *   **Known Vulnerabilities (Severity: Variable, up to Critical):** Identifies vulnerabilities in image components.

    *   **Impact:**
        *   **Known Vulnerabilities:** Risk significantly reduced.

    *   **Currently Implemented:** No.

    *   **Missing Implementation:** CI/CD pipeline integration.

## Mitigation Strategy: [Use Signed and Trusted Images (Docker Content Trust)](./mitigation_strategies/use_signed_and_trusted_images__docker_content_trust_.md)

*   **8. Use Signed and Trusted Images (Docker Content Trust)**

    *   **Description:**
        1.  **Environment Variable:** Set `DOCKER_CONTENT_TRUST=1`.
        2.  **`docker trust`:** Use `docker trust` commands to sign images.
        3.  **Pull and Run:** Docker will verify signatures before pulling and running.

    *   **Threats Mitigated:**
        *   **Image Tampering (Severity: High):** Ensures image integrity.
        *   **Man-in-the-Middle Attacks (Severity: High):** Protects during image download.
        *   **Untrusted Images (Severity: High):** Prevents use of untrusted images.

    *   **Impact:**
        *   **Image Tampering:** Risk eliminated.
        *   **Man-in-the-Middle Attacks:** Risk significantly reduced.
        *   **Untrusted Images:** Risk eliminated.

    *   **Currently Implemented:** No.

    *   **Missing Implementation:** Requires enabling DCT and setting up a Notary server.

## Mitigation Strategy: [Avoid `latest` Tag](./mitigation_strategies/avoid__latest__tag.md)

*   **9. Avoid `latest` Tag**

    *   **Description:**
        1.  **`docker build` and `docker push`:** Use specific, immutable tags (e.g., `myimage:1.2.3`, `myimage:v1-sha256:abcdef...`) when building and pushing.
        2.  **`docker-compose.yml` or `docker run`:** Update image references to use specific tags.
        3.  **Avoid `docker pull latest`:** Never use `docker pull latest` in production.

    *   **Threats Mitigated:**
        *   **Tag Hijacking (Severity: High):** Prevents malicious image replacement.
        *   **Unpredictable Deployments (Severity: Medium):** Ensures consistent deployments.

    *   **Impact:**
        *   **Tag Hijacking:** Risk eliminated.
        *   **Unpredictable Deployments:** Risk eliminated.

    *   **Currently Implemented:** Partially. Some services use specific tags, others use `latest`.

    *   **Missing Implementation:** All services need to use specific tags.

## Mitigation Strategy: [Limit Network Exposure](./mitigation_strategies/limit_network_exposure.md)

*   **10. Limit Network Exposure**

    *   **Description:**
        1.  **`docker run` or Compose:** Use the `-p` flag in `docker run` (or `ports` in `docker-compose.yml`) for *specific* port mappings (e.g., `-p 8080:80`).
        2.  **`docker run` or Compose:** Bind to specific interfaces if needed (e.g., `-p 192.168.1.10:8080:80`).

    *   **Threats Mitigated:**
        *   **Unauthorized Access (Severity: Medium to High):** Reduces the attack surface.
        *   **Information Disclosure (Severity: Low to Medium):** Reduces risk of exposing unintended ports.

    *   **Impact:**
        *   **Unauthorized Access:** Risk reduced.
        *   **Information Disclosure:** Risk reduced.

    *   **Currently Implemented:** Partially. Needs review for all services.

    *   **Missing Implementation:** Thorough review of all services.

## Mitigation Strategy: [Use User-Defined Networks](./mitigation_strategies/use_user-defined_networks.md)

*   **11. Use User-Defined Networks**

    *   **Description:**
        1.  **`docker network create`:** Create a user-defined network (e.g., `docker network create myapp-network`).
        2.  **`docker run` or Compose:** Use the `--network` flag in `docker run` (or `networks` in `docker-compose.yml`) to connect containers.

    *   **Threats Mitigated:**
        *   **Container-to-Container Attacks (Severity: Medium):** Isolates containers on different networks.
        *   **Network Sniffing (Severity: Low):** Reduces risk on the default bridge network.

    *   **Impact:**
        *   **Container-to-Container Attacks:** Risk significantly reduced.
        *   **Network Sniffing:** Risk reduced.

    *   **Currently Implemented:** Yes. A user-defined network is in `docker-compose.yml`.

    *   **Missing Implementation:** None.

## Mitigation Strategy: [Avoid `--net=host`](./mitigation_strategies/avoid__--net=host_.md)

*   **12. Avoid `--net=host`**

    *   **Description:**
        1.  **Do not use `--net=host` in `docker run` (or `network_mode: host` in `docker-compose.yml`)** unless absolutely necessary and the risks are fully understood.

    *   **Threats Mitigated:**
        *   **Complete Network Compromise (Severity: Critical):** Prevents container from accessing the host's network stack directly.

    *   **Impact:**
        *   **Complete Network Compromise:** Risk eliminated (unless `--net=host` is used).

    *   **Currently Implemented:** Yes. `--net=host` is not used.

    *   **Missing Implementation:** None.

## Mitigation Strategy: [Restrict Docker Socket Access](./mitigation_strategies/restrict_docker_socket_access.md)

*   **13. Restrict Docker Socket Access**

    *   **Description:**
        1.  **Avoid mounting `/var/run/docker.sock` into containers.**
        2.  If interaction with the Docker daemon is needed, use a secure proxy or the Docker API over TLS.

    *   **Threats Mitigated:**
        *   **Host Compromise (Severity: Critical):** Prevents container from controlling the Docker daemon.

    *   **Impact:**
        *   **Host Compromise:** Risk significantly reduced (eliminated if the socket is not exposed).

    *   **Currently Implemented:** Yes. The Docker socket is not mounted.

    *   **Missing Implementation:** None.

## Mitigation Strategy: [Enable TLS Authentication for Docker Daemon](./mitigation_strategies/enable_tls_authentication_for_docker_daemon.md)

*   **14. Enable TLS Authentication for Docker Daemon**

    *   **Description:**
        1.  **`dockerd` Configuration:** Configure the Docker daemon (`dockerd`) to use TLS certificates for authentication (`--tlsverify`, `--tlscacert`, `--tlscert`, `--tlskey`).
        2.  **Client Configuration:** Configure Docker clients to use client certificates.

    *   **Threats Mitigated:**
        *   **Unauthorized Remote Access (Severity: High):** Protects the Docker daemon from unauthorized network access.

    *   **Impact:**
        *   **Unauthorized Remote Access:** Risk significantly reduced.

    *   **Currently Implemented:** No.

    *   **Missing Implementation:** Requires configuring TLS for the Docker daemon.

## Mitigation Strategy: [Regularly Update Docker Engine](./mitigation_strategies/regularly_update_docker_engine.md)

*   **15. Regularly Update Docker Engine**

    *   **Description:**
        1.  **Monitor Releases:** Stay informed about new Docker Engine (Moby) releases.
        2.  **`apt`, `yum`, etc.:** Use your system's package manager (e.g., `apt`, `yum`) to update the Docker Engine.
        3.  **Testing:** Test updates in a non-production environment first.

    *   **Threats Mitigated:**
        *   **Docker Daemon Vulnerabilities (Severity: Variable, up to Critical):** Addresses vulnerabilities in the Docker daemon.

    *   **Impact:**
        *   **Docker Daemon Vulnerabilities:** Risk reduced.

    *   **Currently Implemented:** Partially. Updates are applied periodically, but no formal schedule.

    *   **Missing Implementation:** Formal update process.

## Mitigation Strategy: [Secrets Management (Using Docker Secrets)](./mitigation_strategies/secrets_management__using_docker_secrets_.md)

*   **16. Secrets Management (Using Docker Secrets)**

    *   **Description:**
        1.  **`docker secret create`:** Create secrets using `docker secret create`.
        2.  **`docker-compose.yml` or `docker service create`:** Define and use secrets in your `docker-compose.yml` file (or with `docker service create`).
        3.  **Access in Container:** Access secrets within the container from `/run/secrets/`.

    *   **Threats Mitigated:**
        *   **Secret Exposure (Severity: High):** Protects sensitive data.

    *   **Impact:**
        *   **Secret Exposure:** Risk significantly reduced.

    *   **Currently Implemented:** Partially. Some secrets use Docker Secrets, others use environment variables.

    *   **Missing Implementation:** Migrate all secrets to Docker Secrets.

