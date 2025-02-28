Here is the combined list of vulnerabilities, formatted as markdown:

### Combined Vulnerability List

#### Vulnerability Name: Default SSH Password in Baseline Configurations

*   **Description:** The Dockerfiles provided for baseline testing of the Remote-SSH extension configure SSH servers with a default, well-known password "foobar" for the root user. This allows anyone who knows this password and can access the exposed SSH port to gain root access to the container.
    *   **Step-by-step trigger:**
        1.  Build a Docker image using one of the provided Dockerfiles (e.g., `/code/ssh/baseline-configs/fedora/Dockerfile` or `/code/ssh/baseline-configs/fedora+/Dockerfile`).
        2.  Run a container from the built image, exposing the SSH port (port 5671 for fedora, 5670 for fedora+).
        3.  Attempt to connect to the exposed SSH port using an SSH client as the `root` user.
        4.  When prompted for a password, use the default password `foobar`.
        5.  Successful authentication grants root access to the container.

*   **Impact:** An attacker gaining root access to a container can lead to severe consequences, including:
    *   Data breaches by accessing sensitive information within the container.
    *   Malware installation and execution within the container.
    *   Lateral movement to other systems if the container is part of a larger network.
    *   Modification or deletion of critical system files, leading to system instability or denial of service.
    *   Complete control of the development environment running in the container.

*   **Vulnerability Rank:** Critical

*   **Currently implemented mitigations:** None. The documentation mentions the default password in the context of testing instructions, but this is not a mitigation for the vulnerability itself. The Dockerfile explicitly sets the hardcoded password.

*   **Missing mitigations:**
    *   Remove the default password from the Dockerfiles.
    *   Implement key-based authentication instead of password-based authentication for root access.
    *   If password-based authentication is necessary for testing, generate a random password for each container instance or require users to set their own password during container setup.
    *   Use a less predictable password for testing purposes.
    *   Disable password-based authentication in favor of SSH key-based authentication.
    *   Add a clear warning in the README and within the Dockerfiles themselves stating that these configurations are for testing purposes only and should not be used in production environments or exposed to untrusted networks.
    *   Promote the use of SSH key-based authentication instead of password authentication, especially for root access.

*   **Preconditions:**
    *   A Docker image must be built from one of the vulnerable Dockerfiles (`/code/ssh/baseline-configs/fedora/Dockerfile` or `/code/ssh/baseline-configs/fedora+/Dockerfile`).
    *   A container must be running from this image with the SSH port (5670 or 5671) exposed and accessible to the attacker.
    *   The attacker must know or discover the default password `foobar` (publicly documented in `ssh/README.md` file).

*   **Source code analysis:**
    *   File: `/code/ssh/baseline-configs/fedora/Dockerfile` and `/code/ssh/baseline-configs/fedora+/Dockerfile`
    *   Vulnerable Code Line:
        ```dockerfile
        RUN echo "root:foobar" | chpasswd
        ```
    *   Code Flow:
        1.  The Dockerfile uses a Fedora base image.
        2.  It installs the `openssh-server` package.
        3.  It modifies the SSH server configuration (`/etc/ssh/sshd_config`) to allow root login with password (`PermitRootLogin yes`) and enable TCP forwarding (`AllowTcpForwarding yes`).
        4.  SSH host keys are generated using `ssh-keygen -A`.
        5.  **Vulnerability:** The line `RUN echo "root:foobar" | chpasswd` sets the password for the `root` user to the static and easily guessable value "foobar".
        6.  The SSH server is configured to listen on port 5671 (or 5670 for `fedora+/Dockerfile`).
        7.  The container starts the SSH server in the foreground.
    *   Exploitation: An attacker can connect to the running container's SSH service using `ssh root@<container_ip> -p <exposed_port>` and authenticate with the password "foobar", gaining root access.

*   **Security test case:**
    1.  Build the Docker image: `docker build -t vulnerable-ssh-image -f /code/ssh/baseline-configs/fedora/Dockerfile /code/ssh/baseline-configs/fedora/`
    2.  Run the Docker container, mapping the container's port 5671 to the host's port 5671: `docker run -d -p 5671:5671 vulnerable-ssh-image`
    3.  Wait for the container to start and the SSH service to be ready.
    4.  Open a terminal and attempt to SSH into the container as root on localhost, port 5671: `ssh root@localhost -p 5671`
    5.  When prompted for the password, enter `foobar` and press Enter.
    6.  Verify that you are successfully logged in as root to the container. The shell prompt should indicate root access (e.g., `[root@<container_id> /]#`).
    7.  Exit the SSH session: `exit`
    8.  Stop and remove the Docker container: `docker stop <container_id>` and `docker rm <container_id>` (replace `<container_id>` with the actual container ID).
    *   Successful login as root using the password `foobar` confirms the vulnerability.