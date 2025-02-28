### Vulnerability List

- Vulnerability Name: Hardcoded SSH Root Password in Dockerfile
- Description: The Dockerfiles for Fedora based SSH baseline configurations use a hardcoded password "foobar" for the root user. This allows anyone who can access the exposed SSH port to gain root access to the container.
- Impact: Critical. Full root access to the container. An attacker can take complete control of the development environment running in the container, potentially leading to data breaches, malware installation, and further attacks on connected systems.
- Vulnerability Rank: Critical
- Currently implemented mitigations: None. The Dockerfile explicitly sets the hardcoded password.
- Missing mitigations: The hardcoded password should be removed. A secure password generation mechanism should be used, or ideally, password-based authentication should be disabled in favor of SSH key-based authentication. For testing purposes, a less predictable password could be used, or ideally SSH keys should be used for authentication.
- Preconditions:
    - A container is built from either `/code/ssh/baseline-configs/fedora/Dockerfile` or `/code/ssh/baseline-configs/fedora+/Dockerfile`.
    - The container is running and the SSH port (5671 or 5670) is exposed and reachable by the attacker.
- Source code analysis:
    - In `/code/ssh/baseline-configs/fedora/Dockerfile` and `/code/ssh/baseline-configs/fedora+/Dockerfile`, the line `RUN echo "root:foobar" | chpasswd` sets the root password to "foobar".
    ```dockerfile
    FROM fedora:latest

    RUN dnf install -y openssh-server

    RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    RUN sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding yes/' /etc/ssh/sshd_config

    RUN ssh-keygen -A

    RUN echo "root:foobar" | chpasswd # Vulnerability: Hardcoded password

    # TODO: expose only on an isolated docker network to avoid conflicts?
    #       Think about how extension would communicate
    EXPOSE 5671
    CMD ["/usr/sbin/sshd", "-D", "-p", "5671"]
    ```
    - This password is used for SSH authentication when connecting to the exposed port.
- Security test case:
    1. Build a Docker image using `docker build -t test-ssh-vuln -f /code/ssh/baseline-configs/fedora/Dockerfile /code/ssh/baseline-configs/fedora/`. (Assume you are in the root of the repository).
    2. Run the Docker image and expose port 5671: `docker run -p 5671:5671 test-ssh-vuln`.
    3. Attempt to SSH into the container as root using the password "foobar": `ssh root@localhost -p 5671`.
    4. Enter "foobar" when prompted for the password.
    5. Verify that you are successfully logged in as root.