### Vulnerability List:

- Vulnerability Name: Default SSH Root Password
- Description: The Dockerfiles for Fedora-based SSH baseline configurations (`/code/ssh/baseline-configs/fedora/Dockerfile` and `/code/ssh/baseline-configs/fedora+/Dockerfile`) set a default, well-known password "foobar" for the root user. This allows anyone who knows this password to gain unauthorized root access to the SSH server running within the container.
- Impact: An attacker who can reach the exposed SSH port of a container created from these Dockerfiles can log in as root using the password "foobar". This grants them full control over the container environment, potentially leading to data breaches, malware installation, or other malicious activities. While these containers are intended for development and testing, they can still pose a security risk if exposed to wider networks or used in less controlled environments.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The Dockerfiles explicitly configure the weak default password.
- Missing Mitigations:
    - Remove the line setting the default password in the Dockerfiles (`RUN echo "root:foobar" | chpasswd`).
    - Implement a mechanism to require users to set a strong password upon initial container setup or favor SSH key-based authentication.
    - For testing purposes, consider generating a random password during container build or provide clear instructions on how to change the password immediately after container creation.
    - Promote the use of SSH key-based authentication instead of password authentication, especially for root access.
- Preconditions:
    - A Docker container built from either `/code/ssh/baseline-configs/fedora/Dockerfile` or `/code/ssh/baseline-configs/fedora+/Dockerfile` is running.
    - The SSH port of the container (5671 for `fedora/Dockerfile`, 5670 for `fedora+/Dockerfile`) is accessible to the attacker, either through port forwarding or direct exposure.
    - The attacker is aware of or able to guess the default password "foobar", which is publicly documented in the `ssh/README.md` file.
- Source Code Analysis:
    - File: `/code/ssh/baseline-configs/fedora/Dockerfile` and `/code/ssh/baseline-configs/fedora+/Dockerfile`
    - Vulnerable Code Line: `RUN echo "root:foobar" | chpasswd`
    - Code Flow:
        1. The Dockerfile uses a Fedora base image.
        2. It installs the `openssh-server` package.
        3. It modifies the SSH server configuration (`/etc/ssh/sshd_config`) to allow root login with password (`PermitRootLogin yes`) and enable TCP forwarding (`AllowTcpForwarding yes`).
        4. SSH host keys are generated using `ssh-keygen -A`.
        5. **Vulnerability:** The line `RUN echo "root:foobar" | chpasswd` sets the password for the `root` user to the static and easily guessable value "foobar".
        6. The SSH server is configured to listen on port 5671 (or 5670 for `fedora+/Dockerfile`).
        7. The container starts the SSH server in the foreground.
    - Exploitation: An attacker can connect to the running container's SSH service using `ssh root@<container_ip> -p <exposed_port>` and authenticate with the password "foobar", gaining root access.

- Security Test Case:
    1. **Build the Docker Image:** Navigate to the `/code/ssh/baseline-configs/fedora` directory in your terminal. Run the command: `docker build -t fedora-ssh .`
    2. **Run the Docker Container:** Run the built image, mapping the container's SSH port to a local port (e.g., 5671). Execute: `docker run -p 5671:5671 fedora-ssh`
    3. **Attempt SSH Connection:** Open a new terminal window and attempt to connect to the SSH server running in the container as the root user. Use the command: `ssh root@localhost -p 5671`
    4. **Enter Default Password:** When prompted for the password, enter `foobar`.
    5. **Verify Root Access:** If the login is successful, you will be logged in as the root user within the container. You should see a shell prompt indicating root access (e.g., `[root@<container_id> /]#`). This confirms the vulnerability as an external attacker could gain unauthorized root access using the default password.