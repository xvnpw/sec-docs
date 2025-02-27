### Vulnerability List:

* Vulnerability Name: Default SSH Password in Dockerfiles
* Description:
    1. The provided Dockerfiles (`fedora/Dockerfile` and `fedora+/Dockerfile`) are used for setting up test environments for the Remote-SSH extension.
    2. These Dockerfiles contain commands that set a default password "foobar" for the root user in the Docker container.
    3. If a container built from these Dockerfiles is run and its SSH port is exposed, an attacker can attempt to connect to the SSH server using the username "root" and the password "foobar".
    4. Successful authentication grants the attacker shell access to the container.
* Impact:
    High. Successful exploitation allows an attacker to gain unauthorized shell access to the Docker container. While these containers are intended for testing purposes, unauthorized access can lead to:
    - Information disclosure if sensitive data is present in the test environment.
    - Modification of the test environment, potentially affecting test results or introducing malicious changes.
    - Lateral movement if the compromised container is part of a larger network.
* Vulnerability Rank: High
* Currently implemented mitigations:
    None. The Dockerfiles as provided directly configure the default password. These Dockerfiles are intended for internal testing purposes, and are not meant to be exposed to public networks.
* Missing mitigations:
    - Remove the default password configuration from the Dockerfiles.
    - Implement key-based authentication instead of password authentication for SSH access in the Dockerfiles.
    - Add documentation or comments to the Dockerfiles explicitly stating that these are for internal testing only and should not be used in production or exposed to public networks without proper security hardening.
    - Consider using dynamically generated passwords or secrets during container startup for test environments, instead of hardcoded defaults.
* Preconditions:
    1. A Docker image has been built using either `fedora/Dockerfile` or `fedora+/Dockerfile`.
    2. A Docker container is running from this image.
    3. The SSH port of the container (5671 for `fedora/Dockerfile`, 5670 for `fedora+/Dockerfile`) is exposed and accessible from the attacker's network.
    4. The attacker knows or can guess the default password "foobar".
* Source code analysis:
    1. **File:** `/code/ssh/baseline-configs/fedora/Dockerfile`
        ```dockerfile
        FROM fedora:latest

        RUN dnf install -y openssh-server

        RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
        RUN sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding yes/' /etc/ssh/sshd_config

        RUN ssh-keygen -A

        RUN echo "root:foobar" | chpasswd  <--- Vulnerable line: Sets default password

        # TODO: expose only on an isolated docker network to avoid conflicts?
        #       Think about how extension would communicate
        EXPOSE 5671
        CMD ["/usr/sbin/sshd", "-D", "-p", "5671"]
        ```
    2. **File:** `/code/ssh/baseline-configs/fedora+/Dockerfile`
        ```dockerfile
        FROM fedora:latest

        RUN dnf install -y openssh-server wget

        RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
        RUN sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding yes/' /etc/ssh/sshd_config

        RUN ssh-keygen -A

        RUN echo "root:foobar" | chpasswd  <--- Vulnerable line: Sets default password

        EXPOSE 5670
        CMD ["/usr/sbin/sshd", "-D", "-p", "5670"]
        CMD ["/usr/sbin/sshd", "-D", "-p", "5670"]
        ```
    3. The `RUN echo "root:foobar" | chpasswd` command in both Dockerfiles directly sets the root user's password to "foobar".
    4. When these Docker images are built and containers are run, the SSH server will use this default password for root authentication if password authentication is enabled (which is the case due to `PermitRootLogin yes`).
* Security test case:
    1. **Build the Docker image:**
        ```bash
        cd /code/ssh/baseline-configs/fedora
        docker build -t fedora-ssh .
        ```
    2. **Run the Docker container, exposing port 5671:**
        ```bash
        docker run -d -p 5671:5671 fedora-ssh
        ```
    3. **Attempt to SSH to the container from a separate terminal:**
        ```bash
        ssh root@localhost -p 5671
        ```
        (If testing on a remote Docker host, replace `localhost` with the Docker host's IP address.)
    4. **Enter the password "foobar" when prompted.**
    5. **Expected Result:** If the password "foobar" is accepted and you gain a shell prompt inside the Docker container, the vulnerability is confirmed.