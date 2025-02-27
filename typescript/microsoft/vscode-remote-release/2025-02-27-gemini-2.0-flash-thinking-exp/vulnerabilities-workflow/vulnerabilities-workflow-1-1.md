### Vulnerability List

- Vulnerability Name: Default SSH Password in Test Dockerfiles
- Description:
    - The provided Dockerfiles (`/code/ssh/baseline-configs/fedora/Dockerfile` and `/code/ssh/baseline-configs/fedora+/Dockerfile`) are used for baseline testing of the Remote-SSH extension.
    - These Dockerfiles configure an SSH server and set a default, well-known password "foobar" for the root user.
    - If a user were to mistakenly deploy containers based on these Dockerfiles in a non-testing environment accessible to external attackers, or if these test environments were unintentionally exposed, attackers could gain unauthorized root access.
    - Steps to trigger:
        1. Build a Docker image using either `/code/ssh/baseline-configs/fedora/Dockerfile` or `/code/ssh/baseline-configs/fedora+/Dockerfile`.
        2. Run the Docker container, ensuring that the SSH port (5671 or 5670 respectively) is exposed and accessible from the attacker's network.
        3. The attacker attempts to connect to the exposed SSH port using an SSH client.
        4. When prompted for the username, the attacker enters "root".
        5. When prompted for the password, the attacker enters the default password "foobar".
        6. If successful, the attacker gains a root shell within the container.
- Impact:
    - Critical. Successful exploitation grants an attacker complete control over the container as root. This can lead to data breaches, system compromise, malware installation, and further lateral movement within the network if the container is not properly isolated.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None in the provided project files. These Dockerfiles are intended for internal testing and are not meant for production use. The risk relies on misusing these test configurations.
- Missing Mitigations:
    - **Clear Documentation and Warnings:** Add comments to the Dockerfiles and associated documentation explicitly stating that these configurations are for testing purposes only and must not be used in production or exposed environments. Highlight the severe security risk of using default passwords.
    - **Remove Default Password in Production:** Ensure that any production-oriented documentation or scripts related to Remote-SSH do not suggest or use default passwords.
    - **Consider Random Password Generation for Tests:** For automated testing, consider generating random passwords or using SSH keys instead of a static default password.
- Preconditions:
    - A Docker container built from either `/code/ssh/baseline-configs/fedora/Dockerfile` or `/code/ssh/baseline-configs/fedora+/Dockerfile` is running.
    - The SSH port (5671 or 5670) of the container is exposed to a network accessible by the attacker.
    - The attacker is aware or guesses that a container based on these configurations is running and accessible.
- Source Code Analysis:
    - **File:** `/code/ssh/baseline-configs/fedora/Dockerfile`
        ```dockerfile
        FROM fedora:latest
        ...
        RUN echo "root:foobar" | chpasswd
        ...
        EXPOSE 5671
        CMD ["/usr/sbin/sshd", "-D", "-p", "5671"]
        ```
    - **File:** `/code/ssh/baseline-configs/fedora+/Dockerfile`
        ```dockerfile
        FROM fedora:latest
        ...
        RUN echo "root:foobar" | chpasswd
        ...
        EXPOSE 5670
        CMD ["/usr/sbin/sshd", "-D", "-p", "5670"]
        ```
    - In both Dockerfiles, the line `RUN echo "root:foobar" | chpasswd` directly sets the password for the `root` user to "foobar". This is a static, easily guessable password. The `EXPOSE` directive makes the SSH ports accessible, potentially to external networks if not properly configured in a testing environment.
- Security Test Case:
    1. **Environment Setup:** Ensure you have Docker installed and running.
    2. **Build Docker Image:** Navigate to the `/code/ssh/baseline-configs/fedora/` directory in your terminal and run: `docker build -t test-ssh-default-pw .`
    3. **Run Docker Container:** Run the built image, exposing port 5671: `docker run -d -p 5671:5671 test-ssh-default-pw`
    4. **Attacker Machine:** From a separate machine or terminal, use an SSH client to connect to the Docker host's IP address on port 5671: `ssh root@<docker-host-ip> -p 5671` (Replace `<docker-host-ip>` with the actual IP address or `localhost` if running locally).
    5. **Password Attempt:** When prompted for the password, enter `foobar`.
    6. **Verification:** If the login is successful, you will gain a root shell inside the Docker container, confirming the vulnerability. Type `exit` to close the SSH connection.
    7. **Cleanup:** Stop and remove the Docker container: `docker stop <container-id>` (get container ID from `docker ps`) and `docker rm <container-id>`. Remove the Docker image: `docker rmi test-ssh-default-pw`.