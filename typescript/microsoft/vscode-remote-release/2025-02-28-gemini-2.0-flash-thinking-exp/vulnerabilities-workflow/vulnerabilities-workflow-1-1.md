### Vulnerability List:

* Vulnerability Name: Default SSH Password in Baseline Configurations
    * Description: The Dockerfiles provided for baseline testing of the Remote-SSH extension configure SSH servers with a default, well-known password "foobar" for the root user. This allows anyone who knows this password and can access the exposed SSH port to gain root access to the container.
        * Step-by-step trigger:
            1. Build a Docker image using one of the provided Dockerfiles (e.g., `/code/ssh/baseline-configs/fedora/Dockerfile`).
            2. Run a container from the built image, exposing the SSH port (e.g., port 5671 for fedora).
            3. Attempt to connect to the exposed SSH port using an SSH client as the `root` user.
            4. When prompted for a password, use the default password `foobar`.
            5. Successful authentication grants root access to the container.
    * Impact: An attacker gaining root access to a container can lead to severe consequences, including:
        * Data breaches by accessing sensitive information within the container.
        * Malware installation and execution within the container.
        * Lateral movement to other systems if the container is part of a larger network.
        * Modification or deletion of critical system files, leading to system instability or denial of service.
    * Vulnerability Rank: High
    * Currently implemented mitigations: None. The documentation mentions the default password in the context of testing instructions, but this is not a mitigation for the vulnerability itself.
    * Missing mitigations:
        * Remove the default password from the Dockerfiles.
        * Implement key-based authentication instead of password-based authentication for root access.
        * If password-based authentication is necessary for testing, generate a random password for each container instance or require users to set their own password during container setup.
        * Add a clear warning in the README and within the Dockerfiles themselves stating that these configurations are for testing purposes only and should not be used in production environments or exposed to untrusted networks.
    * Preconditions:
        * A Docker image must be built from one of the vulnerable Dockerfiles (e.g., `/code/ssh/baseline-configs/fedora/Dockerfile` or `/code/ssh/baseline-configs/fedora+/Dockerfile`).
        * A container must be running from this image with the SSH port (5670 or 5671) exposed and accessible to the attacker.
        * The attacker must know or discover the default password `foobar`.
    * Source code analysis:
        * In `/code/ssh/baseline-configs/fedora/Dockerfile` and `/code/ssh/baseline-configs/fedora+/Dockerfile`, the following lines are responsible for setting the default password:
        ```dockerfile
        RUN echo "root:foobar" | chpasswd
        ```
        * This command pipes the string "root:foobar" to the `chpasswd` command, which changes the password for the user `root` to `foobar`.
        * The following lines expose the SSH ports:
        ```dockerfile
        EXPOSE 5671 # in fedora/Dockerfile
        EXPOSE 5670 # in fedora+/Dockerfile
        ```
        * These `EXPOSE` directives make the SSH service running within the container accessible from outside the container on ports 5671 and 5670 respectively.
        * An attacker can then connect to these exposed ports and attempt to authenticate as `root` using the known default password.

    * Security test case:
        1. Build the Docker image: `docker build -t vulnerable-ssh-image -f /code/ssh/baseline-configs/fedora/Dockerfile /code/ssh/baseline-configs/fedora/`
        2. Run the Docker container, mapping the container's port 5671 to the host's port 5671: `docker run -d -p 5671:5671 vulnerable-ssh-image`
        3. Wait for the container to start and the SSH service to be ready.
        4. Open a terminal and attempt to SSH into the container as root on localhost, port 5671: `ssh root@localhost -p 5671`
        5. When prompted for the password, enter `foobar` and press Enter.
        6. Verify that you are successfully logged in as root to the container. The shell prompt should indicate root access (e.g., `[root@<container_id> /]#`).
        7. Exit the SSH session: `exit`
        8. Stop and remove the Docker container: `docker stop <container_id>` and `docker rm <container_id>` (replace `<container_id>` with the actual container ID).
        * Successful login as root using the password `foobar` confirms the vulnerability.