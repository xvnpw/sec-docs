# APPLICATION THREAT MODEL

## ASSETS
1. **API Keys**: Sensitive keys for OpenAI, OpenRouter, and Anthropic stored in GitHub secrets.
2. **User Inputs**: Data provided by users through GitHub issues, pull requests, and comments.
3. **Fabric Patterns**: Patterns used by the Fabric Agent Action to process user requests.
4. **Output Files**: Generated output files that may contain sensitive information or results from user inputs.

## TRUST BOUNDARIES
1. **GitHub Repository**: Trusted environment where the action is defined and executed.
2. **External LLM Providers**: OpenAI, OpenRouter, and Anthropic APIs are considered untrusted as they are external services.
3. **User Inputs**: Inputs from users are untrusted until validated and processed.

## DATA FLOWS
1. **User Inputs to GitHub Actions**: User inputs (issues, comments) trigger the GitHub Actions workflow.
2. **GitHub Actions to Fabric Agent Action**: The action processes user inputs and interacts with LLM providers.
3. **Fabric Agent Action to LLM Providers**: The action sends requests to external LLM providers and receives responses.
4. **LLM Providers to Fabric Agent Action**: Responses from LLM providers are processed and returned to the GitHub Actions workflow.
5. **Fabric Agent Action to Output Files**: The action writes results to output files.

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME         | THREAT NAME                                                                 | STRIDE CATEGORY | WHY APPLICABLE                                                                                     | HOW MITIGATED                                                                                     | MITIGATION                                                                                          | LIKELIHOOD EXPLANATION                                                                 | IMPACT EXPLANATION                                                                 | RISK SEVERITY |
|-----------|------------------------|-----------------------------------------------------------------------------|-----------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|----------------|
| 0001      | Fabric Agent Action    | Unauthorized access to API keys through GitHub secrets                     | Spoofing        | API keys are critical for accessing LLM services; unauthorized access can lead to misuse.       | API keys are stored in GitHub secrets and not exposed in the codebase.                           | Implement rate limiting on API calls and monitor usage patterns.                               | Medium                                                                                  | High                                                                                  | High           |
| 0002      | GitHub Actions         | Injection of malicious input through user comments or issues                | Tampering       | Malicious inputs can manipulate the action's behavior or lead to unintended consequences.         | Input validation is required to ensure that inputs are sanitized before processing.               | Implement strict input validation and sanitization to prevent injection attacks.               | Medium                                                                                  | High                                                                                  | High           |
| 0003      | LLM Providers          | Data leakage through untrusted external LLM providers                       | Information Disclosure | Sensitive user data may be exposed if LLM providers mishandle data.                              | Data is sent to LLM providers only after validation; however, the risk remains.                   | Use encryption for data in transit and ensure compliance with data protection regulations.     | Medium                                                                                  | Critical                                                                                 | High           |
| 0004      | Fabric Patterns        | Compromise of fabric patterns leading to incorrect processing of requests    | Tampering       | Altered patterns can lead to incorrect outputs or execution of unintended actions.                | Patterns are version-controlled, but unauthorized changes could still occur.                      | Implement access controls and logging for changes to fabric patterns.                          | Low                                                                                     | High                                                                                  | Medium         |
| 0005      | Output Files           | Exposure of sensitive information in generated output files                 | Information Disclosure | Output files may contain sensitive data that should not be publicly accessible.                   | Output files are generated based on user inputs and should be handled carefully.                  | Implement access controls on output files and ensure they are not publicly accessible.         | Medium                                                                                  | High                                                                                  | High           |

# DEPLOYMENT THREAT MODEL

## DEPLOYMENT ARCHITECTURES
1. **GitHub Actions**: The primary deployment architecture where the Fabric Agent Action is executed.
2. **Docker Container**: The action is packaged in a Docker container for execution.

## ASSETS
1. **Docker Image**: The Docker image containing the Fabric Agent Action code and dependencies.
2. **GitHub Repository**: The repository where the action is defined and managed.

## TRUST BOUNDARIES
1. **GitHub Actions Environment**: Trusted environment where the action runs.
2. **Docker Hub**: Untrusted source for pulling base images or dependencies.

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME         | THREAT NAME                                                                 | WHY APPLICABLE                                                                                     | HOW MITIGATED                                                                                     | MITIGATION                                                                                          | LIKELIHOOD EXPLANATION                                                                 | IMPACT EXPLANATION                                                                 | RISK SEVERITY |
|-----------|------------------------|-----------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|----------------|
| 0001      | Docker Image           | Vulnerability in base image leading to container compromise                 | Vulnerabilities in base images can be exploited to gain unauthorized access to the container.     | Base images are regularly updated, and security scans are performed.                              | Use trusted base images and regularly scan for vulnerabilities.                                  | Medium                                                                                  | High                                                                                  | High           |
| 0002      | GitHub Actions         | Unauthorized access to GitHub Actions workflows                             | Unauthorized access can lead to malicious modifications or execution of workflows.                 | Access controls are implemented for repository collaborators.                                     | Regularly review access permissions and implement two-factor authentication for GitHub accounts. | Medium                                                                                  | Critical                                                                                 | High           |
| 0003      | Docker Container        | Container escape leading to host compromise                                 | If an attacker escapes the container, they can gain access to the host system.                     | Containers are run with limited privileges, and security best practices are followed.              | Use security features like seccomp, AppArmor, and run containers with the least privilege.      | Low                                                                                     | Critical                                                                                 | High           |
| 0004      | GitHub Actions         | Denial of Service (DoS) through excessive workflow runs                     | Excessive workflow runs can exhaust GitHub Actions resources, leading to service disruption.       | Rate limiting and access control measures are in place.                                           | Implement rate limiting on workflow triggers and monitor usage patterns.                       | Medium                                                                                  | High                                                                                  | Medium         |

# BUILD THREAT MODEL

## ASSETS
1. **Source Code**: The codebase stored in the GitHub repository.
2. **Dockerfile**: The file used to build the Docker image for the action.
3. **CI/CD Pipeline**: The GitHub Actions workflows that automate the build and testing process.

## TRUST BOUNDARIES
1. **GitHub Repository**: Trusted environment where the source code is stored.
2. **External Dependencies**: Libraries and packages pulled from external sources.

## BUILD THREATS

| THREAT ID | COMPONENT NAME         | THREAT NAME                                                                 | WHY APPLICABLE                                                                                     | HOW MITIGATED                                                                                     | MITIGATION                                                                                          | LIKELIHOOD EXPLANATION                                                                 | IMPACT EXPLANATION                                                                 | RISK SEVERITY |
|-----------|------------------------|-----------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|----------------|
| 0001      | Source Code            | Supply chain attack through compromised dependencies                         | Compromised dependencies can introduce vulnerabilities or malicious code into the project.        | Dependencies are managed through a lock file, and regular updates are performed.                  | Use dependency scanning tools to identify vulnerabilities and ensure dependencies are from trusted sources. | Medium                                                                                  | Critical                                                                                 | High           |
| 0002      | CI/CD Pipeline          | Unauthorized modifications to the CI/CD pipeline                            | Unauthorized changes can lead to malicious code execution or data exposure.                        | Access controls are implemented for workflow files and repository settings.                       | Regularly review access permissions and implement two-factor authentication for GitHub accounts. | Medium                                                                                  | Critical                                                                                 | High           |
| 0003      | Dockerfile             | Vulnerability in Dockerfile leading to insecure image builds                | Insecure Dockerfile configurations can lead to vulnerabilities in the built image.                | Dockerfile is reviewed for security best practices, and images are scanned for vulnerabilities.   | Follow Docker security best practices and regularly scan images for vulnerabilities.             | Medium                                                                                  | High                                                                                  | Medium         |
| 0004      | CI/CD Pipeline          | Denial of Service (DoS) through excessive builds                           | Excessive builds can exhaust CI/CD resources, leading to service disruption.                       | Rate limiting and monitoring are implemented for CI/CD usage.                                     | Implement rate limiting on build triggers and monitor usage patterns.                         | Medium                                                                                  | High                                                                                  | Medium         |

# QUESTIONS & ASSUMPTIONS
### Questions
1. What additional security measures can be implemented to further protect against unauthorized access?
2. How can we ensure the reliability of external LLM providers?
3. What are the potential impacts of service outages on the functionality of the Fabric Agent Action?

### Assumptions
- The project will be deployed in a secure environment with proper access controls.
- Users will follow best practices for managing API keys and sensitive data.
- The action will be used primarily in private repositories to minimize exposure to unauthorized users.